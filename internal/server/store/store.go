// Package store implements the SQLite-backed durable state for fd0-server
// (STORAGE.md §2 and §7).
package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps a *sql.DB with the SQLite pragmas fd0 requires.
//
// translogPriv / translogPub are populated by SetTranslogKey and used
// by AppendLeaf. Server boot installs them via LoadOrCreateTranslogKey.
// AppendLeaf without an installed key returns ErrTranslogKeyMissing —
// callers (server.go) should treat that as a configuration error, not
// a per-request fault.
type Store struct {
	db           *sql.DB
	translogPriv ed25519.PrivateKey
	translogPub  ed25519.PublicKey
}

// Open initialises the database file and applies the schema.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite WAL allows readers, but our writers use IMMEDIATE; one writer is plenty
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db}
	if err := store.ensureGeneration(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.ensureScopeMemberIndex(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("scope member index: %w", err)
	}
	return store, nil
}

// storeGeneration is raised when stored data gains meaning an older server
// would silently drop. Generation 2: scope metadata may carry member roles
// (docs/SCOPE_ROLES_PLAN.md); an older server would forget them and accept
// writes that clients reject. Servers refuse databases of a newer generation.
const storeGeneration = 2

func (s *Store) ensureGeneration(ctx context.Context) error {
	var stored int
	err := s.db.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM schema_state WHERE key = 'store_generation'`).Scan(&stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read store generation: %w", err)
	}
	if stored > storeGeneration {
		return fmt.Errorf("database was written by a newer fd0-server (store generation %d > %d); downgrading is not supported", stored, storeGeneration)
	}
	if stored == storeGeneration {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO schema_state (key, value) VALUES ('store_generation', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(storeGeneration))
	if err != nil {
		return fmt.Errorf("write store generation: %w", err)
	}
	return nil
}

// Close releases the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// ChainKind is "user" or "scope".
type ChainKind string

const (
	KindUser  ChainKind = "user"
	KindScope ChainKind = "scope"
)

// Chain is one row of the chains table.
type Chain struct {
	ID       string
	TipSeq   uint64
	TipHash  []byte
	Metadata []byte // CBOR
}

// Event is one row of the events table.
type Event struct {
	ChainID  string
	Seq      uint64
	EventID  string
	PrevHash []byte
	Kind     string
	CBOR     []byte
	StoredAt int64
}

// ErrNotFound is returned by lookups that find no row.
var ErrNotFound = errors.New("not found")

// ErrDivergence is returned by Append when prev_hash doesn't match the tip.
var ErrDivergence = errors.New("divergence")

// ErrDuplicate is returned by Append when event_id already exists.
var ErrDuplicate = errors.New("duplicate event_id")

// ChainID encodes a chain id like "user:<shortId>" or "scope:<scope_id>".
func ChainID(kind ChainKind, key string) string { return string(kind) + ":" + key }

// GetChain returns the chain row, or ErrNotFound.
func (s *Store) GetChain(ctx context.Context, id string) (*Chain, error) {
	row := s.db.QueryRowContext(ctx, `SELECT chain_id, tip_seq, tip_hash, metadata FROM chains WHERE chain_id = ?`, id)
	var c Chain
	err := row.Scan(&c.ID, &c.TipSeq, &c.TipHash, &c.Metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AppendOpts is what callers must compute before calling Append.
type AppendOpts struct {
	ChainID     string
	Kind        ChainKind // user/scope (for chain-row creation)
	Genesis     bool      // true at seq=0 (chain row is created)
	Seq         uint64
	NewTipHash  []byte
	NewMetadata []byte // CBOR; replaces prior metadata wholesale
	Event       Event
}

// Append performs the optimistic-CAS append in its own transaction.
// Equivalent to AppendWithTranslog with no translog hook — kept for
// callers that don't have a translog key installed (tests, legacy
// callers).
//
// THREAT: T23 (stored-event replay — the events.event_id UNIQUE
//
//	constraint at the SQL layer is what actually
//	rejects duplicate inserts; proto.EventID derives
//	the content-addressed value the constraint keys on).
func (s *Store) Append(ctx context.Context, o AppendOpts) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.appendTx(ctx, tx, o); err != nil {
		return err
	}
	return tx.Commit()
}

// appendTx is the transaction-internal body of Append. Pulled out so
// AppendWithTranslog can reuse the same atomicity contract while
// adding the translog leaf in the same tx.
//
// Contract:
//
//	BEGIN IMMEDIATE
//	  if !genesis: SELECT tip_hash FROM chains WHERE chain_id = ?
//	               compare with event.prev_hash → ErrDivergence on mismatch
//	  INSERT INTO events
//	  if genesis: INSERT INTO chains
//	  else:       UPDATE chains SET tip_seq, tip_hash, metadata
func (s *Store) appendTx(ctx context.Context, tx *sql.Tx, o AppendOpts) error {
	// Ensure write isolation; sqlite handles BEGIN IMMEDIATE via the next write.
	if !o.Genesis {
		var tip []byte
		var tipSeq uint64
		err := tx.QueryRowContext(ctx, `SELECT tip_seq, tip_hash FROM chains WHERE chain_id = ?`, o.ChainID).Scan(&tipSeq, &tip)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDivergence
		}
		if err != nil {
			return err
		}
		if !bytesEqual(o.Event.PrevHash, tip) || o.Seq != tipSeq+1 {
			return ErrDivergence
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO events (chain_id, seq, event_id, prev_hash, kind, cbor, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		o.ChainID, o.Seq, o.Event.EventID, o.Event.PrevHash, o.Event.Kind, o.Event.CBOR, time.Now().Unix())
	if err != nil {
		// modernc returns "constraint failed: UNIQUE constraint failed: events.event_id"
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	if o.Genesis {
		_, err = tx.ExecContext(ctx, `INSERT INTO chains (chain_id, tip_seq, tip_hash, metadata) VALUES (?, ?, ?, ?)`,
			o.ChainID, o.Seq, o.NewTipHash, o.NewMetadata)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE chains SET tip_seq = ?, tip_hash = ?, metadata = ? WHERE chain_id = ?`,
			o.Seq, o.NewTipHash, o.NewMetadata, o.ChainID)
	}
	if err == nil && o.Kind == KindScope && len(o.NewMetadata) > 0 {
		err = replaceScopeMembersTx(ctx, tx, o.ChainID, o.NewMetadata)
	}
	return err
}

// EventsSince returns events with seq > since up to limit, ordered by seq asc.
func (s *Store) EventsSince(ctx context.Context, chainID string, since uint64, limit int) ([]Event, error) {
	return s.EventsSinceInclusive(ctx, chainID, since, limit, false)
}

// EventsSinceInclusive optionally includes seq == since (used for fresh
// discovery where the caller has no prior cursor and needs the genesis).
func (s *Store) EventsSinceInclusive(ctx context.Context, chainID string, since uint64, limit int, inclusive bool) ([]Event, error) {
	events, _, _, err := s.EventsSinceInclusiveBudget(ctx, chainID, since, limit, inclusive, 0)
	return events, err
}

// EventsSinceInclusiveBudget stops before the first event that would exceed
// maxBytes. nextBytes reports that event's encoded size; zero means the page
// ended by row/count exhaustion. A non-positive maxBytes disables the budget.
func (s *Store) EventsSinceInclusiveBudget(
	ctx context.Context,
	chainID string,
	since uint64,
	limit int,
	inclusive bool,
	maxBytes int,
) ([]Event, int, int, error) {
	op := ">"
	if inclusive {
		op = ">="
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT chain_id, seq, event_id, prev_hash, kind, cbor, stored_at FROM events WHERE chain_id = ? AND seq `+op+` ? ORDER BY seq LIMIT ?`,
		chainID, since, limit)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var out []Event
	usedBytes := 0
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ChainID, &e.Seq, &e.EventID, &e.PrevHash, &e.Kind, &e.CBOR, &e.StoredAt); err != nil {
			return nil, 0, 0, err
		}
		if maxBytes > 0 && usedBytes+len(e.CBOR) > maxBytes {
			return out, usedBytes, len(e.CBOR), nil
		}
		out = append(out, e)
		usedBytes += len(e.CBOR)
	}
	return out, usedBytes, 0, rows.Err()
}

// EventExists returns true iff event_id is already stored.
func (s *Store) EventExists(ctx context.Context, eventID string) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM events WHERE event_id = ? LIMIT 1`, eventID)
	var x int
	err := row.Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LatestUserAuthSet returns the latest event in a user chain.
func (s *Store) LatestEvent(ctx context.Context, chainID string) (*Event, error) {
	row := s.db.QueryRowContext(ctx, `SELECT chain_id, seq, event_id, prev_hash, kind, cbor, stored_at FROM events WHERE chain_id = ? ORDER BY seq DESC LIMIT 1`, chainID)
	var e Event
	err := row.Scan(&e.ChainID, &e.Seq, &e.EventID, &e.PrevHash, &e.Kind, &e.CBOR, &e.StoredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ScopesForMember returns only scopes indexed for pk.
func (s *Store) ScopesForMember(ctx context.Context, pkBytes []byte) ([]Chain, error) {
	scopes, _, err := s.ScopesForMemberPage(ctx, pkBytes, "", 256)
	return scopes, err
}

// ScopesForMemberPage returns a bounded, ordered membership page. nextAfter
// is empty on the final page; otherwise pass it back unchanged.
func (s *Store) ScopesForMemberPage(ctx context.Context, pkBytes []byte, after string, limit int) ([]Chain, string, error) {
	if limit <= 0 || limit > 256 {
		limit = 256
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.chain_id, c.tip_seq, c.tip_hash, c.metadata
		   FROM scope_members sm
		   JOIN chains c ON c.chain_id = sm.chain_id
		  WHERE sm.member_pub = ? AND c.chain_id > ?
		  ORDER BY c.chain_id
		  LIMIT ?`,
		pkBytes, after, limit+1,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []Chain
	for rows.Next() {
		var c Chain
		if err := rows.Scan(&c.ID, &c.TipSeq, &c.TipHash, &c.Metadata); err != nil {
			return nil, "", err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	nextAfter := ""
	if len(out) > limit {
		out = out[:limit]
		nextAfter = out[len(out)-1].ID
	}
	return out, nextAfter, nil
}

type scopeMemberMetadata struct {
	Members [][]byte `cbor:"members"`
}

func replaceScopeMembersTx(ctx context.Context, tx *sql.Tx, chainID string, metadata []byte) error {
	var decoded scopeMemberMetadata
	if err := proto.Unmarshal(metadata, &decoded); err != nil {
		return fmt.Errorf("decode scope members: %w", err)
	}
	if len(decoded.Members) > proto.MaxLegacyScopeMembers {
		return fmt.Errorf("scope member count %d exceeds %d", len(decoded.Members), proto.MaxLegacyScopeMembers)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scope_members WHERE chain_id = ?`, chainID); err != nil {
		return err
	}
	for _, member := range decoded.Members {
		if len(member) != 32 {
			return fmt.Errorf("scope member has length %d", len(member))
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO scope_members (chain_id, member_pub) VALUES (?, ?)`,
			chainID, member,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureScopeMemberIndex(ctx context.Context) error {
	var version string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM schema_state WHERE key = 'scope_members_version'`,
	).Scan(&version)
	if err == nil && version == "1" {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM scope_members`); err != nil {
		return err
	}
	lastChainID := ""
	for {
		var chainID string
		var metadata []byte
		err := tx.QueryRowContext(ctx,
			`SELECT chain_id, metadata
			   FROM chains
			  WHERE chain_id LIKE 'scope:%' AND chain_id > ?
			  ORDER BY chain_id
			  LIMIT 1`,
			lastChainID,
		).Scan(&chainID, &metadata)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		if err := replaceScopeMembersTx(ctx, tx, chainID, metadata); err != nil {
			return fmt.Errorf("%s: %w", chainID, err)
		}
		lastChainID = chainID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_state (key, value) VALUES ('scope_members_version', '1')
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- Replay nonces ----

// CheckAndInsertNonce returns true if (pk, nonce) was inserted; false if seen.
// Old nonces are pruned in the background by PruneNonces.
//
// THREAT: T22 (per-request HTTP replay).
func (s *Store) CheckAndInsertNonce(ctx context.Context, pk, nonce []byte, ts int64) (bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_nonces (pk, nonce, ts) VALUES (?, ?, ?)`, pk, nonce, ts)
	if err == nil {
		return true, nil
	}
	if isUnique(err) {
		return false, nil
	}
	return false, err
}

// PruneNonces deletes nonces older than ttlSecs.
func (s *Store) PruneNonces(ctx context.Context, ttlSecs int64) error {
	cutoff := time.Now().Unix() - ttlSecs
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_nonces WHERE ts < ?`, cutoff)
	return err
}

// RegisterUser inserts a (super_pub, short_id) row. Returns
// ErrDuplicate if super_pub or short_id is already taken (codex
// audit 🔴 server.go:279: super_pub_taken was previously not
// enforced, so the same user_super_pub could register many shortIds).
func (s *Store) RegisterUser(ctx context.Context, superPub []byte, shortID string) error {
	if len(superPub) != 32 {
		return errors.New("store: super_pub must be 32 bytes")
	}
	if shortID == "" {
		return errors.New("store: short_id must not be empty")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (super_pub, short_id, registered_at) VALUES (?, ?, ?)`,
		superPub, shortID, time.Now().Unix(),
	)
	if err != nil && isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// CountUsers returns the total number of registered users. Used by
// the /metrics gauge — cheap (SELECT COUNT on a small indexed table).
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ListChainIDs returns every chain_id sorted alphabetically. Used by
// the public GET /v1/chains endpoint so independent witnesses can
// auto-discover what to poll without operator-side configuration.
//
// Chain IDs are not secret — every cosigned STH a witness publishes
// already includes its chain_id, so exposing the list here doesn't
// leak more than the witness output already does.
func (s *Store) ListChainIDs(ctx context.Context) ([]string, error) {
	ids, _, err := s.ListChainIDsPage(ctx, "", 1024)
	return ids, err
}

// ListChainIDsPage returns a bounded page for witness discovery.
func (s *Store) ListChainIDsPage(ctx context.Context, after string, limit int) ([]string, string, error) {
	if limit <= 0 || limit > 1024 {
		limit = 1024
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT chain_id FROM chains WHERE chain_id > ? ORDER BY chain_id LIMIT ?`,
		after, limit+1,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, "", err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	nextAfter := ""
	if len(out) > limit {
		out = out[:limit]
		nextAfter = out[len(out)-1]
	}
	return out, nextAfter, nil
}

// CountChainsByKind returns chain counts grouped by their kind prefix
// (e.g. "user", "scope"). The chain_id column is "kind:short_id", so
// substring-before-':' gives the kind. Cheap on the small chains table.
func (s *Store) CountChainsByKind(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT substr(chain_id, 1, instr(chain_id, ':') - 1) AS kind, COUNT(*)
		 FROM chains
		 WHERE instr(chain_id, ':') > 0
		 GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var kind string
		var n int64
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
	}
	return out, rows.Err()
}

// IsUserRegistered returns true iff super_pub appears in the users
// table. Codex audit (🔴 auth.go:87): every authenticated endpoint
// MUST check this before honouring a request — otherwise a self-
// signed pk that never went through POST /users could call /sync
// and create scopes.
func (s *Store) IsUserRegistered(ctx context.Context, superPub []byte) (bool, error) {
	if len(superPub) != 32 {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM users WHERE super_pub = ? LIMIT 1`, superPub,
	).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---- helpers ----

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isUnique tells whether err is a SQLite UNIQUE constraint violation.
func isUnique(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{"UNIQUE constraint failed", "constraint failed: UNIQUE", "constraint failed (2067)"} {
		if contains(s, m) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
