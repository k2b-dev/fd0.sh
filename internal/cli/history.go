package cli

// Item history. A scope chain is append-only, so every version a secret has
// ever had is already on disk — reading history is purely an observation of
// what replay computes anyway (chain.ReplayScopeObserved). Nothing here
// weakens, skips or reorders a verification: the observer is handed each
// version only after replay has fully verified and applied it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ErrSecretVersionNotFound is returned when the requested sequence is not a
// version of the named record. Callers use errors.Is rather than string
// matching (same rationale as ErrTypedSecretNotFound).
var ErrSecretVersionNotFound = errors.New("secret version not found")

// ErrSecretVersionTombstone is returned when a caller asks to read back or
// restore a version that is a deletion.
var ErrSecretVersionTombstone = errors.New("secret version is a deletion")

// SecretVersionEntry is one historical state of one secret record.
//
// Seq/EventID/Author come from the verified event envelope. Revision and
// UpdatedAt come from *inside* the decrypted payload (pass items keep them in
// Meta) — the envelope carries no timestamp at all, so a record type that
// does not track its own mtime simply reports HasRevision=false and an empty
// UpdatedAt rather than a guessed time.
type SecretVersionEntry struct {
	SecretID    string
	Seq         uint64
	EventID     string
	Author      []byte
	Record      *proto.SecretRecord // nil = tombstone
	Name        string              // record name AT THIS VERSION ("" for a tombstone)
	Type        string              // record type at this version ("" for a tombstone)
	Revision    int64               // pass-item meta revision; 0 unless HasRevision
	HasRevision bool
	UpdatedAt   string // pass-item meta updated_at (RFC3339) or ""
}

// DeletedTypedRecord is the last live version of an item whose newest event is
// a tombstone. RestoreSeq addresses that exact live version.
type DeletedTypedRecord struct {
	ScopeID    string
	Name       string
	Type       string
	Payload    any
	DeletedSeq uint64
	RestoreSeq uint64
}

// Tombstone reports whether this version deleted the record.
func (e SecretVersionEntry) Tombstone() bool { return e.Record == nil }

// ListDeletedTypedSecrets returns deleted user records across active scopes.
// Replay still performs every normal chain and rollback check; the observer
// only retains the last live value needed to describe and restore a tombstone.
func (s *Session) ListDeletedTypedSecrets() ([]DeletedTypedRecord, error) {
	var deleted []DeletedTypedRecord
	for scopeID, scope := range s.Body.Scopes {
		if scope.Leaving {
			continue
		}
		versions := map[string][]chain.SecretVersion{}
		order := []string{}
		state, err := s.replayObservedAndCheckScope(scopeID, func(secretID string, version chain.SecretVersion) {
			if _, seen := versions[secretID]; !seen {
				order = append(order, secretID)
			}
			versions[secretID] = append(versions[secretID], version)
		})
		if err != nil {
			return nil, err
		}
		for _, secretID := range order {
			observed := versions[secretID]
			if len(observed) == 0 || observed[len(observed)-1].Record != nil {
				continue
			}
			if current, ok := state.SecretIndex[secretID]; ok && current.Record != nil {
				continue
			}
			for index := len(observed) - 2; index >= 0; index-- {
				record := observed[index].Record
				if record == nil {
					continue
				}
				if isMetaSecret(secretID, record.Name) {
					break
				}
				deleted = append(deleted, DeletedTypedRecord{
					ScopeID:    scopeID,
					Name:       record.Name,
					Type:       record.Type,
					Payload:    record.Payload,
					DeletedSeq: observed[len(observed)-1].Seq,
					RestoreSeq: observed[index].Seq,
				})
				break
			}
		}
	}
	sort.Slice(deleted, func(i, j int) bool {
		if deleted[i].DeletedSeq != deleted[j].DeletedSeq {
			return deleted[i].DeletedSeq > deleted[j].DeletedSeq
		}
		if deleted[i].ScopeID != deleted[j].ScopeID {
			return deleted[i].ScopeID < deleted[j].ScopeID
		}
		return deleted[i].Name < deleted[j].Name
	})
	return deleted, nil
}

// SecretHistory returns every observed version of the record currently named
// `name` in scopeOrLabel, newest first.
//
// ID-vs-name semantics: history follows the SECRET ID, not the name. The name
// is resolved to an id once, against the post-replay index (exactly how the
// read path in GetSecretByName/setTypedSecret resolves it), and the returned
// list is every version of THAT id — including versions written while the
// record carried a different name. So after a rename the older entries keep
// their historical Name field, and asking for the old name no longer finds
// the record, just as a normal read would not. Following the name instead
// would splice unrelated records together whenever a name is reused, which is
// strictly worse for a restore feature.
//
// A record whose current version is a tombstone is no longer resolvable by
// name in the live index (nil records are skipped, as everywhere else), so it
// falls back to the newest version that carried that name. That keeps the
// history of a deleted item readable, which is the case a user most wants it
// for.
func (s *Session) SecretHistory(scopeOrLabel, name string) ([]SecretVersionEntry, error) {
	_, entries, err := s.secretHistory(scopeOrLabel, name)
	return entries, err
}

// secretHistory also returns the resolved scope id, which the write path
// (RestoreSecretVersion) needs.
func (s *Session) secretHistory(scopeOrLabel, name string) (string, []SecretVersionEntry, error) {
	scopeID, err := s.resolveScopeID(scopeOrLabel)
	if err != nil {
		return "", nil, err
	}
	versions := map[string][]chain.SecretVersion{}
	order := []string{}
	// One replay, fully checked: replayObservedAndCheckScope runs the same
	// rollback / tip-binding comparison as every other read.
	st, err := s.replayObservedAndCheckScope(scopeID, func(secretID string, v chain.SecretVersion) {
		if _, seen := versions[secretID]; !seen {
			order = append(order, secretID)
		}
		versions[secretID] = append(versions[secretID], v)
	})
	if err != nil {
		return "", nil, err
	}
	sid := resolveHistorySecretID(st, versions, order, name)
	if sid == "" {
		return "", nil, fmt.Errorf("secret %q in scope %s: %w", name, scopeName(s, scopeID), ErrTypedSecretNotFound)
	}
	observed := versions[sid]
	entries := make([]SecretVersionEntry, 0, len(observed))
	for i := len(observed) - 1; i >= 0; i-- { // newest first
		entries = append(entries, newSecretVersionEntry(sid, observed[i]))
	}
	return scopeID, entries, nil
}

// resolveHistorySecretID maps a record name to the secret id whose history to
// follow.
//
// A live record wins, resolved exactly as the read path resolves it. The only
// fallback is a DELETED record: once tombstoned it is gone from the live
// index, yet its history is precisely what a user wants to see (and restore
// from), so an id whose newest version is a tombstone is matched on the name
// its last surviving version carried.
//
// The fallback deliberately does not consider live ids. If it did, a record
// renamed A→B would still answer to A, which no other read path does and
// which would let a stale UI restore into the wrong item.
func resolveHistorySecretID(
	st *chain.ScopeState,
	versions map[string][]chain.SecretVersion,
	order []string,
	name string,
) string {
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
			continue
		}
		if cur.Record.Name == name {
			return id
		}
	}
	best, bestSeq := "", uint64(0)
	for _, id := range order {
		observed := versions[id]
		if len(observed) == 0 || observed[len(observed)-1].Record != nil {
			continue // still live: not ours to claim by an old name
		}
		if cur, known := st.SecretIndex[id]; known && cur.Record != nil {
			continue // a later projection re-established it
		}
		for i := len(observed) - 1; i >= 0; i-- {
			if observed[i].Record == nil {
				continue
			}
			if observed[i].Record.Name == name && !isMetaSecret(id, name) && observed[i].Seq >= bestSeq {
				best, bestSeq = id, observed[i].Seq
			}
			break // only the last surviving name counts
		}
	}
	return best
}

func newSecretVersionEntry(secretID string, v chain.SecretVersion) SecretVersionEntry {
	entry := SecretVersionEntry{
		SecretID: secretID,
		Seq:      v.Seq,
		EventID:  v.EventID,
		Author:   v.Author,
		Record:   v.Record,
	}
	if v.Record == nil {
		return entry
	}
	entry.Name = v.Record.Name
	entry.Type = v.Record.Type
	if v.Record.Type != passitem.TypePassItem {
		return entry
	}
	// Pass items carry their own revision/updated_at in Meta. Decode
	// failures are not fatal for a listing: the version still exists and
	// still renders, it just has no self-reported revision.
	raw, err := payloadJSON(v.Record.Payload)
	if err != nil {
		return entry
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return entry
	}
	if revision, ok := metaRevision(item.Meta); ok {
		entry.Revision, entry.HasRevision = revision, true
	}
	if updated, ok := item.Meta["updated_at"].(string); ok {
		entry.UpdatedAt = updated
	}
	return entry
}

// metaRevision reads the monotonic revision from pass-item meta. JSON decodes
// numbers as float64; passitem.Touch writes an int. Both are accepted.
func metaRevision(meta map[string]any) (int64, bool) {
	switch value := meta["revision"].(type) {
	case float64:
		return int64(value), true
	case int:
		return int64(value), true
	case int64:
		return value, true
	default:
		return 0, false
	}
}

// SecretVersionAt returns one version of a record by sequence.
func (s *Session) SecretVersionAt(scopeOrLabel, name string, seq uint64) (*SecretVersionEntry, error) {
	entries, err := s.SecretHistory(scopeOrLabel, name)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Seq == seq {
			return &entries[i], nil
		}
	}
	return nil, fmt.Errorf("secret %q version %d: %w", name, seq, ErrSecretVersionNotFound)
}

// RestoreSecretVersion writes a historical payload back as the current
// version. It is an ordinary write through the typed-secret save path: a NEW
// secret.set event is appended at the tip, under the same secret id, and no
// existing event is rewritten or removed. The chain grows by exactly one.
//
// The record keeps its CURRENT name — restore rolls back content, not
// identity — so a restore after a rename does not silently rename the item
// back. The historical type and payload are restored verbatim.
//
// One consequence of going through the ordinary save path: restoring a
// version of an item that was DELETED writes under a freshly minted secret
// id, because that is how the save path resolves a name with no live record
// (identical to re-creating it with `fd0 set`). The deleted item's own
// history stays on the chain untouched; it is simply no longer what that name
// resolves to.
//
// Fails loudly when the target version is a deletion; a version that could
// not be decrypted never reaches here at all, because replay skips it and it
// is therefore absent from the history it would have to be selected from.
func (s *Session) RestoreSecretVersion(ctx context.Context, scopeOrLabel, name string, seq uint64) error {
	scopeID, entries, err := s.secretHistory(scopeOrLabel, name)
	if err != nil {
		return err
	}
	var target *SecretVersionEntry
	for i := range entries {
		if entries[i].Seq == seq {
			target = &entries[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("secret %q version %d: %w", name, seq, ErrSecretVersionNotFound)
	}
	if target.Tombstone() {
		return fmt.Errorf("secret %q version %d: %w", name, seq, ErrSecretVersionTombstone)
	}
	// entries is newest-first, so entries[0] is what the restore replaces.
	payload, err := restorePayload(target.Record.Type, target.Record.Payload, entries[0].Record)
	if err != nil {
		return fmt.Errorf("secret %q version %d: %w", name, seq, err)
	}
	return s.writeTypedSecretPayload(ctx, scopeID, name, target.Record.Type, payload, false, "", target.Record)
}

// restorePayload prepares a historical payload to be written back as the
// current value.
//
// The content rolls back, but the write is still a NEW version, so anything
// that describes *when* rather than *what* must move forward. A pass item
// carries its own revision counter and updated_at; writing them back verbatim
// made the counter run backwards, so a restored version showed a lower
// revision than the one it replaced — and restoring the oldest version twice
// produced two entries with the same number.
//
// The new revision is therefore derived from the version being REPLACED, not
// from the one being restored. Types that carry no such fields are returned
// unchanged.
func restorePayload(recordType string, payload any, current *proto.SecretRecord) (any, error) {
	if recordType != passitem.TypePassItem {
		return payload, nil
	}
	// Reuse the shared decode so restore reads a stored payload by exactly the
	// same rules as every other read path.
	raw, err := payloadJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("restore: read pass item: %w", err)
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("restore: decode pass item: %w", err)
	}
	if item.Meta == nil {
		item.Meta = map[string]any{}
	}
	item.Meta["updated_at"] = time.Now().UTC().Format(time.RFC3339)
	item.Meta["revision"] = currentRevision(current) + 1

	// Hand back the same shape the typed setters store — the JSON document as
	// a string — so a restored record reads back through PayloadJSON unchanged.
	encoded, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("restore: encode pass item: %w", err)
	}
	return string(encoded), nil
}

// currentRevision reads the revision of the version a restore is replacing.
// A record without a usable revision counts as 0, so the restore starts at 1.
func currentRevision(record *proto.SecretRecord) int {
	if record == nil {
		return 0
	}
	raw, err := payloadJSON(record.Payload)
	if err != nil {
		return 0
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return 0
	}
	switch value := item.Meta["revision"].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}
