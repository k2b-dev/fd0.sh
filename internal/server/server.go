// Package server implements the fd0 HTTP API (API.md). It is a thin layer
// over store + validate.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/ratelimit"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/server/validate"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Config configures the server.
type Config struct {
	Bind     string // e.g. ":4048"
	DBPath   string // path to SQLite file
	Version  string // server version reported by /version
	MaxBytes int64  // max request body
	Logger   *slog.Logger

	// RateLimit applies per-identity / per-IP rate limiting in front of the
	// authenticated and registration endpoints. Zero values fall back to
	// documented defaults; set RateLimitDisabled to opt out entirely.
	RateLimit         ratelimit.Config
	RateLimitDisabled bool

	// TranslogKeyPath is the path to the operator-supplied Ed25519
	// signing key for transparency-log STHs. If empty, defaults to
	// `<dir of DBPath>/server-translog.key`. Per TRANSLOG.md §4.1, a
	// missing file at this path is auto-generated on first boot and
	// the operator is WARNed to back it up.
	TranslogKeyPath string

	// Observer receives per-operation events for Prometheus
	// instrumentation. nil falls back to NoopObserver — safe in tests
	// or when /metrics isn't wired.
	Observer Observer

	// Label is this server's self-declared identifier, embedded in
	// /v1/server-info and signed alongside the pubkey. Must satisfy
	// [a-z0-9-]{0,32}; New rejects invalid values rather than silently
	// stripping them so a typo in FD0_LABEL doesn't ship a no-label
	// server. Empty = no label.
	Label string

	// Peers lists the replica URLs this server should resolve and
	// republish. The peer resolver fetches each one's /v1/server-info
	// on boot and on PeerResolveInterval (default 1h); pubkeys are
	// TOFU-pinned per-URL in SQLite. URLs are canonicalised via
	// canon.ParseURL before storage. Empty = solo server.
	Peers []string

	// PeerResolveInterval controls how often the peer resolver
	// refreshes its view of each peer. Zero = the documented default
	// (1 hour). Set short (e.g. 5s) in tests to make state observable
	// without flaky waits.
	PeerResolveInterval time.Duration

	// ReplicateFrom, when non-empty, makes this server a disaster-recovery
	// standby that mirrors the primary at this URL into its local backup
	// archive (REPLICATION.md Phase 0). The primary must list THIS server
	// in its FD0_PEERS so it pins this server's pubkey and authorises the
	// peer pull. Empty = not a replica.
	ReplicateFrom string

	// ReplicateInterval controls how often the standby pulls from the
	// primary. Zero = default (30s). Set short in tests.
	ReplicateInterval time.Duration

	// TrustedProxyCIDRs lists reverse proxies allowed to supply one
	// X-Forwarded-For client IP for rate limiting. Empty means headers are
	// ignored and RemoteAddr is authoritative.
	TrustedProxyCIDRs []string
}

// Observer hooks the server emits on every domain operation. Implementations
// must be cheap (called synchronously in the handler hot path) and concurrent
// safe — Prometheus counter/gauge collectors already are.
//
// Pass a nil Observer to disable; the constructor swaps in NoopObserver so
// the rest of the codebase never has to nil-check.
type Observer interface {
	// OnRegister fires once per POST /v1/users. result is "ok", "taken",
	// "bad_input", "ratelimit", "internal".
	OnRegister(result string)
	// OnEventPushed fires once per accepted-or-rejected event in a sync
	// push. chainKind is "user" or "scope". result is "ok" / the
	// pushResult.Reason string (e.g. "divergence", "dup", "bad_author").
	OnEventPushed(chainKind, result string)
	// OnEventsPulled fires once per /v1/sync pull with the count of
	// events returned. chainKind is "user" or "scope".
	OnEventsPulled(chainKind string, count int)
}

// NoopObserver does nothing. Default when Config.Observer is nil.
type NoopObserver struct{}

func (NoopObserver) OnRegister(string)            {}
func (NoopObserver) OnEventPushed(string, string) {}
func (NoopObserver) OnEventsPulled(string, int)   {}

// Server is the HTTP service. New constructs it; ServeHTTP routes requests.
type Server struct {
	cfg            Config
	store          *store.Store
	mux            *http.ServeMux
	log            *slog.Logger
	rl             *ratelimit.Limiter // nil when disabled
	rlStop         context.CancelFunc // cancels the limiter's GC goroutine on Close
	pruneStop      context.CancelFunc // cancels the noncePruner goroutine on Close
	peerStop       context.CancelFunc // cancels the peer resolver goroutine on Close
	replStop       context.CancelFunc // cancels the replication loop on Close
	trustedProxies []*net.IPNet
}

// Store exposes the underlying *store.Store for tests and tooling
// that need to seed registration/data without going through HTTP.
// Production callers should use the HTTP API; this accessor exists
// so tests can call s.Store().RegisterUser(...) etc.
func (s *Server) Store() *store.Store { return s.store }

// New initialises the store, loads the translog signing key, and wires
// the routes.
func New(cfg Config) (*Server, error) {
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 8 * 1024 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Observer == nil {
		cfg.Observer = NoopObserver{}
	}
	// Validate FD0_LABEL up front. A typo in the env var should produce
	// a loud boot failure, not silently ship a peer with no label.
	if !store.ValidLabel(cfg.Label) {
		return nil, fmt.Errorf("FD0_LABEL %q: must match [a-z0-9-]{0,32}", cfg.Label)
	}
	// Canonicalise FD0_PEERS once at boot. Anything that survives this
	// pass goes into the resolver loop and into the peers table under
	// its canonical form, so map-key equality with the peer's own
	// /v1/server-info URL is byte-stable downstream.
	canonPeers, err := canonicalisePeers(cfg.Peers)
	if err != nil {
		return nil, fmt.Errorf("FD0_PEERS: %w", err)
	}
	cfg.Peers = canonPeers
	if cfg.PeerResolveInterval == 0 {
		cfg.PeerResolveInterval = 1 * time.Hour
	}
	var trustedProxies []*net.IPNet
	for _, raw := range cfg.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("FD0_TRUSTED_PROXY_CIDRS %q: %w", raw, err)
		}
		trustedProxies = append(trustedProxies, network)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	keyPath := cfg.TranslogKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.DBPath), "server-translog.key")
	}
	priv, pub, err := store.LoadOrCreateTranslogKey(context.Background(), st, keyPath, func(m string) {
		cfg.Logger.Warn(m)
	})
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if err := st.SetTranslogKey(priv, pub); err != nil {
		_ = st.Close()
		return nil, err
	}
	// Sanity-sign once at boot so SignServerInfo wiring errors fail
	// fast (translog key not installed, etc). We DO NOT cache the
	// result — peers are dynamic, and a per-request sign of a 256-byte
	// CBOR payload is cheap (~50µs Ed25519 + a tiny SQLite SELECT). The
	// previous static cache became correctness-hostile once Peers became
	// runtime-mutable.
	if _, err := st.SignServerInfo(uint64(time.Now().Unix()), cfg.Label, nil); err != nil {
		_ = st.Close()
		return nil, err
	}
	s := &Server{
		cfg:            cfg,
		store:          st,
		mux:            http.NewServeMux(),
		log:            cfg.Logger,
		trustedProxies: trustedProxies,
	}
	// Replication authorization is persistent, so stale peers must be
	// revoked before any handler or background worker starts. A storage
	// error fails startup closed instead of leaving an old peer authorized.
	if err := s.prunePeers(context.Background()); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("revoke stale peers: %w", err)
	}
	if !cfg.RateLimitDisabled {
		var rlCtx context.Context
		rlCtx, s.rlStop = context.WithCancel(context.Background())
		s.rl = ratelimit.New(rlCtx, cfg.RateLimit)
	}
	s.routes()
	// SECURITY (codex audit 🟡 server.go:110): noncePruner now
	// terminates on Close(). Previously it kept ticking against
	// a closed DB after Close, logging warnings forever and
	// leaking a goroutine.
	pruneCtx, pruneCancel := context.WithCancel(context.Background())
	s.pruneStop = pruneCancel
	go s.noncePruner(pruneCtx)
	// Peer resolver: TOFU-pins each configured peer's pubkey on first
	// success, refreshes label + last_verified on schedule. No-op when
	// FD0_PEERS is empty so solo deployments incur zero overhead.
	if len(cfg.Peers) > 0 {
		peerCtx, peerCancel := context.WithCancel(context.Background())
		s.peerStop = peerCancel
		go s.runPeerResolver(peerCtx)
	}
	// Replication standby (REPLICATION.md Phase 0): when configured to
	// replicate from a primary, mirror its chains into the local backup
	// archive. Off unless ReplicateFrom is set, so solo / primary servers
	// incur zero overhead.
	if cfg.ReplicateFrom != "" {
		primary, err := canon.ParseURL(cfg.ReplicateFrom)
		if err != nil {
			return nil, fmt.Errorf("replicate-from URL: %w", err)
		}
		replCtx, replCancel := context.WithCancel(context.Background())
		s.replStop = replCancel
		s.startReplication(replCtx, primary, cfg.ReplicateInterval)
	}
	return s, nil
}

// Close releases resources.
func (s *Server) Close() error {
	if s.replStop != nil {
		s.replStop()
	}
	if s.peerStop != nil {
		s.peerStop()
	}
	if s.pruneStop != nil {
		s.pruneStop()
	}
	if s.rlStop != nil {
		s.rlStop()
	}
	return s.store.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBytes)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Operational endpoints — version-neutral, never under /v1/.
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /version", s.handleVersion)
	// /metrics is wired in cmd/fd0-server/main.go behind the metrics
	// auth middleware; not registered here so the metrics path stays
	// opt-in and per-binary configurable.

	// Data API — every path under /v1/ so the wire version is visible
	// in every URL and future v2/v3 endpoints can coexist.
	s.mux.HandleFunc("POST /v1/users", s.handleRegister)
	s.mux.HandleFunc("GET /v1/users/{shortId}/events", s.handleFetchUser)
	s.mux.HandleFunc("POST /v1/users/{shortId}/events", s.handleAppendUser)
	s.mux.HandleFunc("POST /v1/sync", s.handleSync)

	// Transparency log endpoints (TRANSLOG.md §5). All four are
	// UNAUTHENTICATED — they expose only commitments to a public log,
	// and witness archivers (which are not members of any scope) need
	// to fetch them to detect equivocation.
	s.mux.HandleFunc("GET /v1/server-info", s.handleServerInfo)
	s.mux.HandleFunc("GET /v1/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("GET /v1/chains", s.handleChains)
	s.mux.HandleFunc("GET /v1/sth/{chainId}", s.handleSTH)
	s.mux.HandleFunc("GET /v1/proof/inclusion", s.handleInclusionProof)
	s.mux.HandleFunc("GET /v1/proof/consistency", s.handleConsistencyProof)

	// Server-to-server replication (REPLICATION.md Phase 0). PEER-authed
	// (verifyPeerSig): serves verbatim encrypted chain bytes only to
	// TOFU-pinned peers, for disaster-recovery backup.
	s.mux.HandleFunc("GET /v1/peer/chain", s.handlePeerChain)
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "fd0-server",
		"version": s.cfg.Version,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"service":        "fd0-server",
		"server_version": s.cfg.Version,
		"api_version":    "v1",
	})
}

// GET /v1/capabilities — unsigned feature list. Clients use it only to avoid
// authoring events an older server would reject; the validator and client
// replay enforce the rules. The signed server-info record stays unchanged
// so older verifiers keep working.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"scopeRoles": true})
}

// GET /v1/server-info — publish the self-signed pubkey + label + peers
// record. Unauthenticated by design; first-contact pinning binds the
// pubkey to the operator the user trusts (TRANSLOG.md §6.1). Codex
// threat-model 2nd-round review caught that rate-limiting this with
// the AcquireRegister bucket (5/hour per-IP) blocks normal client
// behaviour: `cli.EnsurePinnedServer` refetches server-info on every
// sync for pin-mismatch detection, so any client syncing >5 times per
// hour from the same NAT/IP would 429-out. Rate-limit reverted;
// the residual DoS exposure is documented in THREATS.md T48.
//
// As of v0.0.4 the response carries the current peer list from SQLite,
// so the response is re-signed per request rather than cached. Cost
// per call: one cheap SELECT on the small peers table + one Ed25519
// sign (~50µs). Still well below the cost of any data-API response.
//
// THREAT: T48 (residual DoS at this unauthenticated endpoint —
//
//	documented as accepted exposure for v1.0).
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.ListPeers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	info, err := s.store.SignServerInfo(uint64(time.Now().Unix()), s.cfg.Label, peers)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	body, err := proto.Marshal(info)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// GET /v1/chains — list every chain the server has at least one event for.
//
// Unauthenticated. Chain IDs are not secret in the v1 protocol: every
// cosigned STH a witness publishes already embeds chain_id, and clients
// receive proofs that carry chain_id in clear. Exposing the list here
// gives independent witnesses a single discovery hop — they can sync
// the chains-to-poll set straight from the server without operator-side
// configuration.
//
// Response: CBOR `{"chains": [...], "next_after": "..."}`.
func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	if s.rl != nil {
		if d := s.rl.AcquireProof(s.clientIP(r)); !d.Allow {
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil && r.URL.Query().Get("limit") != "" {
		writeErr(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	ids, nextAfter, err := s.store.ListChainIDsPage(
		r.Context(),
		r.URL.Query().Get("after"),
		limit,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, struct {
		Chains    []string `cbor:"chains"`
		NextAfter string   `cbor:"next_after,omitempty"`
	}{
		Chains:    ids,
		NextAfter: nextAfter,
	})
}

// GET /v1/sth/{chainId} — current STH for chainId.
//
// chainId on the wire is the raw STORAGE.md §2 chain identifier
// ("user:<shortId>" or "scope:<scope_id>"). Go's mux delivers single
// path segments verbatim including the colon.
//
// Returns 404 if the chain has no events yet (no STH to publish).
// 400 on a malformed chain_id (catches operator/attacker probing
// future namespaces).
func (s *Server) handleSTH(w http.ResponseWriter, r *http.Request) {
	if s.rl != nil {
		if d := s.rl.AcquireProof(s.clientIP(r)); !d.Allow {
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	chainID := r.PathValue("chainId")
	if !validChainID(chainID) {
		writeErr(w, http.StatusBadRequest, "bad_chain_id", "")
		return
	}
	sth, err := s.store.CurrentSTH(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, sth)
}

// GET /v1/proof/inclusion?chain_id=X&leaf_index=Y&tree_size=Z
//
// All three query parameters are required. tree_size MUST be ≤ the
// server's current size; leaf_index MUST be < tree_size.
func (s *Server) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	if s.rl != nil {
		if d := s.rl.AcquireProof(s.clientIP(r)); !d.Allow {
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	q := r.URL.Query()
	chainID := q.Get("chain_id")
	if !validChainID(chainID) {
		writeErr(w, http.StatusBadRequest, "bad_chain_id", "")
		return
	}
	leafIdx, err := strconv.ParseUint(q.Get("leaf_index"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_leaf_index", err.Error())
		return
	}
	treeSize, err := strconv.ParseUint(q.Get("tree_size"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_tree_size", err.Error())
		return
	}
	path, err := s.store.InclusionProofFor(r.Context(), chainID, leafIdx, treeSize)
	if errors.Is(err, store.ErrIndexOutOfRange) {
		writeErr(w, http.StatusBadRequest, "out_of_range", "")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, translog.InclusionProof{
		LeafIndex: leafIdx,
		TreeSize:  treeSize,
		AuditPath: path,
	})
}

// GET /v1/proof/consistency?chain_id=X&from_size=A&to_size=B
//
// Returns the consistency proof from `from_size` to `to_size`. Special
// cases: from_size == 0 returns an empty proof (any tree is consistent
// with empty); from_size == to_size returns an empty proof.
func (s *Server) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if s.rl != nil {
		if d := s.rl.AcquireProof(s.clientIP(r)); !d.Allow {
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	q := r.URL.Query()
	chainID := q.Get("chain_id")
	if !validChainID(chainID) {
		writeErr(w, http.StatusBadRequest, "bad_chain_id", "")
		return
	}
	fromSize, err := strconv.ParseUint(q.Get("from_size"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_from_size", err.Error())
		return
	}
	toSize, err := strconv.ParseUint(q.Get("to_size"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_to_size", err.Error())
		return
	}
	nodes, err := s.store.ConsistencyProofFor(r.Context(), chainID, fromSize, toSize)
	if errors.Is(err, store.ErrIndexOutOfRange) {
		writeErr(w, http.StatusBadRequest, "out_of_range", "")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, translog.ConsistencyProof{
		FromSize: fromSize,
		ToSize:   toSize,
		Nodes:    nodes,
	})
}

// POST /users — accept genesis auth.set, assign shortId.
//
// THREAT: T45 (user-registration replay — UNIQUE on (pubkey, short_id)),
//
//	T48 (DoS — per-IP rate limit on register).
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Observer hook fires once per attempt regardless of exit branch.
	// Branches set result on early-return; the trailing `return` after
	// the chain commit leaves result as the default "ok".
	result := "ok"
	defer func() { s.cfg.Observer.OnRegister(result) }()

	if s.rl != nil {
		ip := s.clientIP(r)
		if d := s.rl.AcquireRegister(ip); !d.Allow {
			result = "ratelimit"
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	body, err := readBody(r)
	if err != nil {
		result = "bad_input"
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	var req struct {
		Event proto.UserEvent `cbor:"event"`
	}
	if err := proto.Unmarshal(body, &req); err != nil {
		result = "bad_input"
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	if err := validate.UserEvent(&req.Event, nil, nil, 0); err != nil {
		result = "bad_input"
		writeErr(w, http.StatusBadRequest, "bad_event", err.Error())
		return
	}
	// SECURITY (codex audit 🔴 server.go:279): a given user_super_pub
	// MUST register at most once. Without this check the same key
	// could enroll many shortIds, splitting the user's identity
	// across the server's view in a way that breaks deduplication
	// downstream.
	if exists, err := s.store.IsUserRegistered(r.Context(), req.Event.UserSuperPub); err != nil {
		result = "internal"
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	} else if exists {
		result = "taken"
		writeErr(w, http.StatusConflict, "super_pub_taken", "user_super_pub is already registered")
		return
	}
	// Allocate a fresh shortId. Retry on collision (extremely unlikely).
	var sid string
	for tries := 0; tries < 8; tries++ {
		sid = newShortID()
		if _, err := s.store.GetChain(r.Context(), store.ChainID(store.KindUser, sid)); errors.Is(err, store.ErrNotFound) {
			break
		}
	}
	prefix, err := req.Event.PrevHashInput()
	if err != nil {
		result = "internal"
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tipHash := proto.HashPrefix(prefix)
	meta, err := proto.Marshal(validate.UserMeta{SuperPub: req.Event.UserSuperPub, ShortID: sid})
	if err != nil {
		result = "internal"
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	cb, err := proto.Marshal(&req.Event)
	if err != nil {
		result = "internal"
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	eventID := proto.EventID(prefix)
	chainID := store.ChainID(store.KindUser, sid)
	sth, err := s.store.AppendWithTranslog(r.Context(), store.AppendOpts{
		ChainID:     chainID,
		Kind:        store.KindUser,
		Genesis:     true,
		Seq:         0,
		NewTipHash:  tipHash[:],
		NewMetadata: meta,
		Event: store.Event{
			Seq:      0,
			EventID:  eventID,
			PrevHash: nil,
			Kind:     proto.KindAuthSet,
			CBOR:     cb,
		},
	}, tipHash[:], uint64(time.Now().Unix()))
	if errors.Is(err, store.ErrDuplicate) {
		result = "dup"
		writeErr(w, http.StatusConflict, "dup", "event_id collision")
		return
	}
	if err != nil {
		result = "internal"
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// Record the (super_pub, short_id) binding so the auth middleware
	// can recognise this user on subsequent authenticated requests.
	// If this fails AFTER the chain commit, log loud (the chain is
	// already on disk; manual repair via re-running registration
	// won't work because of the IsUserRegistered check above — but
	// repair via direct DB insert is straightforward for an
	// operator who can read the server log).
	if regErr := s.store.RegisterUser(r.Context(), req.Event.UserSuperPub, sid); regErr != nil {
		s.log.Error("server: chain committed but users-table insert failed",
			"err", regErr, "short_id", sid, "super_pub_prefix", fmt.Sprintf("%x", req.Event.UserSuperPub[:8]))
		writeErr(w, http.StatusInternalServerError, "internal", "users-table insert failed; server-side repair required")
		return
	}
	// Translog payload — genesis is leaf 0 in a tree of size 1.
	// Server invariant: AppendWithTranslog committed atomically, so
	// the inclusion proof MUST exist; failure here is internal-error
	// territory, not a degradable condition.
	_, incs, _, perr := s.store.ProofsForChain(r.Context(), chainID, []uint64{0}, 0)
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, "internal", perr.Error())
		return
	}
	writeCBOR(w, http.StatusCreated, map[string]any{
		"shortId":         sid,
		"event_id":        eventID,
		"sth":             sth,
		"inclusion_proof": incs[0],
	})
}

// GET /users/<shortId>/events
//
// SECURITY (codex security audit 🔴): this endpoint returns the
// chain's auth.set events, which embed `encrypted_super_priv` —
// a blob that's offline-brute-forceable against the user's
// passphrase. An unauthenticated `shortId` (8 Crockford chars =
// 40 bits) is brute-forceable too, so without auth ANY attacker
// who can guess the shortId AND brute-force the passphrase wins.
//
// Auth model: the requester MUST sign with `super_priv`, and the
// signing pubkey MUST match the chain's `user_super_pub`. Only
// the legitimate chain owner can fetch their own events.
//
// Recovery flow: a fresh device with the recovery file has
// super_priv (after K_recovery decrypt) → can sign → can fetch.
// Operator-side enrollment / observer flows that DON'T have
// super_priv must use a separate API (none exist in v1).
//
// THREAT: T50 (shortId enumeration via API — A2 cannot enumerate
//
//	because this endpoint requires authentication +
//	signer-must-equal-chain-owner. Only A1 with raw
//	DB access can read encrypted user chains).
func (s *Server) handleFetchUser(w http.ResponseWriter, r *http.Request) {
	auth, code, err := s.verifyHTTPSig(r.Context(), r)
	if err != nil {
		var rle rateLimitedError
		if errors.As(err, &rle) {
			s.writeRateLimited(w, rle.RetryAfter())
			return
		}
		writeErr(w, code, "auth", err.Error())
		return
	}
	sid := r.PathValue("shortId")
	chainID := store.ChainID(store.KindUser, sid)
	c, err := s.store.GetChain(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var meta validate.UserMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		writeErr(w, http.StatusInternalServerError, "bad_meta", err.Error())
		return
	}
	// Bind: only the chain owner (matching super_pub) may read.
	if subtle.ConstantTimeCompare(auth.Pub, meta.SuperPub) != 1 {
		writeErr(w, http.StatusForbidden, "forbidden", "signing key does not match chain user_super_pub")
		return
	}
	q := r.URL.Query()
	lastSTHSize := uint64(0)
	if v := q.Get("last_sth_size"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_last_sth_size", err.Error())
			return
		}
		lastSTHSize = n
	}
	if q.Get("latest") == "true" {
		ev, err := s.store.LatestEvent(r.Context(), chainID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		var dec proto.UserEvent
		if err := proto.Unmarshal(ev.CBOR, &dec); err != nil {
			writeErr(w, http.StatusInternalServerError, "bad_event", err.Error())
			return
		}
		sth, incs, cons, perr := s.store.ProofsForChain(r.Context(), chainID, []uint64{ev.Seq}, lastSTHSize)
		if errors.Is(perr, store.ErrIndexOutOfRange) {
			writeErr(w, http.StatusBadRequest, "out_of_range", "last_sth_size beyond current tree")
			return
		}
		if perr != nil {
			writeErr(w, http.StatusInternalServerError, "internal", perr.Error())
			return
		}
		writeCBOR(w, http.StatusOK, map[string]any{
			"user_super_pub":    meta.SuperPub,
			"event":             dec,
			"chain_tip_seq":     c.TipSeq,
			"chain_tip_hash":    c.TipHash,
			"sth":               sth,
			"inclusion_proofs":  incs,
			"consistency_proof": cons,
		})
		return
	}
	since := uint64(0)
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_since", err.Error())
			return
		}
		since = n
	}
	// SECURITY (codex audit 🟡 server.go:438): API.md §2.2 says
	// `?since=<seq>` returns events with seq ≥ since (inclusive),
	// but EventsSince was exclusive. With since=0 the genesis
	// (seq=0) was silently skipped. Use the inclusive variant.
	rows, err := s.store.EventsSinceInclusive(r.Context(), chainID, since, 1000, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]proto.UserEvent, 0, len(rows))
	leafIndices := make([]uint64, 0, len(rows))
	for _, e := range rows {
		var d proto.UserEvent
		if err := proto.Unmarshal(e.CBOR, &d); err != nil {
			writeErr(w, http.StatusInternalServerError, "bad_event", err.Error())
			return
		}
		out = append(out, d)
		leafIndices = append(leafIndices, e.Seq)
	}
	sth, incs, cons, perr := s.store.ProofsForChain(r.Context(), chainID, leafIndices, lastSTHSize)
	if errors.Is(perr, store.ErrIndexOutOfRange) {
		writeErr(w, http.StatusBadRequest, "out_of_range", "last_sth_size beyond current tree")
		return
	}
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, "internal", perr.Error())
		return
	}
	s.cfg.Observer.OnEventsPulled("user", len(out))
	writeCBOR(w, http.StatusOK, map[string]any{
		"user_super_pub":    meta.SuperPub,
		"events":            out,
		"chain_tip_seq":     c.TipSeq,
		"chain_tip_hash":    c.TipHash,
		"sth":               sth,
		"inclusion_proofs":  incs,
		"consistency_proof": cons,
	})
}

// POST /users/<shortId>/events — authenticated append to user chain.
func (s *Server) handleAppendUser(w http.ResponseWriter, r *http.Request) {
	auth, code, err := s.verifyHTTPSig(r.Context(), r)
	if err != nil {
		var rle rateLimitedError
		if errors.As(err, &rle) {
			s.writeRateLimited(w, rle.RetryAfter())
			return
		}
		writeErr(w, code, "auth", err.Error())
		return
	}
	sid := r.PathValue("shortId")
	chainID := store.ChainID(store.KindUser, sid)
	c, err := s.store.GetChain(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var meta validate.UserMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		writeErr(w, http.StatusInternalServerError, "bad_meta", err.Error())
		return
	}
	if !equalBytes(meta.SuperPub, auth.Pub) {
		writeErr(w, http.StatusForbidden, "not_authorized", "pk != chain owner")
		return
	}
	var req struct {
		Event       proto.UserEvent `cbor:"event"`
		LastSTHSize uint64          `cbor:"last_sth_size,omitempty"`
	}
	if err := proto.Unmarshal(auth.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	if err := validate.UserEvent(&req.Event, &meta, c.TipHash, c.TipSeq); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_event", err.Error())
		return
	}
	prefix, err := req.Event.PrevHashInput()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tipHash := proto.HashPrefix(prefix)
	cb, err := proto.Marshal(&req.Event)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	eventID := proto.EventID(prefix)
	sth, err := s.store.AppendWithTranslog(r.Context(), store.AppendOpts{
		ChainID:     chainID,
		Kind:        store.KindUser,
		Genesis:     false,
		Seq:         req.Event.Seq,
		NewTipHash:  tipHash[:],
		NewMetadata: c.Metadata, // unchanged (super_pub fixed; shortId fixed)
		Event: store.Event{
			Seq:      req.Event.Seq,
			EventID:  eventID,
			PrevHash: req.Event.PrevHash,
			Kind:     proto.KindAuthSet,
			CBOR:     cb,
		},
	}, tipHash[:], uint64(time.Now().Unix()))
	switch {
	case errors.Is(err, store.ErrDivergence):
		writeCBOR(w, http.StatusConflict, map[string]any{
			"reason":           "divergence",
			"current_tip_seq":  c.TipSeq,
			"current_tip_hash": c.TipHash,
		})
		return
	case errors.Is(err, store.ErrDuplicate):
		// Dup → fetch the stored event's seq + build STH/proofs so the
		// client can advance LastSTH atomically (TRANSLOG.md §5.4
		// "MANDATORY iff accepted or dup"). If the bookkeeping fetch
		// fails we cannot honor the contract — surface as internal
		// (NOT a degraded "dup" without proof, codex C3 review).
		dupSeq, lerr := s.store.EventSeqByID(r.Context(), eventID)
		if lerr != nil {
			writeErr(w, http.StatusInternalServerError, "internal", lerr.Error())
			return
		}
		dupSTH, dupIncs, dupCons, perr := s.store.ProofsForChain(r.Context(), chainID, []uint64{dupSeq}, req.LastSTHSize)
		if errors.Is(perr, store.ErrIndexOutOfRange) {
			writeErr(w, http.StatusBadRequest, "out_of_range", "last_sth_size beyond current tree")
			return
		}
		if perr != nil {
			writeErr(w, http.StatusInternalServerError, "internal", perr.Error())
			return
		}
		writeCBOR(w, http.StatusConflict, map[string]any{
			"reason":            "dup",
			"event_id":          eventID,
			"seq":               dupSeq,
			"sth":               dupSTH,
			"inclusion_proof":   dupIncs[0],
			"consistency_proof": dupCons,
		})
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_, incs, cons, perr := s.store.ProofsForChain(r.Context(), chainID, []uint64{req.Event.Seq}, req.LastSTHSize)
	if errors.Is(perr, store.ErrIndexOutOfRange) {
		writeErr(w, http.StatusBadRequest, "out_of_range", "last_sth_size beyond current tree")
		return
	}
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, "internal", perr.Error())
		return
	}
	writeCBOR(w, http.StatusOK, map[string]any{
		"event_id":          eventID,
		"seq":               req.Event.Seq,
		"sth":               sth,
		"inclusion_proof":   incs[0],
		"consistency_proof": cons,
	})
}

// ---- /sync ----

// SyncReq mirrors API.md §2.4.
type SyncReq struct {
	Pull syncPull   `cbor:"pull"`
	Push []pushItem `cbor:"push"`
}
type syncPull struct {
	Scopes              map[string]syncCursor `cbor:"scopes"`
	LimitPerScope       uint64                `cbor:"limit_per_scope"`
	DiscoverMemberships bool                  `cbor:"discover_memberships"`
	MembershipAfter     string                `cbor:"membership_after,omitempty"`
	MembershipLimit     uint64                `cbor:"membership_limit,omitempty"`
}
type syncCursor struct {
	Cursor cursorPos `cbor:"cursor"`
	// LastSTHSize is the client's most recent persisted translog
	// tree_size for this scope (TRANSLOG.md §5.4). When > 0 the
	// server includes a consistency proof from this size to the
	// current STH in the response. When 0 (or absent) the response
	// omits the consistency proof — the client must re-pin via the
	// next round.
	LastSTHSize uint64 `cbor:"last_sth_size,omitempty"`
}
type cursorPos struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}
type pushItem struct {
	Scope string           `cbor:"scope"` // "" for genesis
	Event proto.ScopeEvent `cbor:"event"`
	// LastSTHSize is the client's most recent persisted translog
	// tree_size for THIS chain (TRANSLOG.md §5.5). The server
	// returns a synchronous consistency proof in PushResult so the
	// client can advance LastSTH atomically with the push, without
	// a follow-up round-trip.
	LastSTHSize uint64 `cbor:"last_sth_size,omitempty"`
}

// SyncResp is the response shape.
type SyncResp struct {
	Pull                 map[string]pullScope `cbor:"pull"`
	Memberships          []membership         `cbor:"memberships,omitempty"`
	MembershipsNextAfter string               `cbor:"memberships_next_after,omitempty"`
	Push                 []pushResult         `cbor:"push"`
}
type pullScope struct {
	Tip           tipPos             `cbor:"tip"`
	OEKVersionMax uint64             `cbor:"oek_version_max"`
	Events        []proto.ScopeEvent `cbor:"events"`
	// Denied is set when the caller is not (or no longer) a member; the
	// client interprets this as "you've been removed; drop locally".
	Denied bool `cbor:"denied,omitempty"`

	// Translog data per TRANSLOG.md §5.4. STH is mandatory when not
	// denied and the chain has at least one event. InclusionProofs is
	// one proof per element of Events, each against STH.TreeSize.
	// ConsistencyProof is present iff the request supplied
	// LastSTHSize > 0 AND that size is strictly less than the
	// current STH size.
	STH              *translog.STH              `cbor:"sth,omitempty"`
	InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
	ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
}
type tipPos struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}
type membership struct {
	ScopeID    string `cbor:"scope_id"`
	AdmitEvent string `cbor:"admit_event"`
	OEKVersion uint64 `cbor:"oek_version"`
}
type pushResult struct {
	Accepted             bool   `cbor:"accepted"`
	EventID              string `cbor:"event_id,omitempty"`
	Seq                  uint64 `cbor:"seq,omitempty"`
	ScopeID              string `cbor:"scope_id,omitempty"`
	Reason               string `cbor:"reason,omitempty"`
	Detail               string `cbor:"detail,omitempty"`
	CurrentTipEventID    string `cbor:"current_tip_event_id,omitempty"`
	CurrentTipHash       []byte `cbor:"current_tip_hash,omitempty"`
	CurrentOEKVersionMax uint64 `cbor:"current_oek_version_max,omitempty"`

	// Translog data per TRANSLOG.md §5.4. Present iff Accepted ||
	// Reason == "dup". InclusionProof covers the just-appended (or
	// already-present) event at leaf_index = Seq. ConsistencyProof is
	// present iff the request item supplied LastSTHSize > 0 AND that
	// size is strictly less than the post-append STH size.
	STH              *translog.STH              `cbor:"sth,omitempty"`
	InclusionProof   *translog.InclusionProof   `cbor:"inclusion_proof,omitempty"`
	ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	auth, code, err := s.verifyHTTPSig(r.Context(), r)
	if err != nil {
		var rle rateLimitedError
		if errors.As(err, &rle) {
			s.writeRateLimited(w, rle.RetryAfter())
			return
		}
		writeErr(w, code, "auth", err.Error())
		return
	}
	var req SyncReq
	if err := proto.Unmarshal(auth.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	// SECURITY (codex audit 🟡 server.go:720+756): cap the per-
	// request work so one signed body cannot trigger unbounded
	// DB / proof lookups under one rate-limit token. 256 scopes
	// + 64 push items per request is an order-of-magnitude
	// above any realistic v1 client and well below DoS thresholds.
	const maxPullScopes = 256
	const maxPushItems = 64
	const maxPullEvents = 1024
	const maxPullEventBytes = 48 << 20
	if len(req.Pull.Scopes) > maxPullScopes {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_many_pull_scopes",
			fmt.Sprintf("%d > %d", len(req.Pull.Scopes), maxPullScopes))
		return
	}
	if len(req.Push) > maxPushItems {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_many_push_items",
			fmt.Sprintf("%d > %d", len(req.Push), maxPushItems))
		return
	}
	if s.rl != nil && len(req.Push) > 1 {
		ident := base64.StdEncoding.EncodeToString(auth.Pub)
		if d := s.rl.AcquireWrites(ident, len(req.Push)-1); !d.Allow {
			s.writeRateLimited(w, d.Retry)
			return
		}
	}
	resp := SyncResp{Pull: map[string]pullScope{}}
	limit := boundedPullLimit(int(req.Pull.LimitPerScope), len(req.Pull.Scopes), maxPullEvents)
	// Pull. Caller must be in the scope's auth_list to receive any events.
	// Three response states per scope:
	//   served (Events filled)                 → normal apply
	//   denied=true                            → caller no longer authorised
	//   absent from resp.Pull                  → server doesn't have the scope yet
	scopeIDs := make([]string, 0, len(req.Pull.Scopes))
	for sid := range req.Pull.Scopes {
		scopeIDs = append(scopeIDs, sid)
	}
	sort.Slice(scopeIDs, func(i, j int) bool {
		left := req.Pull.Scopes[scopeIDs[i]].Cursor.Seq
		right := req.Pull.Scopes[scopeIDs[j]].Cursor.Seq
		if left != right {
			return left < right
		}
		return scopeIDs[i] < scopeIDs[j]
	})
	remainingPullBytes := maxPullEventBytes
	for _, sid := range scopeIDs {
		cur := req.Pull.Scopes[sid]
		fresh := len(cur.Cursor.Hash) == 0 && cur.Cursor.Seq == 0
		ps, usedBytes, err := s.pullScope(
			r.Context(),
			sid,
			cur.Cursor.Seq,
			limit,
			remainingPullBytes,
			maxPullEventBytes,
			auth.Pub,
			fresh,
			cur.LastSTHSize,
		)
		if err != nil {
			switch {
			case errors.Is(err, errPullBudget):
				continue
			case errors.Is(err, errPullEventTooLarge):
				writeErr(w, http.StatusRequestEntityTooLarge, "stored_event_too_large", err.Error())
				return
			case errors.Is(err, errNotMember):
				resp.Pull[sid] = pullScope{Denied: true}
			case errors.Is(err, store.ErrNotFound):
				// Server doesn't have this scope — leave absent from
				// the response. This is the normal "scope unknown"
				// case (caller probing an id we never created).
				s.log.Debug("pull scope absent", "scope", sid)
			case errors.Is(err, store.ErrIndexOutOfRange):
				// Caller's last_sth_size > current tree. Hard fail
				// the request so the client clamps its state.
				writeErr(w, http.StatusBadRequest, "out_of_range", "last_sth_size beyond current tree for scope "+sid)
				return
			default:
				// Translog or storage error: server invariant break.
				// 500 so the client retries cleanly rather than acting
				// on a partially-translog'd response.
				writeErr(w, http.StatusInternalServerError, "internal", err.Error())
				return
			}
			continue
		}
		remainingPullBytes -= usedBytes
		resp.Pull[sid] = ps
		s.cfg.Observer.OnEventsPulled("scope", len(ps.Events))
	}
	// Discover.
	if req.Pull.DiscoverMemberships {
		ms, nextAfter, err := s.discoverMemberships(
			r.Context(),
			auth.Pub,
			req.Pull.MembershipAfter,
			int(req.Pull.MembershipLimit),
		)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if membershipPaginationRequired(req.Pull.MembershipLimit, nextAfter) {
			writeErr(
				w,
				http.StatusUpgradeRequired,
				"membership_pagination_required",
				"upgrade fd0 to discover more than 256 scopes",
			)
			return
		}
		resp.Memberships = ms
		resp.MembershipsNextAfter = nextAfter
	}
	// Push.
	for _, p := range req.Push {
		pr := s.applyPush(r.Context(), auth.Pub, p)
		resp.Push = append(resp.Push, pr)
		// Metrics: count every push outcome by chain_kind+result so
		// dashboards can tell apart "all client divergences" from
		// "server internal-errors". chain_kind comes from the scope
		// being empty (user chain) or set (scope chain).
		kind := "scope"
		if pr.ScopeID == "" && p.Scope == "" {
			kind = "user"
		}
		result := "ok"
		if !pr.Accepted {
			result = pr.Reason
		}
		s.cfg.Observer.OnEventPushed(kind, result)
	}
	writeCBOR(w, http.StatusOK, resp)
}

func (s *Server) pullScope(
	ctx context.Context,
	scopeID string,
	since uint64,
	limit int,
	byteBudget int,
	maxEventBytes int,
	callerPub []byte,
	fresh bool,
	lastSTHSize uint64,
) (pullScope, int, error) {
	chainID := store.ChainID(store.KindScope, scopeID)
	c, err := s.store.GetChain(ctx, chainID)
	if err != nil {
		return pullScope{}, 0, err
	}
	var meta validate.ScopeMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		return pullScope{}, 0, err
	}
	isMember := false
	for _, m := range meta.Members {
		if equalBytes(m, callerPub) {
			isMember = true
			break
		}
	}
	if !isMember {
		return pullScope{}, 0, errNotMember
	}
	rows, usedBytes, nextBytes, err := s.store.EventsSinceInclusiveBudget(
		ctx,
		chainID,
		since,
		limit,
		fresh,
		byteBudget,
	)
	if err != nil {
		return pullScope{}, 0, err
	}
	if nextBytes > maxEventBytes {
		return pullScope{}, 0, errPullEventTooLarge
	}
	if len(rows) == 0 && nextBytes > 0 {
		return pullScope{}, 0, errPullBudget
	}
	out := pullScope{
		Tip:           tipPos{Seq: c.TipSeq, Hash: c.TipHash},
		OEKVersionMax: meta.OEKVersionMax,
		Events:        make([]proto.ScopeEvent, 0, len(rows)),
	}
	leafIndices := make([]uint64, 0, len(rows))
	for _, e := range rows {
		var d proto.ScopeEvent
		if err := proto.Unmarshal(e.CBOR, &d); err != nil {
			return pullScope{}, 0, err
		}
		out.Events = append(out.Events, d)
		// In our scheme, leaf_index == event.Seq (events are appended
		// in seq order, leaves grow with the tree).
		leafIndices = append(leafIndices, e.Seq)
	}
	// Translog payload — STH is mandatory whenever the chain has any
	// events; for empty `events[]` the client still benefits from an
	// updated STH + consistency proof. Failure here is a server
	// invariant break (AppendWithTranslog committed atomically), so
	// surface as an error to the request handler rather than degrade
	// the response (per TRANSLOG.md §5.4: STH MANDATORY when not denied).
	sth, incs, cons, perr := s.store.ProofsForChain(ctx, chainID, leafIndices, lastSTHSize)
	if perr != nil {
		return pullScope{}, 0, perr
	}
	out.STH = sth
	if len(incs) > 0 {
		out.InclusionProofs = incs
	}
	out.ConsistencyProof = cons
	return out, usedBytes, nil
}

func membershipPaginationRequired(requestedLimit uint64, nextAfter string) bool {
	return requestedLimit == 0 && nextAfter != ""
}

func (s *Server) discoverMemberships(ctx context.Context, pk []byte, after string, limit int) ([]membership, string, error) {
	scopes, nextAfter, err := s.store.ScopesForMemberPage(ctx, pk, after, limit)
	if err != nil {
		return nil, "", err
	}
	var out []membership
	for _, c := range scopes {
		var meta validate.ScopeMeta
		if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
			continue
		}
		isMember := false
		for _, m := range meta.Members {
			if equalBytes(m, pk) {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}
		// Find the admit event (latest member.change op=add of pk). For v1
		// simplicity we report the genesis event ID by scanning.
		// scope_id is the suffix after "scope:".
		scopeID := strings.TrimPrefix(c.ID, "scope:")
		out = append(out, membership{
			ScopeID:    scopeID,
			AdmitEvent: "", // optional in v1; clients can pull from cursor=0
			OEKVersion: meta.OEKVersionMax,
		})
	}
	return out, nextAfter, nil
}

func (s *Server) applyPush(ctx context.Context, authorPub []byte, p pushItem) pushResult {
	sp := &p.Event.SignedPrefix
	// Author == auth principal.
	if !equalBytes(sp.Author, authorPub) {
		return pushResult{Accepted: false, Reason: "bad_author"}
	}
	// Genesis push: scope_id is empty; we derive it.
	if len(sp.PrevHash) == 0 && sp.Seq == 0 && p.Scope == "" {
		prefix, _ := p.Event.PrevHashInput()
		eventID := proto.EventID(prefix)
		// Server uses scopeID as a string identifier into the store
		// + push-result struct; convert at the boundary so downstream
		// call sites stay typed against the store API.
		scopeID := proto.DeriveScopeID(eventID).String()
		if exists, _ := s.eventExists(ctx, eventID); exists {
			// Seq=0 explicit so the client's PushFloor advance logic works
			// uniformly across success and dup responses. STH + proofs
			// also mandatory on dup per TRANSLOG.md §5.4.
			return s.dupPushResult(ctx, store.ChainID(store.KindScope, scopeID), scopeID, eventID, 0, p.LastSTHSize)
		}
		newMeta, err := validate.ScopeEvent(&p.Event, nil, nil, 0)
		if err != nil {
			return pushResult{Accepted: false, Reason: pushReasonFor(err)}
		}
		// store. Note: scope_id MUST be set in the event's signed prefix at
		// this point only if the client built it that way. Per PROTOCOL.md
		// the genesis event's `scope` field is nil. We use the derived ID for
		// the chain row only.
		mb, _ := proto.Marshal(*newMeta)
		cb, _ := proto.Marshal(&p.Event)
		tipHash := proto.HashPrefix(prefix)
		chainID := store.ChainID(store.KindScope, scopeID)
		sth, err := s.store.AppendWithTranslog(ctx, store.AppendOpts{
			ChainID:     chainID,
			Kind:        store.KindScope,
			Genesis:     true,
			Seq:         0,
			NewTipHash:  tipHash[:],
			NewMetadata: mb,
			Event: store.Event{
				Seq: 0, EventID: eventID, PrevHash: nil,
				Kind: proto.KindMemberChange, CBOR: cb,
			},
		}, tipHash[:], uint64(time.Now().Unix()))
		if errors.Is(err, store.ErrDuplicate) {
			// Race: another caller raced us between our exists-probe
			// and the INSERT. Build a full dup result with STH + proofs.
			return s.dupPushResult(ctx, chainID, scopeID, eventID, 0, p.LastSTHSize)
		}
		if err != nil {
			return pushResult{Accepted: false, Reason: "internal"}
		}
		// Translog payload — genesis is leaf 0 in a tree of size 1.
		// p.LastSTHSize is typically 0 for genesis (first event ever).
		_, incs, cons, perr := s.store.ProofsForChain(ctx, chainID, []uint64{0}, p.LastSTHSize)
		if errors.Is(perr, store.ErrIndexOutOfRange) {
			return pushResult{Accepted: false, Reason: "out_of_range", ScopeID: scopeID}
		}
		if perr != nil {
			return pushResult{Accepted: false, Reason: "internal", ScopeID: scopeID}
		}
		return pushResult{
			Accepted:         true,
			EventID:          eventID,
			Seq:              0,
			ScopeID:          scopeID,
			STH:              &sth,
			InclusionProof:   &incs[0],
			ConsistencyProof: cons,
		}
	}
	// Successor push.
	chainID := store.ChainID(store.KindScope, p.Scope)
	// SECURITY (codex audit 🔴 server.go:923): the OUTER push frame
	// names a scope, but the SIGNED event also embeds the scope
	// (signed_prefix.scope). They MUST agree — without this check,
	// an attacker could submit a signed event for chain X under
	// the framing of chain Y, getting it stored on Y where the
	// signature still verifies (the signature covers the embedded
	// scope, which says X). Bind the two together explicitly.
	if p.Event.SignedPrefix.Scope == nil || *p.Event.SignedPrefix.Scope != p.Scope {
		var got string
		if p.Event.SignedPrefix.Scope != nil {
			got = *p.Event.SignedPrefix.Scope
		}
		return pushResult{Accepted: false, Reason: "scope_mismatch", ScopeID: p.Scope,
			Detail: fmt.Sprintf("event signed_prefix.scope=%q, push frame scope=%q", got, p.Scope)}
	}
	c, err := s.store.GetChain(ctx, chainID)
	if err != nil {
		return pushResult{Accepted: false, Reason: "not_found", ScopeID: p.Scope}
	}
	// Early dup check.
	prefix, _ := p.Event.PrevHashInput()
	eventID := proto.EventID(prefix)
	if exists, _ := s.eventExists(ctx, eventID); exists {
		// Echo Seq so the client's push-floor advance logic works on
		// dups; build STH+proofs so the client can advance LastSTH
		// atomically (TRANSLOG.md §5.4 mandates them on dup too).
		return s.dupPushResult(ctx, chainID, p.Scope, eventID, sp.Seq, p.LastSTHSize)
	}
	var meta validate.ScopeMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		return pushResult{Accepted: false, Reason: "internal", ScopeID: p.Scope}
	}
	newMeta, err := validate.ScopeEvent(&p.Event, &meta, c.TipHash, c.TipSeq)
	if err != nil {
		return pushResult{Accepted: false, Reason: pushReasonFor(err), ScopeID: p.Scope}
	}
	tipHash := proto.HashPrefix(prefix)
	mb, _ := proto.Marshal(*newMeta)
	cb, _ := proto.Marshal(&p.Event)
	sth, err := s.store.AppendWithTranslog(ctx, store.AppendOpts{
		ChainID:     chainID,
		Kind:        store.KindScope,
		Genesis:     false,
		Seq:         sp.Seq,
		NewTipHash:  tipHash[:],
		NewMetadata: mb,
		Event: store.Event{
			Seq: sp.Seq, EventID: eventID, PrevHash: sp.PrevHash,
			Kind: sp.Kind, CBOR: cb,
		},
	}, tipHash[:], uint64(time.Now().Unix()))
	switch {
	case errors.Is(err, store.ErrDivergence):
		return pushResult{
			Accepted:             false,
			Reason:               "divergence",
			ScopeID:              p.Scope,
			CurrentTipHash:       c.TipHash,
			CurrentOEKVersionMax: meta.OEKVersionMax,
		}
	case errors.Is(err, store.ErrDuplicate):
		// Race: between our exists() probe and the INSERT another
		// caller landed the same event_id. Treat as dup.
		return s.dupPushResult(ctx, chainID, p.Scope, eventID, sp.Seq, p.LastSTHSize)
	case err != nil:
		return pushResult{Accepted: false, Reason: "internal", ScopeID: p.Scope}
	}
	_, incs, cons, perr := s.store.ProofsForChain(ctx, chainID, []uint64{sp.Seq}, p.LastSTHSize)
	if errors.Is(perr, store.ErrIndexOutOfRange) {
		return pushResult{Accepted: false, Reason: "out_of_range", ScopeID: p.Scope}
	}
	if perr != nil {
		return pushResult{Accepted: false, Reason: "internal", ScopeID: p.Scope}
	}
	return pushResult{
		Accepted:         true,
		EventID:          eventID,
		Seq:              sp.Seq,
		ScopeID:          p.Scope,
		STH:              &sth,
		InclusionProof:   &incs[0],
		ConsistencyProof: cons,
	}
}

// dupPushResult builds a complete pushResult for a "dup" outcome —
// STH + InclusionProof against the previously-stored event, plus an
// optional consistency proof. Centralised here because all four
// dup-detection sites (genesis-exists, successor-exists,
// successor-race-on-insert, and a hypothetical user-chain dup) need
// identical output.
//
// scopeID is the user-facing ScopeID ("" for user chain or genesis-
// without-suffix); chainID is the storage-layer chain id.
//
// `seqHint` is the seq to use for the InclusionProof leaf_index. For
// genesis dup we know it's 0 (no chain row yet to look up). For
// successor dup callers can pass either the request's claimed seq OR
// the result of EventSeqByID — they must be equal for a real dup, so
// passing the request's seq is the safer trip-wire.
func (s *Server) dupPushResult(ctx context.Context, chainID, scopeID, eventID string, seqHint, lastSTHSize uint64) pushResult {
	// Trust the request's seq for the proof — it MUST match the stored
	// event's seq for "dup" to be coherent. If the seq came from a
	// genesis push (seqHint == 0 by construction), this matches too.
	sth, incs, cons, perr := s.store.ProofsForChain(ctx, chainID, []uint64{seqHint}, lastSTHSize)
	if perr != nil {
		// TRANSLOG.md §5.4: STH MANDATORY iff accepted or dup. We
		// can't satisfy that contract — promote to internal so the
		// client retries cleanly rather than acting on half-truths.
		// last_sth_size > current is reported as a separate reason
		// so the client knows to clamp.
		if errors.Is(perr, store.ErrIndexOutOfRange) {
			return pushResult{Accepted: false, Reason: "out_of_range", ScopeID: scopeID, EventID: eventID, Seq: seqHint}
		}
		return pushResult{Accepted: false, Reason: "internal", ScopeID: scopeID}
	}
	return pushResult{
		Accepted:         false,
		Reason:           "dup",
		ScopeID:          scopeID,
		EventID:          eventID,
		Seq:              seqHint,
		STH:              sth,
		InclusionProof:   &incs[0],
		ConsistencyProof: cons,
	}
}

// pushReasonFor maps validate errors to API.md §2.4 reason strings.
func pushReasonFor(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "bad signature"):
		return "bad_sig"
	case strings.Contains(msg, "oek_version"):
		if strings.Contains(msg, "want") || strings.Contains(msg, "expected") {
			return "stale_oek_version"
		}
		return "future_oek_version"
	case strings.Contains(msg, "key_deliveries"):
		return "invalid_key_deliveries"
	case strings.Contains(msg, "prev_hash"),
		strings.Contains(msg, "seq=") && strings.Contains(msg, "expected"):
		return "divergence"
	default:
		return "bad_kind"
	}
}

// ---- helpers ----

func writeCBOR(w http.ResponseWriter, code int, v any) {
	b, err := proto.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, code int, reason, detail string) {
	writeCBOR(w, code, map[string]string{"reason": reason, "detail": detail})
}

var (
	errNotMember         = errors.New("not a member")
	errPullBudget        = errors.New("pull response byte budget exhausted")
	errPullEventTooLarge = errors.New("stored event exceeds pull response byte budget")
)

// eventExists is a tiny shortcut against the events table. Used by applyPush
// for early dup detection (cheaper than running the full validator against
// stale prior state).
func (s *Server) eventExists(ctx context.Context, eventID string) (bool, error) {
	return s.store.EventExists(ctx, eventID)
}

// writeRateLimited emits a 429 with a Retry-After header. The CBOR body
// matches the standard error envelope for consistency with the rest of the
// API.
func (s *Server) writeRateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "rate_limited", "retry after "+strconv.Itoa(secs)+"s")
}

// clientIP extracts the caller IP for per-IP rate limiting. We deliberately
func boundedPullLimit(requested, scopeCount, aggregateLimit int) int {
	if requested <= 0 || requested > 1000 {
		requested = 100
	}
	if scopeCount <= 0 || aggregateLimit <= 0 {
		return requested
	}
	if perScope := aggregateLimit / scopeCount; perScope < requested {
		return perScope
	}
	return requested
}

// clientIP trusts X-Forwarded-For only from an explicitly configured reverse
// proxy and only when it contains one valid IP. This keeps rate-limit identity
// under operator control instead of accepting a client-spoofable header.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	trusted := false
	for _, network := range s.trustedProxies {
		if remoteIP != nil && network.Contains(remoteIP) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return host
	}
	forwarded := strings.TrimSpace(values[0])
	if net.ParseIP(forwarded) == nil {
		return host
	}
	return forwarded
}

func equalBytes(a, b []byte) bool {
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

// newShortID returns 8 chars of Crockford-base32. v1 uses standard base32
// with the same charset minus padding; we lower-case and remap I/O/L to keep
// human-readability.
func newShortID() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure
	}
	const charset = "0123456789abcdefghjkmnpqrstvwxyz" // Crockford
	out := make([]byte, 8)
	bits := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	for i := 0; i < 8; i++ {
		out[i] = charset[bits&31]
		bits >>= 5
	}
	return string(out)
}

// noncePruner runs once a minute and trims expired auth_nonces.
// Terminates when ctx is canceled (Server.Close).
func (s *Server) noncePruner(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := s.store.PruneNonces(pctx, nonceTTLSecs); err != nil {
				s.log.Warn("prune nonces", "err", err)
			}
			cancel()
		}
	}
}

// Run starts an http.Server bound to cfg.Bind and blocks.
//
// SECURITY (codex audit 🔴 cmd/fd0-server/main.go:64): handles
// SIGINT/SIGTERM for graceful Shutdown. Without this, SIGTERM
// (the default kill signal sent by Docker / systemd / kubectl)
// would abort in-flight requests AND skip the deferred srv.Close()
// in the caller, leaving the SQLite WAL with un-checkpointed
// pages and dropping the cancellable noncePruner goroutine.
func Run(s *Server) error {
	srv := &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("fd0-server listening", "bind", s.cfg.Bind, "version", s.cfg.Version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("fd0-server: signal received, shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return <-errCh
	}
}

// validChainID enforces the exact STORAGE.md §2 chain-id shape:
//
//	user:<shortId>      — shortId is 8 Crockford-base32 chars
//	scope:<scope_id>    — scope_id is "s_" + 26 lowercase RFC 4648 base32 chars
//
// Anything else is rejected at the unauthenticated endpoints. Two reasons:
//
//   - Future-proofing: if we add a namespace later (e.g., "witness:"),
//     a permissive prefix check would accidentally publish data from
//     it. Strict shape matching makes new namespaces opt-in.
//   - DoS sanity: rejects multi-MB chain ids that would otherwise hit
//     the DB query layer; bounded length cap is the floor.
//
// Length cap is generous (64 chars) — current shapes max at "scope:s_"
// + 26 = 34. Caps DOS surface without sweating exact arithmetic.
func validChainID(s string) bool {
	if len(s) > 64 {
		return false
	}
	if rest, ok := strings.CutPrefix(s, "user:"); ok {
		return validShortID(rest)
	}
	if rest, ok := strings.CutPrefix(s, "scope:"); ok {
		return validScopeID(rest)
	}
	return false
}

// validShortID checks the 8-char Crockford-base32 form emitted by
// newShortID. Charset matches the constant there; if newShortID ever
// changes, both must move together.
func validShortID(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z' && c != 'i' && c != 'l' && c != 'o' && c != 'u':
		default:
			return false
		}
	}
	return true
}

// validScopeID checks the "s_" + 26 lowercase RFC 4648 base32
// (a-z + 2-7) shape emitted by proto.ScopeID.
func validScopeID(s string) bool {
	if len(s) != 28 || !strings.HasPrefix(s, "s_") {
		return false
	}
	for _, c := range s[2:] {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return true
}
