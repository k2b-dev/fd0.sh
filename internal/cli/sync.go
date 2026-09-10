package cli

// Sync orchestrator. The big workhorse is RunSync: one round-trip
// covers pull + push + discovery + per-scope translog verification.
// Divergence handling, scope discovery, and shared helpers are split out:
//
//   - sync_internal.go   — buildSyncRequestBody, leafHashAtSeq,
//                          decryptSecretBody, upsertOEK, fileSize, …
//   - sync_discover.go   — first-time pull of newly admitted scopes
//   - sync_reconcile.go  — divergence recovery + rebuild loop
//
// signedPOST stays here because every file above eventually goes
// through this transport seam — keeping it next to RunSync makes
// the auth contract (server_pub binding for cross-server replay
// resistance) easy to find.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/httpguard"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// pullCursor is the per-scope position we want the server to send events
// from, in /sync requests. (seq=0, hash=nil) means "send from the
// genesis"; otherwise the server sends events with seq > Seq whose
// prev_hash chain-binds to Hash.
//
// LastSTHSize anchors the translog consistency check (TRANSLOG.md §5.4).
// Zero = no anchor yet (fresh subscription) → server omits the
// consistency proof. Non-zero = client demands a consistency proof
// from this size to the current STH; client will refuse to advance
// LastSTH if the proof doesn't verify.
type pullCursor struct {
	Seq         uint64
	Hash        []byte
	LastSTHSize uint64
}

var (
	errSyncMorePushes  = errors.New("sync: more local pushes pending")
	errSyncRateLimited = errors.New("sync: push batch rate limited")
)

const initialSyncPushBatch = 32

const (
	membershipPageSize        = 32
	maxMembershipPagesPerSync = 4
)

type syncRunBudget struct {
	scopes          map[string]bool // nil syncs all; organization moves restrict destination scopes.
	membershipPages int
}

// RunSync pushes any local-only events to the configured fd0-server and pulls
// new events from there.
//
// v1 is intentionally minimal: push is a single best-effort attempt; pull
// covers every locally-known scope from cursor=local_tip.
//
// RunSync targets one server. RunSyncPrimary wraps it with config/env/flag
// resolution and is the entry point most callers want; the bare-server entry
// here is for explicit, single-target
// invocations (tests, scripts). Passing "" resolves the primary like
// RunSyncPrimary does.
func RunSync(ctx context.Context, server string) error {
	budget := &syncRunBudget{membershipPages: maxMembershipPagesPerSync}
	return runSyncBatches(ctx, server, budget, runSyncRound)
}

func runSyncBatches(
	ctx context.Context,
	server string,
	budget *syncRunBudget,
	runRound func(context.Context, string, int, *syncRunBudget) error,
) error {
	pushLimit := initialSyncPushBatch
	for {
		err := runRound(ctx, server, pushLimit, budget)
		switch {
		case errors.Is(err, errSyncMorePushes):
			continue
		case errors.Is(err, errSyncRateLimited) && pushLimit > 1:
			pushLimit = (pushLimit + 1) / 2
			continue
		default:
			return err
		}
	}
}

func runSyncRound(ctx context.Context, server string, pushLimit int, budget *syncRunBudget) error {
	if server == "" {
		// Resolve the single primary from flag/env/config. A stale pre-A1
		// [sync].servers array errors here with migration guidance.
		resolved, err := ResolvePrimary("")
		if err != nil {
			return err
		}
		server = resolved
	}
	paths, _ := fdhome.Resolve()
	cfg, _ := fdhome.LoadConfig(paths.Config)
	// Wave C-2: parse + canonicalise once at the entry boundary; the
	// typed canon.URL is passed through every downstream helper so
	// the "trailing-slash drift between sync and witness" class is
	// structurally eliminated — every consumer sees the same byte-
	// stable form.
	serverURL, err := canon.ParseURL(server)
	if err != nil {
		return fmt.Errorf("server URL: %w", err)
	}
	// Build the witness cross-check client BEFORE opening the
	// session. A bad [[witness]] config should fail loudly, not get
	// hidden behind the unlock prompt.
	wcc, err := NewWitnessCheckClient(cfg)
	if err != nil {
		return fmt.Errorf("witness config: %w", err)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	// First-contact pinning: ensure (server URL, server pubkey) is in
	// the vault before any STH from this server is trusted. Subsequent
	// rounds short-circuit (the pin is persistent across syncs).
	pinnedPub, err := s.EnsurePinnedServer(ctx, serverURL)
	if err != nil {
		return err
	}
	// Codex audit fix (🔴 auth.go:87 + cli/sync.go:131): the server
	// requires user_super_pub be registered via POST /users before
	// honouring any authenticated request. Wire the registration
	// here so first-time users see no "unregistered_pk" rejection.
	// Idempotent on subsequent syncs (PinnedServer.Registered cache).
	if err := s.EnsureUserRegistered(ctx, serverURL); err != nil {
		return fmt.Errorf("user registration: %w", err)
	}
	if budget.scopes == nil {
		if err := s.repairNonContiguousScopes(ctx, wcc, serverURL); err != nil {
			return err
		}
	}

	// Per-server state key for vault lookups. Each pinned server has
	// its own PushFloor + LastSTH per scope; the canonical URL string
	// is what addresses the entry.
	serverKey := serverURL.String()
	membershipAfter := ""
	if pinned, ok := s.Body.PinnedServers[serverKey]; ok {
		membershipAfter = pinned.MembershipAfter
	}
	if membershipAfter != "" {
		if _, err := membershipCursorScopeID(membershipAfter); err != nil {
			return fmt.Errorf("sync membership discovery: persisted cursor: %w", err)
		}
	}

	// Snapshot pre-sync LastSTH per scope. Both pull AND push
	// consistency proofs in this round are relative to the request's
	// last_sth_size, which we computed from the pre-sync state. After
	// pull processing succeeds we update LastSTH; without this
	// snapshot the push verify would compare the server's "from K"
	// proof against an "from N (post-pull)" anchor and falsely reject.
	//
	// Wave D: vault-loaded anchors are wrapped as *VerifiedSTH —
	// they were placed there by a previous successful Verify call
	// in an earlier sync round and the sealed vault rules out
	// tampering, so the type-state holds by induction.
	//
	// v0.0.5: LastSTH is read per-server (sd.LastSTHFor(serverKey)) so
	// server A's STH never anchors a consistency check against server
	// B's tree. Legacy vaults (PerServer empty) fall through to the
	// singular sd.LastSTH for backward compat on first sync.
	preSyncLastSTH := map[string]*VerifiedSTH{}
	for sid, sd := range s.Body.Scopes {
		if budget.scopes != nil && !budget.scopes[sid] {
			continue
		}
		preSyncLastSTH[sid], _ = decodeVerifiedSTH(sd.LastSTHFor(serverKey))
	}

	// First round-trip: discovery + pull for known scopes + push. With a
	// single primary every scope is synced here — there is no per-scope
	// routing and (by construction) no possibility of replica divergence.
	pullScopes := map[string]pullCursor{}
	for sid, sd := range s.Body.Scopes {
		if budget.scopes != nil && !budget.scopes[sid] {
			continue
		}
		pullScopes[sid] = pullCursor{
			Seq:         sd.ChainTip.Seq,
			Hash:        sd.ChainTip.Hash,
			LastSTHSize: scopeLastSTHSizeFor(sd, serverKey),
		}
	}
	// Build push: only events whose seq is at or above the per-server
	// PushFloor for this scope (= "lowest seq we still need to push to
	// THIS server"). Foreign events (authored by another member,
	// fetched via pull) are skipped because they're already on the
	// server and would yield `bad_author`.
	//
	// Bandwidth invariant: PushFloor only advances after the server has
	// accepted (or de-duped) the corresponding event AND the vault has
	// been re-sealed. Any failure between push and re-seal leaves the
	// floor untouched, so the next sync repushes the same suffix; the
	// server idempotent-dedups by event_id. Worst case is extra traffic;
	// data loss is impossible by construction.
	pushItems := []any{}
	for sid, sd := range s.Body.Scopes {
		if budget.scopes != nil && !budget.scopes[sid] {
			continue
		}
		evs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(proto.MustParseScopeID(sid)))
		if err != nil {
			return err
		}
		lastSize := scopeLastSTHSizeFor(sd, serverKey)
		floor := sd.PushFloorFor(serverKey)
		for _, ev := range evs {
			if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
				continue
			}
			if ev.SignedPrefix.Seq < floor {
				continue
			}
			scopeRef := sid
			if ev.SignedPrefix.Seq == 0 {
				scopeRef = ""
			}
			pushItems = append(pushItems, pushItemFor(scopeRef, ev, lastSize))
		}
	}
	morePushes := len(pushItems) > pushLimit
	if morePushes {
		pushItems = pushItems[:pushLimit]
	}
	discoverMemberships := budget.membershipPages > 0
	body, err := buildSyncRequestBody(
		pullScopes,
		pushItems,
		discoverMemberships,
		membershipAfter,
		1000,
	)
	if err != nil {
		return err
	}
	resp, err := s.signedPOST(ctx, serverURL.JoinPath("/v1/sync"), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := httpguard.ReadBody(resp.Body, maxSyncResponseBytes)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			return errSyncRateLimited
		}
		return fmt.Errorf("sync: %s: %s", resp.Status, rb)
	}
	var sr struct {
		Pull map[string]struct {
			Tip struct {
				Seq  uint64 `cbor:"seq"`
				Hash []byte `cbor:"hash"`
			} `cbor:"tip"`
			OEKVersionMax    uint64                     `cbor:"oek_version_max"`
			Events           []proto.ScopeEvent         `cbor:"events"`
			Denied           bool                       `cbor:"denied,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
		} `cbor:"pull"`
		Memberships          []membershipResult `cbor:"memberships"`
		MembershipsNextAfter string             `cbor:"memberships_next_after,omitempty"`
		Push                 []struct {
			Accepted         bool                       `cbor:"accepted"`
			Reason           string                     `cbor:"reason,omitempty"`
			ScopeID          string                     `cbor:"scope_id,omitempty"`
			Seq              uint64                     `cbor:"seq,omitempty"`
			EventID          string                     `cbor:"event_id,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProof   *translog.InclusionProof   `cbor:"inclusion_proof,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
		} `cbor:"push"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return fmt.Errorf("sync: decode resp: %w", err)
	}
	if budget.scopes != nil {
		for sid := range sr.Pull {
			if !budget.scopes[sid] {
				return errors.New("scoped sync returned an unrequested scope")
			}
		}
		for _, result := range sr.Push {
			if result.ScopeID != "" && !budget.scopes[result.ScopeID] {
				return errors.New("scoped sync returned an unrequested scope")
			}
		}
	}
	// Apply pulled events for each known scope.
	dirty := false
	pullReconciled := map[string]struct{}{}
	for sid, ps := range sr.Pull {
		// Server says caller is no longer authorised → drop the scope
		// locally (STORAGE.md §5.3).
		//
		// SECURITY (codex audit 🔴 sync.go:266): vault state must
		// be re-sealed BEFORE removing the chain file. Doing it
		// after meant a ReSeal failure (later in the loop) left
		// the file deleted but the vault still referencing the
		// scope — next sync replayed a missing chain and silently
		// dropped the scope without notification. Order: update
		// vault map → ReSeal → remove file. If ReSeal fails the
		// chain file survives and the scope can be re-discovered.
		if ps.Denied {
			delete(s.Body.Scopes, sid)
			if err := s.ReSeal(); err != nil {
				return fmt.Errorf("scope %s denied: ReSeal failed (chain file kept for retry): %w", sid, err)
			}
			// Codex C-1.1 review fix: a malformed scope_id in a denied
			// server response previously panicked via MustParseScopeID.
			// Use ParseScopeID — silently skip the file-remove when
			// the id can't be validated; the in-memory map delete
			// above already handled the membership downgrade.
			if pid, perr := proto.ParseScopeID(sid); perr == nil {
				_ = os.Remove(s.Paths.ScopeChain(pid))
			}
			fmt.Fprintf(os.Stderr, "  ↳ removed from scope %s\n", shortScopeID(sid))
			continue
		}
		sd, ok := s.Body.Scopes[sid]
		if !ok {
			continue
		}
		// Pending-leave: the user has already issued `scope leave` and
		// we have a local member.change op=remove event queued for push.
		// Skip the pull processing (which would otherwise replay the
		// chain, see the local leave, hit the st.Left branch, and drop
		// the scope before the leave event has reached the server —
		// triggering a futile re-discovery on the next round). The push
		// in this same sync round will land the leave; the *next* sync
		// will get a clean Denied from pull and drop normally.
		if sd.Leaving {
			continue
		}
		if err := validateScopePullPage(sid, pullScopes[sid], ps.Tip.Seq, ps.Tip.Hash, ps.Events); err != nil {
			if errors.Is(err, errScopePullDiverged) {
				if rerr := s.reconcileAndRepush(ctx, wcc, serverURL, sid, 3); rerr != nil {
					return fmt.Errorf("scope %s: pull diverged (%v); reconcile failed: %w", sid, err, rerr)
				}
				pullReconciled[sid] = struct{}{}
				dirty = true
				continue
			}
			return fmt.Errorf("scope %s: invalid pull suffix: %w", sid, err)
		}
		// Translog verification: hard-fail BEFORE any local state
		// mutation. Server invariant per TRANSLOG.md §5.4: STH is
		// mandatory whenever a non-denied response carries chain
		// data. Inclusion proofs cover ps.Events one-for-one,
		// leaf_index == event.Seq for each. Consistency proof covers
		// our PRE-SYNC LastSTH → server's current STH (not the
		// just-updated LastSTH — see snapshot rationale at top).
		priorSTH := preSyncLastSTH[sid]
		leafHashes := make([][]byte, 0, len(ps.Events))
		leafIndices := make([]uint64, 0, len(ps.Events))
		for i := range ps.Events {
			prefix, err := ps.Events[i].PrevHashInput()
			if err != nil {
				return fmt.Errorf("translog: leaf hash for scope %s: %w", sid, err)
			}
			leafHashes = append(leafHashes, translog.LeafHashOfPrevInput(prefix))
			leafIndices = append(leafIndices, ps.Events[i].SignedPrefix.Seq)
		}
		expectedChainID := "scope:" + sid
		verifiedSTH, err := VerifyAndCrossCheck(ctx, wcc, serverURL, pinnedPub, expectedChainID, ps.STH, priorSTH, ps.InclusionProofs, leafIndices, leafHashes, ps.ConsistencyProof)
		if err != nil {
			return fmt.Errorf("scope %s: %w", sid, err)
		}

		path := s.Paths.ScopeChain(proto.MustParseScopeID(sid))
		// SECURITY (subagent regression hunt 🔴): check every
		// event's signed_prefix.scope BEFORE persisting any of
		// them. The post-AppendRaw replay-then-check path leaves
		// a crash window: events fsync'd, server crashes, file
		// has wrong-scope events at restart. Pre-check is cheap
		// and closes the window.
		for i, ev := range ps.Events {
			sp := &ev.SignedPrefix
			// Genesis events legitimately have nil scope; any
			// other event MUST embed the scope we're pulling.
			if sp.Scope != nil && *sp.Scope != sid {
				return fmt.Errorf("scope %s: server returned event[%d] for scope %s (chain swap, pre-write)",
					sid, i, *sp.Scope)
			}
		}
		// Wave E: chain.AppendTx replaces the previous manual
		// preSize+rollbackTruncate dance. Three failure paths
		// (AppendRaw mid-batch, replay-rejection, scope-swap
		// detection) used to each call `_ = os.Truncate(...)`
		// with the silent-drop hazard codex flagged in three
		// review rounds (sync.go:319/355/366/382). The tx's
		// `defer Cleanup()` makes rollback uniform; a future
		// failure branch added between Append and Commit
		// automatically inherits the rollback without per-site
		// truncate boilerplate.
		tx, err := chain.BeginAppend(path)
		if err != nil {
			return fmt.Errorf("scope %s: BeginAppend: %w", sid, err)
		}
		appendErr := func() error {
			for _, ev := range ps.Events {
				cb, merr := proto.Marshal(&ev)
				if merr != nil {
					return merr
				}
				if aerr := tx.AppendRaw(cb); aerr != nil {
					return aerr
				}
			}
			return nil
		}()
		if appendErr != nil {
			if cerr := tx.Cleanup(); cerr != nil {
				return fmt.Errorf("%w (cleanup also failed: %v)", appendErr, cerr)
			}
			return fmt.Errorf("scope %s: AppendRaw failed mid-batch (rolled back): %w", sid, appendErr)
		}
		st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil {
			// Replay rejection: divergence with the server. Roll
			// back the just-appended events so reconcile starts
			// from a clean pre-batch state.
			if cerr := tx.Cleanup(); cerr != nil {
				return cerr
			}
			if rerr := s.reconcileAndRepush(ctx, wcc, serverURL, sid, 3); rerr != nil {
				return fmt.Errorf("sync: replay %s rejected; reconcile failed: %w", sid, rerr)
			}
			dirty = true
			continue
		}
		if st == nil {
			// No state after replay (empty chain). Commit to
			// finalise the tx so a subsequent defer/explicit
			// Cleanup is a no-op; we don't want the truncate.
			if cerr := tx.Commit(); cerr != nil {
				return cerr
			}
			continue
		}
		// SECURITY (codex audit 🔴 sync.go:328): the replayed
		// state's ScopeID MUST match the chain we asked about.
		// Without this, a server returning a (signature-valid)
		// chain for a different scope would land under our
		// requested scope's vault entry.
		if st.ScopeID.String() != sid {
			if cerr := tx.Cleanup(); cerr != nil {
				return cerr
			}
			return fmt.Errorf("scope %s: server returned chain for scope %s (chain swap)", sid, st.ScopeID)
		}
		// All checks passed — finalise the appended events.
		if cerr := tx.Commit(); cerr != nil {
			return cerr
		}
		// We were removed from this scope: drop locally (STORAGE.md §5.3).
		if st.Left {
			_ = os.Remove(path)
			delete(s.Body.Scopes, sid)
			fmt.Fprintf(os.Stderr, "  ↳ removed from scope %s\n", scopeName(s, sid))
			dirty = true
			continue
		}
		sd.ChainTip = proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash}
		// SECURITY (subagent regression hunt 🔴 sync.go:394):
		// merge ALL OEK versions from the replayed state, not
		// just the current. Previously only `st.OEKs[CurrentOEKVer]`
		// was upserted, so historic versions in `st.OEKs` (still
		// needed to decrypt pre-rotation secrets in pending-event
		// reconcile) were never persisted to the vault. The next
		// `savePendingLocalEvents` would error with "missing OEK
		// v%d" — silently losing local-only secrets authored
		// under an older era.
		for v, k := range st.OEKs {
			sd.OEKs = upsertOEK(sd.OEKs, v, k)
		}
		// Refresh shared label from _meta if present.
		if l := metaLabelFromIndex(st.SecretIndex); l != "" {
			sd.Label = l
		}
		// Persist the verified STH as the new anchor. Wave D: the
		// type-state ensures we can only encode the STH that
		// VerifyAndCrossCheck just returned — no risk of
		// re-extracting an unverified copy from ps.
		if verifiedSTH != nil {
			encoded, err := EncodeSTH(*verifiedSTH)
			if err != nil {
				return fmt.Errorf("encode LastSTH for scope %s: %w", sid, err)
			}
			sd.SetLastSTHFor(serverKey, encoded)
		}
		s.Body.Scopes[sid] = sd
		dirty = true
	}
	if dirty {
		if err := s.ReSeal(); err != nil {
			return err
		}
	}
	// Auto-discover: server reported memberships in scopes we don't track
	// locally yet. For each unknown scope_id we issue a second pull from
	// cursor=0 and replay; replay extracts our OEK from the admit event's
	// key_delivery via agent.OpenSeal (PROTOCOL.md §4.5 / STORAGE.md §6.1).
	if discoverMemberships {
		if err := s.processMembershipPages(
			ctx,
			wcc,
			serverURL,
			membershipAfter,
			sr.Memberships,
			sr.MembershipsNextAfter,
			budget,
		); err != nil {
			return err
		}
	}
	// Summarise push results, and advance per-scope PushFloor on
	// accepted-or-dup'd events.
	//
	// Why dup? Because dup means "server already has this event_id".
	// Mathematically the seq has been pushed (by us, in some earlier round
	// whose vault flush failed, or by another device). Either way, future
	// syncs needn't repush; advancing the floor is safe and saves traffic.
	//
	// Floor advances monotonically: we never roll backwards even if the
	// server returns a stale-looking seq from an old retry.
	//
	// SECURITY (codex audit 🔴 sync.go:447): track the highest STH
	// tree_size we've persisted PER SCOPE in this round. Without
	// this, push results returned in non-monotone order could
	// overwrite the latest LastSTH with an older one (the verify
	// against PRE-SYNC priorSTH passes for both, but the persisted
	// anchor must always be the highest tree_size seen).
	pushed, dups, failed := 0, 0, 0
	refusedReasons := map[string]int{} // reason → count, summarized once (no per-push spam)
	floorDirty := false
	maxSizePersisted := map[string]uint64{} // scope_id → max sth.head.tree_size
	for _, p := range sr.Push {
		if _, ok := pullReconciled[p.ScopeID]; ok {
			// The full reconcile ran after this response was received and
			// therefore already incorporated any event this stale push
			// result accepted. Do not verify or retry the old result again.
			continue
		}
		switch {
		case p.Accepted:
			pushed++
		case p.Reason == "dup":
			dups++
		default:
			failed++
			refusedReasons[p.Reason]++ // summarized after the loop, not per-push
			continue
		}
		if p.ScopeID == "" {
			continue
		}
		sd, ok := s.Body.Scopes[p.ScopeID]
		if !ok {
			continue
		}
		// Translog verification per accepted/dup result. STH +
		// InclusionProof are MANDATORY on accepted/dup per
		// TRANSLOG.md §5.4 — missing them is a server protocol
		// violation; refuse to advance.
		if p.STH == nil || p.InclusionProof == nil {
			return fmt.Errorf("scope %s push: %w (server returned %s without STH/inclusion proof)",
				p.ScopeID, ErrSTHMissing, p.Reason)
		}
		// SECURITY (codex audit 🔴 sync.go:430): the push verify
		// must prove the SUBMITTED event's leaf, not whatever
		// leaf the server claims at p.Seq. Compute the expected
		// leaf hash from the LOCAL chain entry that produced
		// this push — if the server proved a different leaf at
		// the same seq (e.g. a re-org we haven't replayed yet),
		// VerifyAndCrossCheck will reject. leafHashAtSeq reads
		// from the local chain file by seq.
		leafHash, lerr := s.leafHashAtSeq(p.ScopeID, p.Seq)
		if lerr != nil {
			return fmt.Errorf("scope %s push verify: %w", p.ScopeID, lerr)
		}
		// Use the PRE-SYNC LastSTH for the consistency anchor — the
		// request's last_sth_size was based on the pre-sync state.
		// The pull-side update of sd.LastSTH happened in this same
		// round and is irrelevant to the push proof.
		priorSTH := preSyncLastSTH[p.ScopeID]
		expectedChainID := "scope:" + p.ScopeID
		verifiedPushSTH, err := VerifyAndCrossCheck(ctx, wcc, serverURL, pinnedPub, expectedChainID, p.STH, priorSTH, []translog.InclusionProof{*p.InclusionProof}, []uint64{p.Seq}, [][]byte{leafHash}, p.ConsistencyProof)
		if err != nil {
			return fmt.Errorf("scope %s push verify: %w", p.ScopeID, err)
		}
		if verifiedPushSTH == nil {
			// p.STH was non-nil to reach the verify call (the
			// guard at line ~470 mandates STH+InclusionProof on
			// accepted/dup), so a nil verified value would mean
			// VerifyAndCrossCheck inferred "no STH" — protocol
			// violation, refuse to advance.
			return fmt.Errorf("scope %s push verify: verified STH unexpectedly nil", p.ScopeID)
		}
		encoded, err := EncodeSTH(*verifiedPushSTH)
		if err != nil {
			return fmt.Errorf("encode LastSTH: %w", err)
		}
		// Track per-scope max so post-loop persistence picks the
		// highest STH (codex audit 🔴 sync.go:447). Only update
		// when strictly greater.
		if p.STH.Head.TreeSize >= maxSizePersisted[p.ScopeID] {
			sd.SetLastSTHFor(serverKey, encoded)
			maxSizePersisted[p.ScopeID] = p.STH.Head.TreeSize
		}
		floorDirty = true
		next := p.Seq + 1
		if next > sd.PushFloorFor(serverKey) {
			sd.SetPushFloorFor(serverKey, next)
			floorDirty = true
		}
		s.Body.Scopes[p.ScopeID] = sd
	}
	// Persist PushFloor advances NOW (before any reconcile-on-failure path
	// that may rewrite the chain and update its own ChainTip/PushFloor).
	// If ReSeal fails here, every floor change in this round is lost; the
	// next sync re-pushes the same suffix and the server idempotent-dedups.
	// That's the no-data-loss invariant: floor never advances on disk
	// without an authoritative server confirmation having already landed.
	if floorDirty {
		if err := s.ReSeal(); err != nil {
			return err
		}
	}
	// Auto-retry: collect scopes whose pushes hit divergence/stale_oek and
	// run a reconcile-and-replay loop. PROTOCOL.md §7.1: up to 3 retries.
	if failed > 0 {
		// One summary line, not one per refused event: a diverged scope
		// can refuse hundreds of pushes and must never spam the terminal.
		fmt.Fprintf(os.Stderr, "  %d push(es) refused (%s); reconciling…\n", failed, summarizeReasons(refusedReasons))
		conflictScopes := map[string]struct{}{}
		for _, p := range sr.Push {
			if p.Accepted {
				continue
			}
			if p.Reason != "divergence" && p.Reason != "stale_oek_version" {
				continue
			}
			if p.ScopeID != "" {
				conflictScopes[p.ScopeID] = struct{}{}
			}
		}
		retried, retryFailed := 0, 0
		for sid := range conflictScopes {
			if err := s.reconcileAndRepush(ctx, wcc, serverURL, sid, 3); err != nil {
				fmt.Fprintf(os.Stderr, "  reconcile %s: %v\n", shortScopeID(sid), err)
				retryFailed++
				continue
			}
			retried++
		}
		if retryFailed > 0 {
			return fmt.Errorf("sync: %d scope(s) failed reconcile after retry; %d push(es) initially refused", retryFailed, failed)
		}
		if retried > 0 {
			if morePushes {
				return errSyncMorePushes
			}
			fmt.Fprintf(os.Stderr, "✓ sync ok (pushed=%d dup=%d reconciled=%d)\n", pushed, dups, retried)
			return nil
		}
		return fmt.Errorf("sync: %d push(es) refused (pushed=%d dup=%d)", failed, pushed, dups)
	}
	if morePushes {
		return errSyncMorePushes
	}
	fmt.Fprintf(os.Stderr, "✓ sync ok (pushed=%d dup=%d)\n", pushed, dups)
	return nil
}

type membershipResult struct {
	ScopeID    string `cbor:"scope_id"`
	OEKVersion uint64 `cbor:"oek_version"`
}

func (s *Session) processMembershipPages(
	ctx context.Context,
	wcc *WitnessCheckClient,
	serverURL canon.URL,
	requestAfter string,
	memberships []membershipResult,
	nextAfter string,
	budget *syncRunBudget,
) error {
	for {
		if err := validateMembershipPage(requestAfter, memberships, nextAfter); err != nil {
			return err
		}
		for _, m := range memberships {
			if _, known := s.Body.Scopes[m.ScopeID]; known {
				continue
			}
			if err := s.discoverScope(ctx, wcc, serverURL, m.ScopeID); err != nil {
				fmt.Fprintf(os.Stderr, "  skip discover %s: %v\n", m.ScopeID, err)
			}
		}
		budget.membershipPages--
		if nextAfter == "" || budget.membershipPages == 0 {
			return s.persistMembershipCursor(serverURL.String(), nextAfter)
		}
		body, err := buildMembershipDiscoveryRequest(nextAfter)
		if err != nil {
			return err
		}
		resp, err := s.signedPOST(ctx, serverURL.JoinPath("/v1/sync"), body)
		if err != nil {
			return err
		}
		rb, readErr := httpguard.ReadBody(resp.Body, maxSyncResponseBytes)
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("sync membership discovery: %s: %s", resp.Status, rb)
		}
		var page struct {
			Memberships          []membershipResult `cbor:"memberships"`
			MembershipsNextAfter string             `cbor:"memberships_next_after,omitempty"`
		}
		if err := proto.Unmarshal(rb, &page); err != nil {
			return fmt.Errorf("sync membership discovery: decode response: %w", err)
		}
		requestAfter = nextAfter
		memberships = page.Memberships
		nextAfter = page.MembershipsNextAfter
	}
}

func validateMembershipPage(after string, memberships []membershipResult, nextAfter string) error {
	if len(memberships) > membershipPageSize {
		return fmt.Errorf(
			"sync membership discovery: server returned %d memberships, limit is %d",
			len(memberships),
			membershipPageSize,
		)
	}
	seen := make(map[string]struct{}, len(memberships))
	for _, membership := range memberships {
		if _, err := proto.ParseScopeID(membership.ScopeID); err != nil {
			return fmt.Errorf("sync membership discovery: invalid scope_id: %w", err)
		}
		if _, ok := seen[membership.ScopeID]; ok {
			return fmt.Errorf("sync membership discovery: duplicate scope_id %q", membership.ScopeID)
		}
		seen[membership.ScopeID] = struct{}{}
	}
	if nextAfter != "" && nextAfter <= after {
		return errors.New("sync membership discovery: server pagination did not advance")
	}
	if nextAfter != "" {
		cursorScopeID, err := membershipCursorScopeID(nextAfter)
		if err != nil {
			return fmt.Errorf("sync membership discovery: invalid next cursor: %w", err)
		}
		if len(memberships) == 0 || memberships[len(memberships)-1].ScopeID != cursorScopeID {
			return errors.New("sync membership discovery: next cursor does not match page tail")
		}
	}
	return nil
}

func membershipCursorScopeID(cursor string) (string, error) {
	const prefix = "scope:"
	if !strings.HasPrefix(cursor, prefix) {
		return "", errors.New("cursor must start with scope")
	}
	scopeID := strings.TrimPrefix(cursor, prefix)
	if _, err := proto.ParseScopeID(scopeID); err != nil {
		return "", err
	}
	if cursor != prefix+scopeID {
		return "", errors.New("cursor is not canonical")
	}
	return scopeID, nil
}

func (s *Session) persistMembershipCursor(serverKey, after string) error {
	pinned, ok := s.Body.PinnedServers[serverKey]
	if !ok {
		return errors.New("sync membership discovery: server pin missing")
	}
	if pinned.MembershipAfter == after {
		return nil
	}
	pinned.MembershipAfter = after
	s.Body.PinnedServers[serverKey] = pinned
	return s.ReSeal()
}

// summarizeReasons renders a push-refusal histogram as a single compact
// string like "divergence×42, stale_oek_version×3" (reasons sorted), so a
// diverged scope produces one summary line instead of hundreds.
func summarizeReasons(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s×%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// syncHTTPClient is the shared client for every fd0-server round-trip
// (sync POST + translog pulls). It bounds the failure modes that made a
// stalled server hang `fd0 sync` indefinitely: a dead connection
// (DialContext), a stuck TLS handshake, and — the common one — a server
// that accepts the connection but never sends response headers
// (ResponseHeaderTimeout). The overall Timeout is a generous backstop so
// a legitimately large pull that keeps making progress is not killed.
var syncHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	},
	CheckRedirect: httpguard.RejectRedirect,
	Timeout:       5 * time.Minute,
}

const maxSyncResponseBytes = 64 << 20

// signedPOST performs an authenticated POST against the fd0-server.
//
// SECURITY (signature subagent audit 🔴): the signed input includes
// the destination server's pinned pubkey, binding the signature to
// a specific server. Without this, a malicious server-A operator
// could replay the signed request to server-B (where the user is
// also registered) and have it accepted.
func (s *Session) signedPOST(ctx context.Context, endpoint string, body []byte) (*http.Response, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	// Look up the server's pinned pub from the canonical URL (not
	// `endpoint` which carries the path). PinnedServerPub returns
	// an error if the server isn't pinned yet, but EnsurePinnedServer
	// is always called before any signedPOST.
	canonical, err := canon.ParseURL((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
	if err != nil {
		return nil, err
	}
	serverPub, err := s.PinnedServerPub(canonical)
	if err != nil {
		return nil, fmt.Errorf("signedPOST: %w", err)
	}
	qmap := map[string]string{}
	for k, vs := range u.Query() {
		qmap[k] = vs[0]
	}

	// Bounded retry on 429. The reconcile path pushes events one-by-one,
	// which can trip a hosted replica's per-identity rate limit; without
	// honouring Retry-After the sync never converges. Each attempt
	// re-signs (fresh nonce + ts) because the server rejects nonce reuse
	// as replay. Bounded by attempts AND a per-wait cap so a hostile or
	// misconfigured Retry-After can't hang the client.
	const maxAttempts = 4
	const maxWait = 30 * time.Second
	for attempt := 0; ; attempt++ {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ts := uint64(time.Now().Unix())
		si, err := proto.HTTPSignedInput("POST", u.Path, qmap, ts, nonce, body, []byte(serverPub))
		if err != nil {
			return nil, err
		}
		sig, err := s.Agent.Sign(si)
		if err != nil {
			return nil, err
		}
		r, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/cbor")
		r.Header.Set("Authorization",
			"fd0-sig v1 pk="+base64.StdEncoding.EncodeToString(s.UserSuperPub)+
				", nonce="+base64.StdEncoding.EncodeToString(nonce)+
				", ts="+strconv.FormatUint(ts, 10)+
				", sig="+base64.StdEncoding.EncodeToString(sig))
		resp, err := syncHTTPClient.Do(r)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests || attempt >= maxAttempts-1 {
			return resp, nil
		}
		// Rate-limited and attempts remain: close the body, wait
		// out Retry-After (server sends integer seconds; default 1s,
		// capped), then re-sign and retry.
		wait := retryAfterDelay(resp.Header.Get("Retry-After"), maxWait)
		resp.Body.Close()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// retryAfterDelay parses a Retry-After header value (integer seconds,
// per RFC 7231 / our server) into a bounded wait. Empty / unparseable
// → 1s; negative → 1s; clamped to max.
func retryAfterDelay(header string, max time.Duration) time.Duration {
	d := time.Second
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs > 0 {
		d = time.Duration(secs) * time.Second
	}
	if d > max {
		d = max
	}
	return d
}

// _ silences unused-import lint when the only HTTP client use is Default.
var _ = agent.OpStatus
