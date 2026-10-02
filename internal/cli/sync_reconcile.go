package cli

// Divergence-recovery flow extracted from sync.go in Wave B.
//
// The reconcile path is the highest-stakes part of /sync: it
// rewrites the local chain from the server's authoritative copy,
// captures local-only writes as `pendingEvent`s, and rebuilds them
// in chain order on the new tip. Bugs here lose user data — past
// audits flagged five separate "silent local-write loss" classes
// in this flow alone. Concentrating it in one file (with the same
// helpers from sync_internal.go) shrinks the per-LOC surface for
// the next reviewer.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/httpguard"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

var errScopePullDenied = errors.New("sync: scope pull denied")

// repairNonContiguousScopes upgrades local files produced by the retired v1
// compactor. Reconcile preserves local-only writes, while fullPullScope
// authenticates the replacement through the pinned server and transparency
// log before it becomes visible.
func (s *Session) repairNonContiguousScopes(ctx context.Context, wcc *WitnessCheckClient, server canon.URL) error {
	scopeIDs := make([]string, 0, len(s.Body.Scopes))
	for scopeID := range s.Body.Scopes {
		scopeIDs = append(scopeIDs, scopeID)
	}
	sort.Strings(scopeIDs)
	for _, scopeID := range scopeIDs {
		path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
		continuityErr := chain.ValidateScopeContinuity(path)
		if continuityErr != nil && !errors.Is(continuityErr, chain.ErrScopeHistoryNonContiguous) {
			return fmt.Errorf("sync repair %s: inspect local history: %w", shortScopeID(scopeID), continuityErr)
		}
		localTip, hasLocalTip, err := chain.ScopeFileTip(path)
		if err != nil {
			return fmt.Errorf("sync repair %s: inspect local tip: %w", shortScopeID(scopeID), err)
		}
		vaultTip := s.Body.Scopes[scopeID].ChainTip
		tipMismatch := !hasLocalTip ||
			localTip.Seq != vaultTip.Seq ||
			!bytes.Equal(localTip.Hash, vaultTip.Hash)
		if continuityErr == nil && !tipMismatch {
			continue
		}
		fmt.Fprintf(os.Stderr, "  ↳ repairing legacy scope history %s from verified server copy\n", shortScopeID(scopeID))
		if err := s.reconcileAndRepush(ctx, wcc, server, scopeID, 3); err != nil {
			if errors.Is(err, errScopePullDenied) {
				// The normal sync response removes scopes that no longer
				// authorize this member.
				continue
			}
			return fmt.Errorf("sync repair %s: %w", shortScopeID(scopeID), err)
		}
		if _, stillPresent := s.Body.Scopes[scopeID]; !stillPresent {
			continue
		}
		if err := chain.ValidateScopeContinuity(path); err != nil {
			return fmt.Errorf("sync repair %s produced invalid history: %w", shortScopeID(scopeID), err)
		}
	}
	return nil
}

// reconcileAndRepush handles a divergence-on-push by:
//  1. Fetching the full server chain (cursor=0, inclusive) for scope.
//  2. Saving every local-only event authored by us as a pendingEvent —
//     either a secret.set (decrypted body cached) or a member.change
//     (op + target captured for three-way merge).
//  3. Overwriting the local chain with the server's authoritative copy.
//  4. Replaying to derive the post-merge running state (member set, OEK).
//  5. Rebuilding each pending event in original chain order on top of
//     the new tip:
//     - secret.set → re-encrypt under the post-replay OEK and push.
//     - member.change → semantic rebase via
//     chain.RebaseMemberChangeMeaningful; drop on no-op, otherwise
//     emit a fresh member.change (rotates OEK) and push.
//
// Retries the whole loop up to maxRetries before returning an error.
// Each retry restarts from a fresh server pull, so a rebuilt event that
// races a third party (yet another concurrent push) gets another
// chance.
func (s *Session) reconcileAndRepush(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string, maxRetries int) (err error) {
	// DATA SAFETY (prime directive: never lose a local-authored event).
	//
	// Reconcile rewrites the local chain to the server's authoritative
	// copy and holds the user's local-only writes only in an in-memory
	// `pending` slice while it re-pushes them one at a time. If anything
	// fails before they are ALL durably re-appended and accepted —
	// a terminal push error, retry exhaustion, a replay error — those
	// writes would vanish from disk (the chain file now holds the
	// server copy; the only other copy was the in-memory slice).
	//
	// So the whole reconcile is transactional: snapshot the original
	// chain file + this scope's vault state ONCE up front, and on ANY
	// error restore both. A failed reconcile is then a no-op on local
	// disk — every local event stays exactly as the user authored it,
	// ready for the next sync (the server dedups anything that did land
	// by content-derived event_id). The chain file is restored FIRST
	// because it is the source of truth for events; the vault chain_tip
	// is re-derived from it on the next replay even if the vault restore
	// or its ReSeal hiccups.
	path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
	origChain, origChainErr := os.ReadFile(path)
	// Deep-clone the scope snapshot: reconcile mutates OEKs / PerServer /
	// byte slices in place, so a shallow `x := s.Body.Scopes[scopeID]`
	// would alias them and the rollback would restore already-mutated
	// nested state. Clone() gives an independent snapshot to restore.
	origScopeRaw, hadScope := s.Body.Scopes[scopeID]
	origScope := origScopeRaw.Clone()
	defer func() {
		if err == nil {
			return // success: keep the converged state
		}
		if origChainErr == nil {
			_ = os.WriteFile(path, origChain, 0o600)
		}
		if hadScope {
			s.Body.Scopes[scopeID] = origScope
		} else {
			delete(s.Body.Scopes, scopeID)
		}
		_ = s.ReSeal()
	}()

	for attempt := 0; attempt < maxRetries; attempt++ {
		serverEvents, finalSTH, err := s.fullPullScope(ctx, wcc, server, scopeID)
		if err != nil {
			return err
		}
		// Save local-only pending events BEFORE we rewrite the chain.
		pending, err := s.savePendingLocalEvents(scopeID, serverEvents)
		if err != nil {
			return err
		}
		if err := s.replaceLocalChain(scopeID, serverEvents); err != nil {
			return err
		}
		if err := s.applyReplayedScope(scopeID, server.String()); err != nil {
			// The outer transaction restores the original chain + vault.
			return fmt.Errorf("reconcile replay failed: %w", err)
		}
		// Persist the verified-on-pull final STH as the new anchor.
		// fullPullScope already verified its signature + per-page
		// inclusion proofs; we just have to store it. Skip if the
		// scope was dropped (st.Left handled inside applyReplayedScope).
		if sd, still := s.Body.Scopes[scopeID]; still && finalSTH != nil {
			encoded, eerr := EncodeSTH(*finalSTH)
			if eerr != nil {
				return fmt.Errorf("encode reconcile LastSTH: %w", eerr)
			}
			sd.SetLastSTHFor(server.String(), encoded)
			s.Body.Scopes[scopeID] = sd
			if rerr := s.ReSeal(); rerr != nil {
				return fmt.Errorf("persist reconcile LastSTH: %w", rerr)
			}
		}
		// If we were removed, pending sets are moot.
		if _, still := s.Body.Scopes[scopeID]; !still {
			return nil
		}
		// Rebuild pending events on the new tip, in their original
		// chain order. member.changes rotate the OEK and feed the
		// running state for any subsequent secret.sets in the same
		// rebuild pass; rebuildAndPushSet picks up the new OEK via
		// replayAndCheckScope before encrypting.
		//
		// If any single rebuild hits a fresh divergence we BREAK
		// immediately and let the outer loop restart from
		// fullPullScope+replaceLocalChain. Continuing past a `!ok`
		// would build subsequent events on top of a locally-appended
		// but server-rejected predecessor, guaranteeing a cascade of
		// further divergences and inflating stale-OEK exposure.
		diverged := false
		for _, p := range pending {
			var (
				ok   bool
				rerr error
			)
			switch p.kind {
			case proto.KindSecretSet:
				ok, rerr = s.rebuildAndPushSet(ctx, wcc, server, scopeID, p)
			case proto.KindMemberChange:
				ok, rerr = s.rebuildAndPushMemberChange(ctx, wcc, server, scopeID, p)
			default:
				return fmt.Errorf("reconcile: unknown pending kind %q", p.kind)
			}
			// SECURITY (codex audit 🔴 sync.go:1241): pushRebuilt
			// returns (true, err) when the server ACCEPTED the
			// push but a follow-up ReSeal failed. Treating that
			// as terminal aborts the retry loop AND the caller's
			// outer sync, even though everything actually
			// succeeded modulo a non-fatal floor-staleness. Honour
			// `ok` over `err`: if the push landed (ok=true),
			// continue draining the rebuild queue; surface the
			// reseal error only as a warning.
			if rerr != nil && !ok {
				return rerr
			}
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "  warn: %s rebuilt-push: post-success reseal: %v\n", shortScopeID(scopeID), rerr)
			}
			if !ok {
				diverged = true
				break
			}
		}
		if !diverged {
			return nil
		}
		// Diverged — outer loop will refresh server state and retry.
	}
	// Retry exhausted. The outer transaction's defer restores the
	// original chain file + vault scope state, so the user's local-only
	// events are preserved on disk exactly as authored — nothing lost,
	// nothing to re-issue by hand. The next sync will retry from a fresh
	// server pull (anything that did land is deduped by the server).
	return fmt.Errorf("scope %s: still diverging after %d retries — local state left untouched (your events are safe on disk). Re-run `fd0 sync` later, or pause concurrent writers to the scope and retry",
		shortScopeID(scopeID), maxRetries)
}

// fullPullScope pages through the entire scope chain from seq=0. The server
// caps each response at 1000 events (API.md §2.4), so we loop until the
// returned tip equals the last event's hash.
//
// Translog: each page's STH is verified against the pinned server pub
// + inclusion proofs against that page's events. The final STH (= the
// one covering all returned events) is returned to the caller for
// persistence as the new LastSTH after the reconcile commits.
func (s *Session) fullPullScope(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string) ([]proto.ScopeEvent, *VerifiedSTH, error) {
	pinnedPub, err := s.PinnedServerPub(server)
	if err != nil {
		return nil, nil, err
	}
	const pageSize = 1000
	var all []proto.ScopeEvent
	var finalSTH *VerifiedSTH
	cursorSeq := uint64(0)
	cursorHash := []byte(nil) // sentinel: include seq=0 (server fresh-discovery)
	for round := 0; round < 64; round++ {
		body, err := buildSyncRequestBody(
			map[string]pullCursor{scopeID: {Seq: cursorSeq, Hash: cursorHash}},
			nil, false, "", pageSize,
		)
		if err != nil {
			return nil, nil, err
		}
		resp, err := s.signedPOST(ctx, server.JoinPath("/v1/sync"), body)
		if err != nil {
			return nil, nil, err
		}
		rb, err := httpguard.ReadBody(resp.Body, maxSyncResponseBytes)
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("full pull %s: %s", scopeID, resp.Status)
		}
		var sr struct {
			Pull map[string]struct {
				Tip struct {
					Seq  uint64 `cbor:"seq"`
					Hash []byte `cbor:"hash"`
				} `cbor:"tip"`
				Events           []proto.ScopeEvent         `cbor:"events"`
				Denied           bool                       `cbor:"denied,omitempty"`
				STH              *translog.STH              `cbor:"sth,omitempty"`
				InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
				ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
			} `cbor:"pull"`
		}
		if err := proto.Unmarshal(rb, &sr); err != nil {
			return nil, nil, err
		}
		ps, ok := sr.Pull[scopeID]
		if !ok {
			return nil, nil, errors.New("server returned no pull entry for scope")
		}
		if ps.Denied {
			return nil, nil, errScopePullDenied
		}
		cursor := pullCursor{Seq: cursorSeq, Hash: cursorHash}
		if err := validateScopePullPage(scopeID, cursor, ps.Tip.Seq, ps.Tip.Hash, ps.Events); err != nil {
			return nil, nil, fmt.Errorf("full pull %s: invalid page: %w", scopeID, err)
		}
		// Per-page translog verify. priorSTH is nil because we
		// don't carry an anchor across pages — the STH must verify
		// independently per page (and the final page's STH is what
		// we persist).
		leafHashes := make([][]byte, 0, len(ps.Events))
		leafIndices := make([]uint64, 0, len(ps.Events))
		for i := range ps.Events {
			prefix, perr := ps.Events[i].PrevHashInput()
			if perr != nil {
				return nil, nil, fmt.Errorf("translog: leaf hash on full pull: %w", perr)
			}
			leafHashes = append(leafHashes, translog.LeafHashOfPrevInput(prefix))
			leafIndices = append(leafIndices, ps.Events[i].SignedPrefix.Seq)
		}
		expectedChainID := "scope:" + scopeID
		verifiedPage, err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, ps.STH, nil, ps.InclusionProofs, leafIndices, leafHashes, ps.ConsistencyProof)
		if err != nil {
			return nil, nil, fmt.Errorf("full pull %s: %w", scopeID, err)
		}
		if verifiedPage != nil {
			finalSTH = verifiedPage
		}

		all = append(all, ps.Events...)
		if len(ps.Events) == 0 || ps.Events[len(ps.Events)-1].SignedPrefix.Seq >= ps.Tip.Seq {
			// We've reached the server's reported tip; verify last event's
			// hash matches it before trusting the page.
			if len(all) > 0 {
				lastPrefix, _ := all[len(all)-1].PrevHashInput()
				lastHash := proto.HashPrefix(lastPrefix)
				if !bytes.Equal(lastHash[:], ps.Tip.Hash) {
					return nil, nil, fmt.Errorf("server tip hash mismatch")
				}
			}
			return all, finalSTH, nil
		}
		// Advance cursor and loop.
		cursorSeq = ps.Events[len(ps.Events)-1].SignedPrefix.Seq
		lastPrefix, _ := ps.Events[len(ps.Events)-1].PrevHashInput()
		h := proto.HashPrefix(lastPrefix)
		cursorHash = h[:]
	}
	return nil, nil, fmt.Errorf("full pull %s: page limit exceeded", scopeID)
}

// pendingEvent is one local-only event we need to rebuild on the new server
// tip after a divergence. Discriminated by `kind`:
//
//   - kind == KindSecretSet : `body` carries the decrypted SecretBody so the
//     rebuild loop can re-encrypt under the post-reconcile OEK.
//   - kind == KindMemberChange : `op` (add|remove) and `target` carry the
//     intent so the rebuild loop can re-emit a fresh member.change against
//     the post-replay member set (three-way merge — STORAGE.md §5.3).
type pendingEvent struct {
	kind   string
	body   *proto.SecretBody // KindSecretSet
	op     string            // KindMemberChange
	target []byte            // KindMemberChange
	role   string            // KindMemberChange add or role; "" = admin
}

// savePendingLocalEvents identifies events that exist in our local chain
// but not on the server (the events we authored after the divergence
// point) and packages them for the rebuild loop. Two recoverable kinds:
//
//   - secret.set: decrypt body under the OEK era it was sealed with so we
//     can re-encrypt against the post-reconcile OEK.
//   - member.change: capture op + target so we can re-emit a fresh
//     member.change against the post-replay running state (three-way
//     merge). chain.RebaseMemberChangeMeaningful decides at rebuild time
//     whether the rebased event is still meaningful.
//
// The set-diff itself is delegated to chain.LocalOnlyEvents (pure, unit
// tested in chain).
//
// DATA SAFETY (multi-server): an event authored by ANOTHER member cannot
// be rebuilt/re-pushed by us — we can't forge their signature. Against a
// single authoritative server this set is always empty: any foreign
// event we hold came FROM that server, so it is never local-only. With
// multiple replicas, though, a foreign-authored event we legitimately
// pulled from an up-to-date replica B can be local-only relative to a
// replica A that is still behind. Reconcile would then overwrite the
// local chain with A's stale copy (replaceLocalChain) and silently DROP
// that event — the cursor advances past its seq, so the next pull won't
// re-fetch it. We refuse the reconcile instead: the transactional caller
// restores the chain untouched, the event survives on replica B, and A
// converges once the authoring member re-pushes there (or peer
// replication lands). Returning an error here is strictly safer than the
// old behaviour, which dropped the foreign event.
func (s *Session) savePendingLocalEvents(scopeID string, serverEvents []proto.ScopeEvent) ([]pendingEvent, error) {
	localPtrs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)))
	if err != nil {
		return nil, err
	}
	// chain.ReadScopeEvents returns pointers (decoder ergonomics); the
	// server-response side is values. Materialise both as values so the
	// pure helper has a uniform signature.
	localEvents := make([]proto.ScopeEvent, len(localPtrs))
	for i, p := range localPtrs {
		localEvents[i] = *p
	}
	sd := s.Body.Scopes[scopeID]
	var pending []pendingEvent
	foreignLocalOnly := 0
	for _, ev := range chain.LocalOnlyEvents(localEvents, serverEvents) {
		if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
			// See the function doc: this server lacks a foreign-authored
			// event we hold. Don't drop it — count and refuse below.
			foreignLocalOnly++
			continue
		}
		switch ev.SignedPrefix.Kind {
		case proto.KindSecretSet:
			var oek []byte
			for _, e := range sd.OEKs {
				if e.Version == ev.SignedPrefix.OEKVersion {
					oek = e.Key
					break
				}
			}
			if oek == nil {
				return nil, fmt.Errorf("missing OEK v%d for divergent event", ev.SignedPrefix.OEKVersion)
			}
			body, err := decryptSecretBody(&ev, oek)
			if err != nil {
				return nil, err
			}
			pending = append(pending, pendingEvent{kind: proto.KindSecretSet, body: body})
		case proto.KindMemberChange:
			pending = append(pending, pendingEvent{
				kind:   proto.KindMemberChange,
				op:     ev.SignedPrefix.Payload.Op,
				target: append([]byte(nil), ev.SignedPrefix.Payload.Member...),
				role:   ev.SignedPrefix.Payload.Role,
			})
		default:
			return nil, fmt.Errorf("unexpected local-only event kind %q on scope %s", ev.SignedPrefix.Kind, shortScopeID(scopeID))
		}
	}
	if foreignLocalOnly > 0 {
		return nil, fmt.Errorf("reconcile %s: this server is behind on %d event(s) authored by other members; refusing to reconcile to avoid dropping them locally — they remain on the up-to-date replica and converge once those members sync here (or peer replication lands)", shortScopeID(scopeID), foreignLocalOnly)
	}
	return pending, nil
}

// replaceLocalChain rewrites the chain file with a fresh server-authoritative
// sequence. Atomic via chain.WriteAll's tmp+rename.
func (s *Session) replaceLocalChain(scopeID string, events []proto.ScopeEvent) error {
	path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
	bytesList := make([][]byte, 0, len(events))
	for _, ev := range events {
		b, err := proto.Marshal(&ev)
		if err != nil {
			return err
		}
		bytesList = append(bytesList, b)
	}
	return chain.WriteAll(path, bytesList)
}

// applyReplayedScope replays the (possibly rewritten) chain and updates vault
// (chain_tip, OEKs, label). Drops the scope on leave.
func (s *Session) applyReplayedScope(scopeID, serverKey string) error {
	path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("empty chain after reconcile")
	}
	if st.Left {
		_ = os.Remove(path)
		delete(s.Body.Scopes, scopeID)
		return s.ReSeal()
	}
	sd := s.Body.Scopes[scopeID]
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash}
	// SECURITY (subagent regression hunt 🔴): merge ALL OEK
	// versions, not just CurrentOEKVer. See sync.go:394 fix.
	for v, k := range st.OEKs {
		sd.OEKs = upsertOEK(sd.OEKs, v, k)
	}
	if l := metaLabelFromIndex(st.SecretIndex); l != "" {
		sd.Label = l
	}
	// After a reconcile, the local chain has been rewritten from the
	// server's authoritative copy. Every event up to and including st.TipSeq
	// is therefore guaranteed to already exist on the server; the next event
	// we'd push starts at st.TipSeq+1. Advance the floor so the immediately
	// following rebuilt secret.sets aren't accompanied by a costly replay
	// of the entire restored history on every subsequent sync.
	if next := st.TipSeq + 1; next > sd.PushFloorFor(serverKey) {
		sd.SetPushFloorFor(serverKey, next)
	}
	s.Body.Scopes[scopeID] = sd
	return s.ReSeal()
}

// rebuildAndPushSet appends a fresh secret.set built on the current tip and
// pushes it. Returns (false, nil) on a fresh divergence (caller retries).
func (s *Session) rebuildAndPushSet(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string, p pendingEvent) (bool, error) {
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return false, err
	}
	if role := st.Roles.RoleOf(s.UserSuperPub); role != proto.RoleAdmin && role != proto.RoleWriter {
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s value change dropped; your role is now %s\n", shortScopeID(scopeID), role)
		return true, nil
	}
	sd := s.Body.Scopes[scopeID]
	var curOEK proto.OEKEntry
	for _, e := range sd.OEKs {
		if e.Version == st.CurrentOEKVer {
			curOEK = e
			break
		}
	}
	if curOEK.Version == 0 {
		return false, fmt.Errorf("missing OEK v%d after reconcile", st.CurrentOEKVer)
	}
	// If the secret has a name and another member already wrote the same
	// name to a different id, prefer the existing id (last-writer-wins on
	// the same id). Otherwise keep the original id.
	if p.body.Record != nil {
		for id, cur := range st.SecretIndex {
			if cur.Record != nil && cur.Record.Name == p.body.Record.Name && id != p.body.ID {
				p.body.ID = id
				break
			}
		}
	}
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, proto.MustParseScopeID(scopeID),
		st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, p.body)
	if err != nil {
		return false, err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return false, err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	// Pre-push: do NOT advance PushFloor yet. The push below may still fail.
	// The append above is local-only; if the push fails the next sync will
	// retry it (PushFloor stays at <= sd.ChainTip.Seq+1, and the rebuilt
	// event's seq matches that, so it's still in scope).
	if err := s.ReSeal(); err != nil {
		return false, err
	}
	return s.pushRebuiltEvent(ctx, wcc, server, scopeID, ev)
}

// rebuildAndPushMemberChange rebases a divergent local-only member.change
// onto the post-replay running member set (three-way merge), pushes it,
// and updates the local OEK ring. Symmetric to rebuildAndPushSet but
// rotates the OEK and persists a fresh OEKEntry — same as a normal
// `scope add-member` / `remove-member` would.
//
// Returns:
//   - (true, nil)  on accept/dup, or when the rebase is a semantic no-op
//     (drop without pushing — see chain.RebaseMemberChangeMeaningful).
//   - (false, nil) on fresh divergence/stale_oek_version (caller retries).
//   - (false, err) on terminal failure.
func (s *Session) rebuildAndPushMemberChange(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string, p pendingEvent) (bool, error) {
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return false, err
	}
	if role := st.Roles.RoleOf(s.UserSuperPub); role != proto.RoleAdmin {
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s membership change dropped; your role is now %s\n", shortScopeID(scopeID), role)
		return true, nil
	}
	if err := checkRoleTransition(st, p.op, p.target, p.role); err != nil {
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s membership change dropped: %v\n", shortScopeID(scopeID), err)
		return true, nil
	}
	if p.op == proto.OpRole {
		return s.rebuildAndPushRoleChange(ctx, wcc, server, scopeID, st, p)
	}
	// Semantic rebase: drop if the running state already matches our intent.
	if !chain.RebaseMemberChangeMeaningful(st.MemberSet, p.op, p.target) {
		shortPub := base64.StdEncoding.EncodeToString(p.target)
		if len(shortPub) > 12 {
			shortPub = shortPub[:12]
		}
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s op=%s target=%s… now a no-op, dropped\n",
			shortScopeID(scopeID), p.op, shortPub)
		return true, nil
	}
	// Re-emit against the post-replay tip + member set. New OEK is rotated
	// inside BuildMemberChange and must be installed in the vault BEFORE
	// the push (so a successful push doesn't strand secrets unable to
	// decrypt against the just-promoted era).
	proj := projectionFromIndex(st.SecretIndex)
	ev, newOEK, err := chain.BuildMemberChangeWithRole(
		AgentSigner{Agent: s.Agent}, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, st.CurrentOEKVer,
		p.op, p.target, p.role, st.MemberSet, proj,
	)
	if err != nil {
		return false, err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return false, err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = upsertOEK(sd.OEKs, ev.SignedPrefix.OEKVersion, newOEK)
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return false, err
	}
	return s.pushRebuiltEvent(ctx, wcc, server, scopeID, ev)
}

// pushRebuiltEvent posts a single locally-appended event to the server
// and reconciles the response. Shared between rebuildAndPushSet and
// rebuildAndPushMemberChange — both want the same accept/dup/divergence
// disposition and the same PushFloor advance.
//
// Contract:
//   - (true, nil)  : accepted or de-duplicated; PushFloor advanced.
//   - (false, nil) : divergence / stale_oek_version → caller loops the
//     reconcile (server-tip moved again).
//   - (false, err) : transport error or terminal "refused" reason.
func (s *Session) pushRebuiltEvent(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string, ev *proto.ScopeEvent) (bool, error) {
	// Snapshot pre-push LastSTH for the consistency anchor: the
	// request's last_sth_size is read here, server's consistency
	// proof is relative to it. Reading after a successful push would
	// see the just-updated LastSTH and verify wrong (same root cause
	// as the RunSync snapshot pattern).
	sdPre := s.Body.Scopes[scopeID]
	preSTH, _ := decodeVerifiedSTH(sdPre.LastSTHFor(server.String()))
	preSize := uint64(0)
	if preSTH != nil {
		preSize = preSTH.TreeSize()
	}

	push := []any{pushItemFor(scopeID, ev, preSize)}
	body, err := buildSyncRequestBody(nil, push, false, "", 0)
	if err != nil {
		return false, err
	}
	// Server pin must already be installed in the vault by the
	// outer RunSync. Reconcile-on-conflict only runs after a
	// successful first round, so the pin lookup is a map read.
	pinnedPub, perr := s.PinnedServerPub(server)
	if perr != nil {
		return false, perr
	}
	resp, err := s.signedPOST(ctx, server.JoinPath("/v1/sync"), body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	rb, err := httpguard.ReadBody(resp.Body, maxSyncResponseBytes)
	if err != nil {
		return false, err
	}
	// Check the HTTP status BEFORE decoding. A non-200 response (429
	// rate-limit, 4xx, 5xx) carries an error body with no `push`
	// field, so blindly decoding it yields an empty push list and the
	// misleading "server returned no push result" — masking the real
	// cause. This was the ONE push path missing the status check that
	// every other push/pull path already has. signedPOST already
	// retries transient 429s with Retry-After backoff; reaching here
	// with a 429 means the limit persisted past those retries, which
	// we surface verbatim so the operator sees the true reason.
	if resp.StatusCode != http.StatusOK {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			return false, fmt.Errorf("rebuilt-push %s: %s (retry-after %ss)", shortScopeID(scopeID), resp.Status, ra)
		}
		return false, fmt.Errorf("rebuilt-push %s: %s", shortScopeID(scopeID), resp.Status)
	}
	var sr struct {
		Push []struct {
			Accepted         bool                       `cbor:"accepted"`
			Reason           string                     `cbor:"reason,omitempty"`
			Seq              uint64                     `cbor:"seq,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProof   *translog.InclusionProof   `cbor:"inclusion_proof,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
		} `cbor:"push"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return false, err
	}
	// Cardinality invariant: one push item submitted ⇒ exactly one
	// push result. Zero (or any other count) on a 200 response is a
	// server protocol violation — refuse rather than guess. (Wire
	// contract: PROTOCOL.md — len(response.push) MUST equal
	// len(request.push).)
	if len(sr.Push) != 1 {
		return false, fmt.Errorf("rebuilt-push %s: protocol violation: submitted 1 push item, server returned %d push results", shortScopeID(scopeID), len(sr.Push))
	}
	r := sr.Push[0]
	if r.Accepted || r.Reason == "dup" {
		// Translog verify before persisting any state. STH +
		// InclusionProof are MANDATORY on accepted/dup per
		// TRANSLOG.md §5.4 — missing them is a server protocol
		// violation; refuse to advance.
		if r.STH == nil || r.InclusionProof == nil {
			return false, fmt.Errorf("scope %s rebuilt-push: %w (server returned %s without STH/inclusion proof)",
				scopeID, ErrSTHMissing, r.Reason)
		}
		// SECURITY (subagent regression hunt 🔴 sync.go:1334):
		// the server's r.Seq MUST match the seq we just signed
		// and submitted. Without this check, a server bug or
		// hostile server returning a different Seq would cause
		// leafHashAtSeq to read the WRONG event's leaf and the
		// inclusion proof would verify (against the wrong leaf)
		// — letting the client persist a LastSTH that "proves"
		// inclusion of an event the user never authored.
		if r.Seq != ev.SignedPrefix.Seq {
			return false, fmt.Errorf("scope %s rebuilt-push: server returned r.Seq=%d but submitted event has Seq=%d",
				scopeID, r.Seq, ev.SignedPrefix.Seq)
		}
		leafHash, lerr := s.leafHashAtSeq(scopeID, r.Seq)
		if lerr != nil {
			return false, fmt.Errorf("scope %s rebuilt-push verify: %w", scopeID, lerr)
		}
		expectedChainID := "scope:" + scopeID
		verifiedPushSTH, err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, r.STH, preSTH, []translog.InclusionProof{*r.InclusionProof}, []uint64{r.Seq}, [][]byte{leafHash}, r.ConsistencyProof)
		if err != nil {
			return false, fmt.Errorf("scope %s rebuilt-push verify: %w", scopeID, err)
		}
		if verifiedPushSTH == nil {
			return false, fmt.Errorf("scope %s rebuilt-push verify: verified STH unexpectedly nil", scopeID)
		}
		sdNow := s.Body.Scopes[scopeID]
		encoded, eerr := EncodeSTH(*verifiedPushSTH)
		if eerr != nil {
			return false, fmt.Errorf("encode LastSTH: %w", eerr)
		}
		sdNow.SetLastSTHFor(server.String(), encoded)
		if next := sdNow.ChainTip.Seq + 1; next > sdNow.PushFloorFor(server.String()) {
			sdNow.SetPushFloorFor(server.String(), next)
		}
		s.Body.Scopes[scopeID] = sdNow
		if err := s.ReSeal(); err != nil {
			// ReSeal failure is non-fatal here: the push already
			// landed on the server; floor staleness only costs a
			// re-push on the next sync (server dedups). Surface so
			// it shows up in logs.
			return true, fmt.Errorf("re-seal after push-floor advance: %w", err)
		}
		return true, nil
	}
	if r.Reason == "divergence" || r.Reason == "stale_oek_version" {
		return false, nil // caller retries
	}
	return false, fmt.Errorf("push refused: %s", r.Reason)
}

// rebuildAndPushRoleChange re-emits a pending role change against the
// current tip, or drops it when the target left or already has the role.
func (s *Session) rebuildAndPushRoleChange(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string, st *chain.ScopeState, p pendingEvent) (bool, error) {
	if !memberIn(st.MemberSet, p.target) || st.Roles.RoleOf(p.target) == p.role {
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s role change now a no-op, dropped\n", shortScopeID(scopeID))
		return true, nil
	}
	ev, err := chain.BuildRoleChange(
		AgentSigner{Agent: s.Agent}, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, st.CurrentOEKVer,
		p.target, p.role,
	)
	if err != nil {
		return false, err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return false, err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return false, err
	}
	return s.pushRebuiltEvent(ctx, wcc, server, scopeID, ev)
}

// checkRoleTransition applies the last-admin rule to a membership change
// against st before anything is signed.
func checkRoleTransition(st *chain.ScopeState, op string, target []byte, role string) error {
	post := make([][]byte, 0, len(st.MemberSet)+1)
	for _, m := range st.MemberSet {
		if op != proto.OpRemove || !bytes.Equal(m, target) {
			post = append(post, m)
		}
	}
	if op == proto.OpAdd && !memberIn(post, target) {
		post = append(post, target)
	}
	_, err := proto.NextScopeRoles(st.Roles, post, &proto.SignedPrefix{Payload: proto.Payload{Op: op, Member: target, Role: role}})
	return err
}

func memberIn(set [][]byte, key []byte) bool {
	for _, m := range set {
		if bytes.Equal(m, key) {
			return true
		}
	}
	return false
}
