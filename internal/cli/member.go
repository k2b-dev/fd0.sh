package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// RunScopeAddMember adds the holder of memberCardOrLabel to scopeID. The
// argument is either a card URL (`fd0://card/...`) or a pinned-identity
// label (see `fd0 card import`). Rotates the OEK on accept.
// RunScopeAddMember adds a member. An empty role keeps the legacy wire form,
// which makes the member an admin.
func RunScopeAddMember(ctx context.Context, scopeID, memberCardOrLabel, role string) error {
	if role != "" && !proto.ValidRole(role) {
		return fmt.Errorf("invalid role %q (use admin, writer or reader)", role)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	memberPub, err := s.resolveMember(memberCardOrLabel)
	if err != nil {
		return err
	}
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	for _, m := range st.MemberSet {
		if bytes.Equal(m, memberPub) {
			return fmt.Errorf("already a member of %s", scopeName(s, scopeID))
		}
	}
	// Build current projection.
	proj := projectionFromIndex(st.SecretIndex)
	if err := s.requireAdmin(scopeID, st); err != nil {
		return err
	}
	// Admin is the absent role: keep legacy bytes so older servers and
	// clients accept ordinary sharing.
	if role == proto.RoleAdmin {
		role = ""
	}
	if role != "" {
		if err := s.requireScopeRolesSupport(ctx); err != nil {
			return err
		}
	}
	ev, newOEK, err := chain.BuildMemberChangeWithRole(
		s.Agent, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpAdd, memberPub, role, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = upsertOEK(sd.OEKs, ev.SignedPrefix.OEKVersion, newOEK)
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	shown := role
	if shown == "" {
		shown = proto.RoleAdmin
	}
	fmt.Fprintf(os.Stderr, "✓ added %s to %s as %s (oek=v%d)\n",
		memberDisplay(s, memberPub), scopeName(s, scopeID), shown, ev.SignedPrefix.OEKVersion)
	hintSyncForPeers()
	return nil
}

// RunScopeRemoveMember removes the holder of memberCardOrLabel from scopeID.
// Rotates the OEK on accept.
func RunScopeRemoveMember(ctx context.Context, scopeID, memberCardOrLabel string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	memberPub, err := s.resolveMember(memberCardOrLabel)
	if err != nil {
		return err
	}
	return removeScopeMember(s, scopeID, memberPub, yes)
}

// RunScopeRemoveMemberByPublicKey is the trusted desktop bridge path for
// members that are visible in scope history but are not pinned locally.
func RunScopeRemoveMemberByPublicKey(ctx context.Context, scopeID string, memberPub []byte) error {
	if len(memberPub) != ed25519.PublicKeySize {
		return fmt.Errorf("member public key must be %d bytes", ed25519.PublicKeySize)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return removeScopeMember(s, scopeID, append([]byte(nil), memberPub...), true)
}

func removeScopeMember(s *Session, scopeID string, memberPub []byte, yes bool) error {
	resolvedScopeID, err := s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	scopeID = resolvedScopeID
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	if bytes.Equal(memberPub, s.UserSuperPub) {
		return errors.New("use `fd0 scope leave` to remove yourself")
	}
	found := false
	for _, m := range st.MemberSet {
		if bytes.Equal(m, memberPub) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%s is not a member of %s",
			memberDisplay(s, memberPub), scopeName(s, scopeID))
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove %s from %s?", memberDisplay(s, memberPub), scopeName(s, scopeID))); err != nil {
		return err
	}
	proj := projectionFromIndex(st.SecretIndex)
	if err := s.requireAdmin(scopeID, st); err != nil {
		return err
	}
	ev, newOEK, err := chain.BuildMemberChange(
		s.Agent, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpRemove, memberPub, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = upsertOEK(sd.OEKs, ev.SignedPrefix.OEKVersion, newOEK)
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ removed %s from %s (oek=v%d)\n",
		memberDisplay(s, memberPub), scopeName(s, scopeID), ev.SignedPrefix.OEKVersion)
	hintSyncForPeers()
	return nil
}

// RunScopeLeave appends a `member.change op=remove member=self` event to
// the scope chain and marks the scope as Leaving in the vault. The actual
// deletion (chain file unlink + vault.Scopes prune) is deferred to the
// next sync round, which:
//
//  1. Pushes the leave event so the server records that we're no longer
//     a member.
//  2. On the next pull, the server returns `denied=true` for the scope
//     (we're not authorised) — the existing drop path then unlinks the
//     chain file and removes the vault entry.
//
// The previous implementation dropped the chain file immediately. That
// caused the server to re-discover us as a member on the next sync (the
// leave event was deleted with the file, and the server hadn't been
// told). Marking + deferring is the only race-free approach that
// doesn't require synchronous server I/O inside `scope leave`.
//
// `scope ls` and the read/write helpers filter out `Leaving` scopes so
// they appear gone to the user immediately.
func RunScopeLeave(ctx context.Context, scopeID string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Leave %s?", scopeName(s, scopeID))); err != nil {
		return err
	}
	if role := st.Roles.RoleOf(s.UserSuperPub); role != proto.RoleAdmin {
		// Only admins sign membership changes (docs/SCOPE_ROLES_PLAN.md).
		// Hide the scope on this device; an admin removes the membership.
		sd := s.Body.Scopes[scopeID]
		sd.Leaving = true
		s.Body.Scopes[scopeID] = sd
		if err := s.ReSeal(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ %s hidden on this device; ask an admin to remove you (fd0 scope remove-member) so you stop receiving its keys\n", scopeName(nil, scopeID))
		return nil
	}
	if len(st.MemberSet) > 1 {
		admins := 0
		for _, m := range st.MemberSet {
			if st.Roles.RoleOf(m) == proto.RoleAdmin {
				admins++
			}
		}
		if admins == 1 {
			return fmt.Errorf("you are the only admin of %s; make another member admin first (fd0 scope role CARD admin)", scopeName(s, scopeID))
		}
	}
	// Build the event with op=remove, member=self.
	proj := projectionFromIndex(st.SecretIndex)
	ev, _, err := chain.BuildMemberChange(
		s.Agent, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpRemove, s.UserSuperPub, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	// Update vault entry: bump ChainTip past the leave, mark Leaving.
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	sd.Leaving = true
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ left %s (will be dropped after next sync)\n", scopeName(nil, scopeID))
	hintSyncForPeers()
	return nil
}

// RunScopeMembers prints the member list of one scope.
func RunScopeMembers(ctx context.Context, scopeID string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	pubs := make([][]byte, len(st.MemberSet))
	copy(pubs, st.MemberSet)
	sort.Slice(pubs, func(i, j int) bool { return bytes.Compare(pubs[i], pubs[j]) < 0 })
	for _, p := range pubs {
		marker := "  "
		if bytes.Equal(p, s.UserSuperPub) {
			marker = "* "
		}
		fmt.Printf("%s%-8s %s\n", marker, st.Roles.RoleOf(p), memberDisplay(s, p))
	}
	return nil
}

// RunScopeSetRole changes an existing member's role. Read access stays the
// same, so no OEK is rotated.
func RunScopeSetRole(ctx context.Context, scopeID, memberCardOrLabel, role string) error {
	return runScopeSetRole(ctx, scopeID, role, func(s *Session) ([]byte, error) { return s.resolveMember(memberCardOrLabel) })
}

// RunScopeSetRoleByPublicKey is RunScopeSetRole for callers that hold the
// member's super_pub (Desktop's access list).
func RunScopeSetRoleByPublicKey(ctx context.Context, scopeID string, memberPub []byte, role string) error {
	return runScopeSetRole(ctx, scopeID, role, func(*Session) ([]byte, error) { return memberPub, nil })
}

func runScopeSetRole(ctx context.Context, scopeID, role string, resolve func(*Session) ([]byte, error)) error {
	if !proto.ValidRole(role) {
		return fmt.Errorf("invalid role %q (use admin, writer or reader)", role)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	memberPub, err := resolve(s)
	if err != nil {
		return err
	}
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	if err := s.requireAdmin(scopeID, st); err != nil {
		return err
	}
	if !memberIn(st.MemberSet, memberPub) {
		return fmt.Errorf("%s is not a member of %s", memberDisplay(s, memberPub), scopeName(s, scopeID))
	}
	if st.Roles.RoleOf(memberPub) == role {
		fmt.Fprintf(os.Stderr, "%s is already %s in %s\n", memberDisplay(s, memberPub), role, scopeName(s, scopeID))
		return nil
	}
	if err := s.requireScopeRolesSupport(ctx); err != nil {
		return err
	}
	if err := checkRoleTransition(st, proto.OpRole, memberPub, role); err != nil {
		return err
	}
	ev, err := chain.BuildRoleChange(s.Agent, s.UserSuperPub, proto.MustParseScopeID(scopeID),
		st.TipSeq, st.TipHash, st.CurrentOEKVer, memberPub, role)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ %s is now %s in %s\n", memberDisplay(s, memberPub), role, scopeName(s, scopeID))
	hintSyncForPeers()
	return nil
}

// RunScopeRename updates a scope's shared label. The label rides on the
// reserved `_meta` secret (see internal/cli/meta.go) so all members see the
// new name after their next sync.
func RunScopeRename(ctx context.Context, scopeOrLabel, newLabel string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err := s.resolveScopeID(scopeOrLabel)
	if err != nil {
		return err
	}
	old := s.Body.Scopes[scopeID].Label
	if err := s.writeScopeMeta(scopeID, map[string]string{MetaKeyLabel: newLabel}); err != nil {
		return err
	}
	if old == "" {
		fmt.Fprintf(os.Stderr, "✓ scope %s labeled '%s'\n", shortScopeID(scopeID), terminalSafe(newLabel))
	} else {
		fmt.Fprintf(os.Stderr, "✓ scope renamed: '%s' → '%s' (%s)\n",
			terminalSafe(old), terminalSafe(newLabel), shortScopeID(scopeID))
	}
	hintSyncForPeers()
	return nil
}

func memberDisplay(s *Session, pub []byte) string {
	if s != nil {
		if bytes.Equal(pub, s.UserSuperPub) {
			return "you (" + b64sub(pub) + "…)"
		}
		for label, pinned := range s.Body.PinnedIdentities {
			if bytes.Equal(pub, pinned.SuperPub) {
				return label + " (" + b64sub(pub) + "…)"
			}
		}
	}
	return b64sub(pub) + "…"
}

// projectionFromIndex builds a MemberProjection from the in-memory secret
// index, omitting tombstones.
func projectionFromIndex(idx map[string]chain.ScopeSecret) *proto.MemberProjection {
	out := &proto.MemberProjection{Secrets: make([]proto.SecretInProjection, 0, len(idx))}
	for id, cur := range idx {
		if cur.Record == nil {
			continue
		}
		out.Secrets = append(out.Secrets, proto.SecretInProjection{ID: id, Record: cur.Record})
	}
	sort.Slice(out.Secrets, func(i, j int) bool { return out.Secrets[i].ID < out.Secrets[j].ID })
	return out
}
