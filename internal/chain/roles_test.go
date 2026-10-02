package chain

import (
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

type roleFixture struct {
	t         *testing.T
	path      string
	ownerPub  []byte
	owner     LocalSigner
	open      LocalOpener
	ownerXPub []byte
	memberPub []byte
	member    LocalSigner
	scope     proto.ScopeID
}

// newRoleFixture creates a scope owned by an admin and adds a second member
// with the given role.
func newRoleFixture(t *testing.T, role string) *roleFixture {
	t.Helper()
	path, ownerPub, ownerPriv, _, _, ownerXPub, ownerXPriv, scopeID := setupTwoMember(t)
	_ = path
	ownerTyped, _ := crypto.ParseEd25519Priv(ownerPriv)
	f := &roleFixture{t: t, ownerPub: ownerPub, owner: LocalSigner{Priv: ownerTyped}, open: LocalOpener{Pub: ownerXPub, Priv: ownerXPriv}, ownerXPub: ownerXPub, scope: scopeID, path: path}
	pub, priv, _ := crypto.GenerateIdentity()
	f.memberPub = pub.Bytes()
	f.member = LocalSigner{Priv: priv}
	st := f.replay()
	ev, _, err := BuildMemberChangeWithRole(f.owner, ownerPub, scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer, proto.OpAdd, f.memberPub, role, st.MemberSet, buildProjection(st))
	if err != nil {
		t.Fatal(err)
	}
	f.append(ev)
	return f
}

func (f *roleFixture) replay() *ScopeState {
	f.t.Helper()
	st, err := ReplayScope(f.path, f.ownerPub, f.ownerXPub, f.open)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

func (f *roleFixture) append(ev *proto.ScopeEvent) {
	f.t.Helper()
	if err := AppendScope(f.path, ev); err != nil {
		f.t.Fatal(err)
	}
}

func (f *roleFixture) expectRejected(ev *proto.ScopeEvent, want string) {
	f.t.Helper()
	f.append(ev)
	if _, err := ReplayScope(f.path, f.ownerPub, f.ownerXPub, f.open); err == nil || !strings.Contains(err.Error(), want) {
		f.t.Fatalf("replay accepted a forbidden event or failed differently: %v", err)
	}
}

func (f *roleFixture) secretSet(signer LocalSigner, author []byte, st *ScopeState) *proto.ScopeEvent {
	f.t.Helper()
	ev, err := BuildSecretSet(signer, author, f.scope, st.TipSeq, st.TipHash, st.OEKs[st.CurrentOEKVer], st.CurrentOEKVer,
		&proto.SecretBody{ID: "s_role_test_value_a", Record: &proto.SecretRecord{Name: "x", Type: "kv.string", SchemaVersion: 1, Payload: "v", Tags: map[string]string{}}})
	if err != nil {
		f.t.Fatal(err)
	}
	return ev
}

func TestReplayRolesReaderCannotWrite(t *testing.T) {
	f := newRoleFixture(t, proto.RoleReader)
	st := f.replay()
	if st.Roles.RoleOf(f.memberPub) != proto.RoleReader {
		t.Fatalf("role after add: %v", st.Roles)
	}
	f.expectRejected(f.secretSet(f.member, f.memberPub, st), "may not write values")
}

func TestReplayRolesWriterWritesButCannotAddMembers(t *testing.T) {
	f := newRoleFixture(t, proto.RoleWriter)
	st := f.replay()
	f.append(f.secretSet(f.member, f.memberPub, st))
	st = f.replay()
	if _, ok := st.SecretIndex["s_role_test_value_a"]; !ok {
		t.Fatal("writer's value missing")
	}
	thirdPub, _, _ := crypto.GenerateIdentity()
	ev, _, err := BuildMemberChange(f.member, f.memberPub, f.scope, st.TipSeq, st.TipHash, st.CurrentOEKVer, proto.OpAdd, thirdPub.Bytes(), st.MemberSet, buildProjection(st))
	if err != nil {
		t.Fatal(err)
	}
	f.expectRejected(ev, "may not change membership")
}

func TestReplayRoleChangeKeepsOEKAndProtectsLastAdmin(t *testing.T) {
	f := newRoleFixture(t, proto.RoleReader)
	st := f.replay()
	before := st.CurrentOEKVer
	ev, err := BuildRoleChange(f.owner, f.ownerPub, f.scope, st.TipSeq, st.TipHash, st.CurrentOEKVer, f.memberPub, proto.RoleWriter)
	if err != nil {
		t.Fatal(err)
	}
	f.append(ev)
	st = f.replay()
	if st.Roles.RoleOf(f.memberPub) != proto.RoleWriter || st.CurrentOEKVer != before {
		t.Fatalf("role change: role=%s oek %d -> %d", st.Roles.RoleOf(f.memberPub), before, st.CurrentOEKVer)
	}
	// setupTwoMember's second member is an admin; demote it, then the owner
	// is the only admin and cannot demote itself.
	for _, m := range st.MemberSet {
		if string(m) != string(f.ownerPub) && string(m) != string(f.memberPub) {
			ev, err := BuildRoleChange(f.owner, f.ownerPub, f.scope, st.TipSeq, st.TipHash, st.CurrentOEKVer, m, proto.RoleReader)
			if err != nil {
				t.Fatal(err)
			}
			f.append(ev)
			st = f.replay()
		}
	}
	last, err := BuildRoleChange(f.owner, f.ownerPub, f.scope, st.TipSeq, st.TipHash, st.CurrentOEKVer, f.ownerPub, proto.RoleWriter)
	if err != nil {
		t.Fatal(err)
	}
	f.expectRejected(last, "no admin left")
}

func TestReplayRejectsRoleChangeWithRotation(t *testing.T) {
	f := newRoleFixture(t, proto.RoleReader)
	st := f.replay()
	ev, err := BuildRoleChange(f.owner, f.ownerPub, f.scope, st.TipSeq, st.TipHash, st.CurrentOEKVer+1, f.memberPub, proto.RoleWriter)
	if err != nil {
		t.Fatal(err)
	}
	f.expectRejected(ev, "oek_version")
}
