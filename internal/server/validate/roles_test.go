package validate

import (
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// TestServerValidatorEnforcesScopeRoles builds a real chain with the client
// builders and feeds it through the server validator.
func TestServerValidatorEnforcesScopeRoles(t *testing.T) {
	adminPub, adminPriv, _ := crypto.GenerateIdentity()
	readerPub, readerPriv, _ := crypto.GenerateIdentity()
	admin := chain.LocalSigner{Priv: adminPriv}
	reader := chain.LocalSigner{Priv: readerPriv}

	gen, _, scope, err := chain.BuildScopeGenesis(admin, adminPub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := ScopeEvent(gen, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	tip := func(ev *proto.ScopeEvent) []byte {
		in, _ := ev.PrevHashInput()
		h := proto.HashPrefix(in)
		return h[:]
	}
	prev, seq := tip(gen), uint64(0)
	add, _, err := chain.BuildMemberChangeWithRole(admin, adminPub.Bytes(), scope, seq, prev, meta.OEKVersionMax,
		proto.OpAdd, readerPub.Bytes(), proto.RoleReader, meta.Members, &proto.MemberProjection{})
	if err != nil {
		t.Fatal(err)
	}
	if meta, err = ScopeEvent(add, meta, prev, seq); err != nil {
		t.Fatal(err)
	}
	if meta.Roles.RoleOf(readerPub.Bytes()) != proto.RoleReader {
		t.Fatalf("server roles: %v", meta.Roles)
	}
	prev, seq = tip(add), seq+1

	oek := make([]byte, 32)
	write, err := chain.BuildSecretSet(reader, readerPub.Bytes(), scope, seq, prev, oek, meta.OEKVersionMax,
		&proto.SecretBody{ID: "s_server_role_test", Record: &proto.SecretRecord{Name: "x", Type: "kv.string", SchemaVersion: 1, Payload: "v", Tags: map[string]string{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScopeEvent(write, meta, prev, seq); err == nil || !strings.Contains(err.Error(), "may not write") {
		t.Fatalf("server accepted a reader's write: %v", err)
	}
	promote, err := chain.BuildRoleChange(admin, adminPub.Bytes(), scope, seq, prev, meta.OEKVersionMax, readerPub.Bytes(), proto.RoleWriter)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ScopeEvent(promote, meta, prev, seq)
	if err != nil {
		t.Fatal(err)
	}
	if next.OEKVersionMax != meta.OEKVersionMax || next.Roles.RoleOf(readerPub.Bytes()) != proto.RoleWriter {
		t.Fatalf("role change: %+v", next)
	}
	demoteSelf, err := chain.BuildRoleChange(admin, adminPub.Bytes(), scope, seq, prev, meta.OEKVersionMax, adminPub.Bytes(), proto.RoleReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScopeEvent(demoteSelf, meta, prev, seq); err == nil || !strings.Contains(err.Error(), "no admin left") {
		t.Fatalf("server allowed demoting the last admin: %v", err)
	}
}
