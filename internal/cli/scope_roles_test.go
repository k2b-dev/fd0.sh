package cli

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestCheckRoleTransitionKeepsAnAdmin(t *testing.T) {
	a, b, c := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	// a is the only admin; b reads.
	st := &chain.ScopeState{MemberSet: [][]byte{a, b}, Roles: proto.ScopeRoles{hex.EncodeToString(b): proto.RoleReader}}
	for _, tc := range []struct {
		op     string
		target []byte
		role   string
		ok     bool
	}{
		{proto.OpRole, a, proto.RoleWriter, false}, // sole admin demotes itself
		{proto.OpRemove, a, "", false},             // sole admin leaves while b remains
		{proto.OpRole, b, proto.RoleAdmin, true},
		{proto.OpAdd, c, proto.RoleReader, true},
		{proto.OpRemove, b, "", true},
	} {
		err := checkRoleTransition(st, tc.op, tc.target, tc.role)
		if (err == nil) != tc.ok {
			t.Fatalf("%s %x→%q: err=%v, want ok=%v", tc.op, tc.target[:1], tc.role, err, tc.ok)
		}
	}
	// The last member may leave: the scope becomes a tombstone.
	solo := &chain.ScopeState{MemberSet: [][]byte{a}, Roles: proto.ScopeRoles{}}
	if err := checkRoleTransition(solo, proto.OpRemove, a, ""); err != nil {
		t.Fatalf("last member leave: %v", err)
	}
}
