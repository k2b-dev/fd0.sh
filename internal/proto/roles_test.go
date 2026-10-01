package proto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestAuthorizeScopeEventRules(t *testing.T) {
	admin, writer, reader, outsider := key(1), key(2), key(3), key(4)
	members := [][]byte{admin, writer, reader}
	roles := ScopeRoles{hex.EncodeToString(writer): RoleWriter, hex.EncodeToString(reader): RoleReader}
	ev := func(author []byte, kind, op string, member []byte, role string) *SignedPrefix {
		return &SignedPrefix{Kind: kind, Author: author, Payload: Payload{Op: op, Member: member, Role: role}}
	}
	for _, tc := range []struct {
		name string
		sp   *SignedPrefix
		ok   bool
	}{
		{"admin writes", ev(admin, KindSecretSet, "", nil, ""), true},
		{"writer writes", ev(writer, KindSecretSet, "", nil, ""), true},
		{"reader cannot write", ev(reader, KindSecretSet, "", nil, ""), false},
		{"outsider cannot write", ev(outsider, KindSecretSet, "", nil, ""), false},
		{"secret.set carries no role", ev(admin, KindSecretSet, "", nil, RoleReader), false},
		{"admin adds legacy", ev(admin, KindMemberChange, OpAdd, outsider, ""), true},
		{"admin adds reader", ev(admin, KindMemberChange, OpAdd, outsider, RoleReader), true},
		{"invalid role", ev(admin, KindMemberChange, OpAdd, outsider, "owner"), false},
		{"writer cannot add", ev(writer, KindMemberChange, OpAdd, outsider, RoleReader), false},
		{"reader cannot remove itself", ev(reader, KindMemberChange, OpRemove, reader, ""), false},
		{"admin removes", ev(admin, KindMemberChange, OpRemove, reader, ""), true},
		{"remove carries no role", ev(admin, KindMemberChange, OpRemove, reader, RoleReader), false},
		{"admin promotes", ev(admin, KindMemberChange, OpRole, reader, RoleWriter), true},
		{"role must change", ev(admin, KindMemberChange, OpRole, reader, RoleReader), false},
		{"role target must be member", ev(admin, KindMemberChange, OpRole, outsider, RoleWriter), false},
		{"role needs a role", ev(admin, KindMemberChange, OpRole, reader, ""), false},
		{"writer cannot change roles", ev(writer, KindMemberChange, OpRole, writer, RoleAdmin), false},
		{"unknown op", ev(admin, KindMemberChange, "rotate", reader, ""), false},
	} {
		err := AuthorizeScopeEvent(tc.sp, members, roles)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestNextScopeRolesKeepsAnAdmin(t *testing.T) {
	admin, other := key(1), key(2)
	roles := ScopeRoles{}
	next, err := NextScopeRoles(roles, [][]byte{admin, other}, &SignedPrefix{Payload: Payload{Op: OpAdd, Member: other, Role: RoleReader}})
	if err != nil || next.RoleOf(other) != RoleReader || next.RoleOf(admin) != RoleAdmin {
		t.Fatalf("add reader: %v %v", next, err)
	}
	if _, err := NextScopeRoles(next, [][]byte{admin, other}, &SignedPrefix{Payload: Payload{Op: OpRole, Member: admin, Role: RoleWriter}}); err == nil {
		t.Fatal("demoting the last admin was allowed")
	}
	if _, err := NextScopeRoles(next, [][]byte{other}, &SignedPrefix{Payload: Payload{Op: OpRemove, Member: admin}}); err == nil {
		t.Fatal("removing the last admin from a non-empty scope was allowed")
	}
	if _, err := NextScopeRoles(ScopeRoles{}, nil, &SignedPrefix{Payload: Payload{Op: OpRemove, Member: admin}}); err != nil {
		t.Fatalf("removing the last member must tombstone, not fail: %v", err)
	}
	promoted, err := NextScopeRoles(next, [][]byte{admin, other}, &SignedPrefix{Payload: Payload{Op: OpRole, Member: other, Role: RoleAdmin}})
	if err != nil || len(promoted) != 0 {
		t.Fatalf("admin entries stay implicit: %v %v", promoted, err)
	}
	if err := GenesisRole(&SignedPrefix{Payload: Payload{Role: RoleReader}}); err == nil {
		t.Fatal("genesis reader accepted")
	}
}

func TestLegacyMemberChangeBytesUnchanged(t *testing.T) {
	legacy := Payload{Op: OpAdd, Member: key(9), EncProjection: []byte{1, 2, 3}}
	raw, err := Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("role")) {
		t.Fatal("a legacy payload gained a role key")
	}
	var back Payload
	if err := Unmarshal(raw, &back); err != nil || back.Role != "" {
		t.Fatalf("decode: %+v %v", back, err)
	}
	again, _ := Marshal(back)
	if !bytes.Equal(raw, again) {
		t.Fatal("legacy payload does not round-trip byte-identically")
	}
}
