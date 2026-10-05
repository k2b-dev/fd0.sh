package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func createGrant(t *testing.T, ctx context.Context, kind, scope, name, field string, auth *agent.UnlockReq) (*agent.SecretGrantResp, error) {
	t.Helper()
	r := agent.SecretGrantReq{Action: "prepare", ScopeID: scope, Kind: kind, Name: name, Field: field, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	preview, err := ManageSecretGrant(ctx, r)
	if err != nil {
		return nil, err
	}
	r.Action, r.Digest, r.Authentication = "create", preview.Digest, auth
	return ManageSecretGrant(ctx, r)
}

// TestSecretGrantsLifecycle covers the contract in docs/SECRET_GRANTS_PLAN.md
// against an in-process agent.
func TestSecretGrantsLifecycle(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	paths, _ := fdhome.Resolve()
	client := agent.NewClient(paths.AgentSock)
	relock := func() {
		t.Helper()
		if err := client.Lock(); err != nil {
			t.Fatal(err)
		}
	}
	unlock := func() {
		t.Helper()
		if _, err := client.Unlock(paths.Vault, paths.UserChain, proto.AuthPassphrase, agent.UnlockCredential{Passphrase: []byte("correct horse battery staple")}); err != nil {
			t.Fatal(err)
		}
	}

	if err := RunSecretSet(ctx, scope, "cld-client-secret", "v1-secret"); err != nil {
		t.Fatal(err)
	}
	if err := RunSecretSet(ctx, scope, "not-granted", "nope"); err != nil {
		t.Fatal(err)
	}
	if err := RunPassAdd(ctx, PassAddOpts{Name: "mail", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	if err := RunPassFieldSet(ctx, PassFieldSetOpts{Item: "mail", Path: "password", Value: "mail-pw", Secret: true, Scope: scope}); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "app", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	var err error
	withStdio(t, dir, "svc-token", func() {
		err = RunServiceSet(ctx, ServiceSetOpts{Name: "app", Scope: scope, Field: "token"})
	})
	if err != nil {
		t.Fatal(err)
	}

	// Creation needs the right credential and the reviewed digest.
	if _, err := createGrant(t, ctx, "secret", scope, "cld-client-secret", "", &agent.UnlockReq{MethodType: proto.AuthPassphrase, Passphrase: []byte("wrong")}); err == nil {
		t.Fatal("wrong passphrase created a grant")
	}
	r := agent.SecretGrantReq{Action: "create", ScopeID: scope, Kind: "secret", Name: "cld-client-secret", ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Digest: strings.Repeat("0", 64), Authentication: goodAuth()}
	if _, err := ManageSecretGrant(ctx, r); err == nil {
		t.Fatal("unreviewed grant accepted")
	}
	if _, err := createGrant(t, ctx, "pass", scope, "mail", "missing", goodAuth()); err == nil {
		t.Fatal("grant for a missing field accepted")
	}
	for _, g := range []struct{ kind, name, field string }{{"secret", "cld-client-secret", ""}, {"pass", "mail", "password"}, {"service", "app", "token"}} {
		if _, err := createGrant(t, ctx, g.kind, scope, g.name, g.field, goodAuth()); err != nil {
			t.Fatalf("%s grant: %v", g.kind, err)
		}
	}

	// Locked: granted values are readable, by scope ID or label; others are not.
	relock()
	label := scopeNameForTest(t, scope)
	if v, err := RunSecretGet(ctx, label, "cld-client-secret"); err != nil || v != "v1-secret" {
		t.Fatalf("locked secret read: %q %v", v, err)
	}
	if _, err := RunSecretGet(ctx, scope, "not-granted"); !errors.Is(err, ErrAgentLocked) {
		t.Fatalf("ungranted read: %v", err)
	}
	if out := withStdio(t, dir, "", func() { err = RunPassFieldGet(ctx, scope, "mail", "password", true) }); err != nil || out != "mail-pw" {
		t.Fatalf("locked pass read: %q %v", out, err)
	}
	if out := withStdio(t, dir, "", func() { err = RunServiceGet(ctx, scope, "app", "token", true) }); err != nil || out != "svc-token" {
		t.Fatalf("locked service read: %q %v", out, err)
	}
	if st, _ := client.Status(); st.SecretGrantCount != 3 {
		t.Fatalf("status count %d", st.SecretGrantCount)
	}

	// A rotation while unlocked is served after the next lock.
	unlock()
	if err := RunSecretSet(ctx, scope, "cld-client-secret", "v2-secret"); err != nil {
		t.Fatal(err)
	}
	relock()
	if v, _ := RunSecretGet(ctx, scope, "cld-client-secret"); v != "v2-secret" {
		t.Fatalf("rotation not served: %q", v)
	}

	// Renaming the granted record disables its grant.
	unlock()
	s, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameItem(ctx, KindService, scope, "app", "app-2", false, nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	relock()
	for _, name := range []string{"app", "app-2"} {
		if err := RunServiceGet(ctx, scope, name, "token", true); !errors.Is(err, ErrAgentLocked) {
			t.Fatalf("renamed record %s still released: %v", name, err)
		}
	}

	// lock --all stops every grant until the next unlock.
	if err := client.LockAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := RunSecretGet(ctx, scope, "cld-client-secret"); !errors.Is(err, ErrAgentLocked) {
		t.Fatalf("lock --all left a grant active: %v", err)
	}

	// Grants survive ordinary vault writes; the renamed service's grant was
	// removed for good at the rename. Grants can be revoked.
	unlock()
	list, err := ManageSecretGrant(ctx, agent.SecretGrantReq{Action: "list"})
	if err != nil || len(list.Grants) != 2 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := RunValueRevoke(ctx, list.Grants[0].ID); err != nil {
		t.Fatal(err)
	}
	if list, _ = ManageSecretGrant(ctx, agent.SecretGrantReq{Action: "list"}); len(list.Grants) != 1 {
		t.Fatalf("revoke: %+v", list)
	}
}

func scopeNameForTest(t *testing.T, scope string) string {
	t.Helper()
	paths, _ := fdhome.Resolve()
	resp, err := agent.NewClient(paths.AgentSock).SecretGrant(agent.SecretGrantReq{Action: "list"})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range resp.Grants {
		if g.ScopeID == scope && g.ScopeLabel != "" {
			return g.ScopeLabel
		}
	}
	t.Fatal("no scope label on active grants")
	return ""
}

// A field that is removed and created again under the same name must not
// inherit the old grant, and locked reads need an unambiguous scope.
func TestSecretGrantsDoNotResurrect(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	paths, _ := fdhome.Resolve()
	client := agent.NewClient(paths.AgentSock)
	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "app", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	set := func(value string) {
		t.Helper()
		var err error
		withStdio(t, dir, value, func() { err = RunServiceSet(ctx, ServiceSetOpts{Name: "app", Scope: scope, Field: "token"}) })
		if err != nil {
			t.Fatal(err)
		}
	}
	set("granted-value")
	if _, err := createGrant(t, ctx, "service", scope, "app", "token", goodAuth()); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceFieldRemove(ctx, scope, "app", "token", true); err != nil {
		t.Fatal(err)
	}
	set("new-value-never-approved")
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	var err error
	out := withStdio(t, dir, "", func() { err = RunServiceGet(ctx, scope, "app", "token", true) })
	if !errors.Is(err, ErrAgentLocked) || strings.Contains(out, "new-value") {
		t.Fatalf("recreated field inherited the grant: %q %v", out, err)
	}
	if _, err := client.Unlock(paths.Vault, paths.UserChain, proto.AuthPassphrase, agent.UnlockCredential{Passphrase: []byte("correct horse battery staple")}); err != nil {
		t.Fatal(err)
	}
	if list, _ := ManageSecretGrant(ctx, agent.SecretGrantReq{Action: "list"}); len(list.Grants) != 0 {
		t.Fatalf("invalidated grant kept: %+v", list.Grants)
	}
	// A new grant on the recreated field works; reads need --scope.
	if _, err := createGrant(t, ctx, "service", scope, "app", "token", goodAuth()); err != nil {
		t.Fatal(err)
	}
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := grantedValue("service", "", "app", "token"); err == nil {
		t.Fatal("read without scope released a value")
	}
	if v, err := grantedValue("service", scope, "app", "token"); err != nil || string(v) != "new-value-never-approved" {
		t.Fatalf("explicit scope read: %q %v", v, err)
	}
}
