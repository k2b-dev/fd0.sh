package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestOrganizationAccessRequiresExactApprovalAndKeepsValuesPrivate(t *testing.T) {
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	var destination string
	withSession(t, ctx, func(s *Session) {
		destination, _ = s.resolveScopeID("destination")
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "PRIVATE_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
		if err := s.writeTypedSecretPayload(ctx, destination, "HIDDEN_NAME", "kv.string", "HIDDEN_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
	})
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Destinations: []string{destination}, Operations: []string{"tags", "rename", "move"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	items, err := access.Inventory(ctx)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	tags := []string{"Prod"}
	name := "organized"
	proposed, err := access.Propose(ctx, []OrganizationChange{{ScopeID: scope, ID: items[0].ID, Revision: items[0].Revision, Tags: &tags, Name: &name, TargetScopeID: destination}})
	if err != nil {
		t.Fatal(err)
	}
	plan := proposed["plan"].(OrganizationPlan)
	if _, err := access.Execute(ctx, plan.ID); err == nil {
		t.Fatal("unapproved plan executed")
	}
	if err := ApproveOrganizationPlan(access.grant.ID, plan.ID, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if err := ApproveOrganizationPlan(access.grant.ID, plan.ID, plan.Digest()); err != nil {
		t.Fatal(err)
	}
	result, err := access.Execute(ctx, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{items, proposed, result})
	for _, forbidden := range []string{"PRIVATE_CANARY", "HIDDEN_CANARY", "HIDDEN_NAME", "unlockSession", "payload"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private information escaped", forbidden)
		}
	}
	if _, err := access.Execute(ctx, plan.ID); err != nil {
		t.Fatal("completed plan retry failed", err)
	}
	withSession(t, ctx, func(s *Session) {
		r, err := s.GetTypedSecret(destination, "organized")
		if err != nil || r.Payload != "PRIVATE_CANARY" || len(r.OrganizationTags) != 1 {
			t.Fatal("move did not preserve value and tags", err)
		}
	})
}
func TestOrganizationAccessRejectsBypassDriftAndRevocation(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "BYPASS_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
	})
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ name, args string }{
		{"secret.get", `{"name":"token"}`}, {"agent.getBody", `{}`}, {"organization_approve", `{}`},
		{"organization_list", `{"raw":true}`}, {"organization_execute", `{"planId":"../../grant"}`},
	} {
		if _, err := access.Call(ctx, request.name, []byte(request.args)); err == nil {
			t.Fatal("bypass accepted", request.name)
		}
	}
	items, _ := access.Inventory(ctx)
	tags := []string{"Prod"}
	changes := []OrganizationChange{{ScopeID: scope, ID: items[0].ID, Revision: items[0].Revision, Tags: &tags}}
	bad := changes[0]
	bad.ScopeID = "not-allowed"
	if _, err := access.Propose(ctx, []OrganizationChange{bad}); err == nil {
		t.Fatal("scope bypass")
	}
	forbiddenName := "new"
	bad = changes[0]
	bad.Name = &forbiddenName
	if _, err := access.Propose(ctx, []OrganizationChange{bad}); err == nil {
		t.Fatal("operation bypass")
	}
	proposed, err := access.Propose(ctx, changes)
	if err != nil {
		t.Fatal(err)
	}
	plan := proposed["plan"].(OrganizationPlan)
	if err := ApproveOrganizationPlan(access.grant.ID, plan.ID, plan.Digest()); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.ChangeItemTags(ctx, scope, "token", "add", []string{"Newer"}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := access.Execute(ctx, plan.ID); err == nil {
		t.Fatal("stale plan executed")
	}
	if err := RevokeOrganizationAccess(access.grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Inventory(ctx); err == nil {
		t.Fatal("revoked session readable")
	}
}
func TestOrganizationAccessDoesNotSurviveRelockOrExpiry(t *testing.T) {
	ctx, scope := newTestVault(t)
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(access.paths.AgentSock)
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Inventory(ctx); err == nil {
		t.Fatal("locked session readable")
	}
	if _, err := client.Unlock(access.paths.Vault, access.paths.UserChain, proto.AuthPassphrase, agent.UnlockCredential{Passphrase: []byte("correct horse battery staple")}); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Inventory(ctx); err == nil {
		t.Fatal("old session revived after unlock")
	}
	access, err = NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Millisecond)
	if _, err := access.Inventory(ctx); err == nil {
		t.Fatal("expired session readable")
	}
}
func TestOrganizationMCPExposesOnlyAllowlistedTools(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "STDIO_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
	})
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	requests := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"organization_list","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secret.get","arguments":{"name":"token"}}}
`
	var output bytes.Buffer
	if err := access.Serve(ctx, strings.NewReader(requests), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "STDIO_CANARY") {
		t.Fatal("stdio leaked secret")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatal(output.String())
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatal("non-protocol stdout", line)
		}
	}
	if !strings.Contains(lines[3], `"isError":true`) {
		t.Fatal("raw method allowed")
	}
}

func TestOrganizationPlanRejectsScopePolicyAndApprovalTampering(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scope, "token", "kv.string", "POLICY_CANARY"); err != nil {
			t.Fatal(err)
		}
	})
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	items, _ := access.Inventory(ctx)
	tags := []string{"Prod"}
	proposed, err := access.Propose(ctx, []OrganizationChange{{ScopeID: scope, ID: items[0].ID, Revision: items[0].Revision, Tags: &tags}})
	if err != nil {
		t.Fatal(err)
	}
	plan := proposed["plan"].(OrganizationPlan)
	if err := ApproveOrganizationPlan(access.grant.ID, plan.ID, plan.Digest()); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		policy, err := s.organizationScopePolicy(scope)
		if err != nil {
			t.Fatal(err)
		}
		policy.Revision = "changed-membership"
		if err := s.checkOrganizationPolicies([]OrganizationScopePolicy{policy}); err == nil {
			t.Fatal("changed policy accepted")
		}
	})
	path, _ := access.planPath(plan.ID)
	plan.Items[0].Change.Tags = &[]string{"Tampered"}
	if err := writeOrganizationJSON(path, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Execute(ctx, plan.ID); err == nil {
		t.Fatal("changed approved plan executed")
	}
	items, _ = access.Inventory(ctx)
	if len(items[0].Tags) != 0 {
		t.Fatal("tampered plan wrote")
	}
}

func TestOrganizationPlanStopsAfterScopeRename(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scope, "token", "kv.string", "SCOPE_CANARY"); err != nil {
			t.Fatal(err)
		}
	})
	access, err := NewOrganizationAccess(ctx, OrganizationAccessOptions{Scopes: []string{scope}, Operations: []string{"tags"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	items, _ := access.Inventory(ctx)
	tags := []string{"Prod"}
	proposed, err := access.Propose(ctx, []OrganizationChange{{ScopeID: scope, ID: items[0].ID, Revision: items[0].Revision, Tags: &tags}})
	if err != nil {
		t.Fatal(err)
	}
	plan := proposed["plan"].(OrganizationPlan)
	if err := ApproveOrganizationPlan(access.grant.ID, plan.ID, plan.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := RunScopeRename(ctx, scope, "changed-scope"); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Execute(ctx, plan.ID); err == nil {
		t.Fatal("scope drift ignored")
	}
	items, _ = access.Inventory(ctx)
	if len(items[0].Tags) != 0 {
		t.Fatal("stale plan wrote")
	}
}
