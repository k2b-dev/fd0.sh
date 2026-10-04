package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/recipe"
)

// TestRecipeApproveDeployAndResults runs the full recipe flow against an
// in-process agent: nothing runs before approval, approval needs the right
// credential and pins the definition, deploy runs once per target with values
// on stdin, results are recorded, and any change needs a new approval.
func TestRecipeApproveDeployAndResults(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	saved := deploySync
	deploySync = func(context.Context) error { return nil }
	t.Cleanup(func() { deploySync = saved })
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECIPE_OUT", out)

	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "shop-db", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	set := func(field, env, value string) {
		t.Helper()
		var err error
		withStdio(t, dir, value, func() {
			err = RunServiceSet(ctx, ServiceSetOpts{Name: "shop-db", Scope: scope, Field: field, Env: env})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	set("db-password", "DB_PASSWORD", "first-value")

	write := []string{"/bin/sh", "-c", `cat > "$RECIPE_OUT/$FD0_TARGET"`}
	opts := RecipeOpts{Name: "shop-db/apps", Scope: scope, Command: write, Fields: []string{"db-password"},
		Input: "stdin:systemd-env", Targets: []string{"app-1", "app-2"}}
	if err := RunRecipeAdd(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db"}); err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("unapproved recipe ran: %v", err)
	}

	digest := recipeDigest(t, ctx, scope, "shop-db/apps")
	wrong := &agent.UnlockReq{MethodType: proto.AuthPassphrase, Passphrase: []byte("wrong passphrase")}
	if err := approveRecipe(ctx, scope, "shop-db/apps", digest, wrong); err == nil {
		t.Fatal("wrong passphrase approved a recipe")
	}
	if err := approveRecipe(ctx, scope, "shop-db/apps", strings.Repeat("0", 64), goodAuth()); err == nil {
		t.Fatal("unreviewed digest approved")
	}
	if err := approveRecipe(ctx, scope, "shop-db/apps", digest, goodAuth()); err != nil {
		t.Fatal(err)
	}

	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db"}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"app-1", "app-2"} {
		got, err := os.ReadFile(filepath.Join(out, target))
		if err != nil || string(got) != "DB_PASSWORD=\"first-value\"\n" {
			t.Fatalf("%s received %q (%v)", target, got, err)
		}
	}
	results := recipeResults(t, ctx, scope, "shop-db/apps")
	if len(results) != 2 || results[0].Status != "ok" || results[0].Target != "app-1" || results[0].Digest != digest || results[0].Source == "" {
		t.Fatalf("results: %+v", results)
	}

	// A value rotation needs no new approval; one target can run alone.
	set("db-password", "", "second-value")
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db/apps", Target: "app-2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "app-2")); string(got) != "DB_PASSWORD=\"second-value\"\n" {
		t.Fatalf("rotation not delivered: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "app-1")); string(got) != "DB_PASSWORD=\"first-value\"\n" {
		t.Fatal("--target ran other targets")
	}

	// Any change to the definition, even one more target, needs approval.
	opts.Targets = append(opts.Targets, "app-3")
	if err := RunRecipeAdd(ctx, opts, true); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db"}); err == nil || !strings.Contains(err.Error(), "changed since approval") {
		t.Fatalf("changed recipe ran: %v", err)
	}

	// A failing target stops the run and is recorded as failed.
	failing := RecipeOpts{Name: "shop-db/broken", Scope: scope, Command: []string{"/bin/sh", "-c", `[ "$FD0_TARGET" != b ] || exit 7`},
		Fields: []string{"db-password=PGPASSWORD"}, Input: "env", Targets: []string{"a", "b", "c"}}
	if err := RunRecipeAdd(ctx, failing, false); err != nil {
		t.Fatal(err)
	}
	if err := approveRecipe(ctx, scope, "shop-db/broken", recipeDigest(t, ctx, scope, "shop-db/broken"), goodAuth()); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db/broken"}); err == nil || !strings.Contains(err.Error(), "stopped at shop-db/broken  b") {
		t.Fatalf("failure not reported: %v", err)
	}
	broken := recipeResults(t, ctx, scope, "shop-db/broken")
	if len(broken) != 2 || broken[1].Target != "b" || broken[1].Status != "failed" || broken[1].ExitCode != 7 {
		t.Fatalf("failed run results: %+v", broken)
	}

	// Env input: the value reaches the environment under the mapped name.
	envRecipe := RecipeOpts{Name: "shop-db/env", Scope: scope, Command: []string{"/bin/sh", "-c", `printf %s "$PGPASSWORD" > "$RECIPE_OUT/env"`},
		Fields: []string{"db-password=PGPASSWORD"}, Input: "env"}
	if err := RunRecipeAdd(ctx, envRecipe, false); err != nil {
		t.Fatal(err)
	}
	if err := approveRecipe(ctx, scope, "shop-db/env", recipeDigest(t, ctx, scope, "shop-db/env"), goodAuth()); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db/env"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "env")); string(got) != "second-value" {
		t.Fatalf("env input: %q", got)
	}

	// Revocation stops the recipe again.
	if err := RunRecipeRevoke(ctx, "", "shop-db/env"); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "shop-db/env"}); err == nil {
		t.Fatal("revoked recipe ran")
	}

	// Name spaces and dependent operations are guarded.
	if err := RunSecretRemove(ctx, scope, "recipe:shop-db/env", true); err == nil || !strings.Contains(err.Error(), "is a recipe") {
		t.Fatalf("plain secret command reached a recipe: %v", err)
	}
	if err := RunServiceRename(ctx, scope, "shop-db", "shop-db-2", false); err == nil || !strings.Contains(err.Error(), "has recipes") {
		t.Fatalf("rename orphaned recipes: %v", err)
	}
	if err := RunRecipeAdd(ctx, RecipeOpts{Name: "missing/x", Scope: scope, Command: write, Fields: []string{"a"}, Input: "env"}, false); err == nil {
		t.Fatal("recipe for a missing service accepted")
	}
	if err := RunRecipeAdd(ctx, RecipeOpts{Name: "shop-db/bad", Scope: scope, Command: write, Fields: []string{"nope"}, Input: "env"}, false); err == nil {
		t.Fatal("recipe for a missing field accepted")
	}
}

func goodAuth() *agent.UnlockReq {
	return &agent.UnlockReq{MethodType: proto.AuthPassphrase, Passphrase: []byte("correct horse battery staple")}
}

func recipeDigest(t *testing.T, ctx context.Context, scope, name string) string {
	t.Helper()
	s, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	serviceName, _, _ := strings.Cut(name, "/")
	entries, err := loadRecipes(s, scope, serviceName)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == name {
			return e.Digest
		}
	}
	t.Fatalf("recipe %s not found", name)
	return ""
}

func recipeResults(t *testing.T, ctx context.Context, scope, name string) []recipe.Result {
	t.Helper()
	s, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err := loadResults(s, scope, name)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// TestRecipeReviewGuards covers the review findings: env names are pinned in
// the recipe, an unusable recipe blocks a deploy, one deploy runs at a time,
// and forged results are ignored.
func TestRecipeReviewGuards(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	saved := deploySync
	deploySync = func(context.Context) error { return nil }
	t.Cleanup(func() { deploySync = saved })
	out := filepath.Join(dir, "env-out")
	t.Setenv("RECIPE_OUT", out)
	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "app", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	var err error
	withStdio(t, dir, "token-value", func() {
		err = RunServiceSet(ctx, ServiceSetOpts{Name: "app", Scope: scope, Field: "token", Env: "APP_TOKEN"})
	})
	if err != nil {
		t.Fatal(err)
	}
	// The env name is copied into the recipe at creation.
	r := RecipeOpts{Name: "app/env", Scope: scope, Command: []string{"/bin/sh", "-c", `env | grep -E '^(APP_TOKEN|LD_PRELOAD)=' > "$RECIPE_OUT"`},
		Fields: []string{"token"}, Input: "env"}
	if err := RunRecipeAdd(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	if err := approveRecipe(ctx, scope, "app/env", recipeDigest(t, ctx, scope, "app/env"), goodAuth()); err != nil {
		t.Fatal(err)
	}
	// A later change of the field's env name in the service does not change
	// what the approved recipe passes.
	withStdio(t, dir, "token-value", func() {
		err = RunServiceSet(ctx, ServiceSetOpts{Name: "app", Scope: scope, Field: "token", Env: "LD_PRELOAD"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "app/env"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "APP_TOKEN=token-value\n" {
		t.Fatalf("env after service rename: %q", got)
	}
	if err := RunRecipeAdd(ctx, RecipeOpts{Name: "app/reserved", Scope: scope, Command: r.Command, Fields: []string{"token=FD0_TARGET"}, Input: "env"}, false); err == nil {
		t.Fatal("reserved variable accepted")
	}

	// Only one deploy at a time on a device.
	unlock, err := lockDeploys()
	if err != nil {
		t.Fatal(err)
	}
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "app/env"}); err == nil || !strings.Contains(err.Error(), "another fd0 service deploy") {
		t.Fatalf("concurrent deploy: %v", err)
	}
	unlock()

	// An unusable recipe in the selection stops the whole deploy.
	s, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTypedSecret(ctx, scope, recipeNamePrefix+"app/broken", "kv.other", map[string]any{"version": 1}); err != nil {
		t.Fatal(err)
	}
	// A forged result naming another device is ignored.
	forged := map[string]any{"recipe": "app/env", "target": "", "device": "someone-else", "status": "ok", "at": "2030-01-01T00:00:00Z"}
	if err := s.CreateTypedSecret(ctx, scope, resultNamePrefix+"app/env/-/my-device", "fd0.deploy-result", forged); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := RunServiceDeploy(ctx, DeployOpts{Name: "app"}); err == nil || !strings.Contains(err.Error(), "app/broken cannot be used") {
		t.Fatalf("unusable recipe skipped: %v", err)
	}
	for _, res := range recipeResults(t, ctx, scope, "app/env") {
		if res.Device == "someone-else" {
			t.Fatal("forged result shown")
		}
	}
	if err := RunServiceRename(ctx, scope, "app", "app-2", false); err == nil {
		t.Fatal("rename ignored an unusable recipe")
	}
}
