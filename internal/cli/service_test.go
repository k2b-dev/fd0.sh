package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serviceTestEnv isolates HOME and agent state; nothing touches the installed
// client or a server.
func serviceTestEnv(t *testing.T) string {
	t.Helper()
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	return isolation
}

// withStdio replaces stdin with data and stdout with a file for one call.
func withStdio(t *testing.T, dir, stdin string, fn func()) string {
	t.Helper()
	in := filepath.Join(dir, "stdin")
	if err := os.WriteFile(in, []byte(stdin), 0o600); err != nil {
		t.Fatal(err)
	}
	inFile, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer inFile.Close()
	out := filepath.Join(dir, "stdout")
	outFile, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	savedIn, savedOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inFile, outFile
	fn()
	os.Stdin, os.Stdout = savedIn, savedOut
	_ = outFile.Close()
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestServiceLifecycle(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "pg-1", Scope: scope, Description: "database", Tags: []string{"postgres"}}); err != nil {
		t.Fatal(err)
	}
	set := func(o ServiceSetOpts, stdin string) error {
		var err error
		withStdio(t, dir, stdin, func() { err = RunServiceSet(ctx, o) })
		return err
	}
	if err := set(ServiceSetOpts{Name: "pg-1", Scope: scope, Field: "postgres-password", Env: "POSTGRES_PASSWORD"}, "synthetic one\n"); err != nil {
		t.Fatal(err)
	}
	if err := set(ServiceSetOpts{Name: "pg-1", Scope: scope, Field: "postgres-password"}, ""); err == nil {
		t.Fatal("empty stdin overwrote a value")
	}
	if err := set(ServiceSetOpts{Name: "pg-1", Scope: scope, Field: "postgres-password", Type: "text"}, "x"); err == nil {
		t.Fatal("type change accepted")
	}
	if err := set(ServiceSetOpts{Name: "pg-1", Scope: scope, EnvFile: true}, "PG_HOST=db.internal\nPG_REPLICATION_PASSWORD='synthetic two'\n"); err != nil {
		t.Fatal(err)
	}
	if err := set(ServiceSetOpts{Name: "pg-1", Scope: scope, Field: "ca.crt", Type: "file"}, "-----BEGIN-----\n"); err != nil {
		t.Fatal(err)
	}

	got := withStdio(t, dir, "", func() {
		if err := RunServiceGet(ctx, scope, "pg-1", "postgres-password", true); err != nil {
			t.Fatal(err)
		}
	})
	if got != "synthetic one" {
		t.Fatalf("get: %q", got)
	}
	env := withStdio(t, dir, "", func() {
		if err := RunServiceEnv(ctx, scope, "pg-1", nil, "sh"); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"export POSTGRES_PASSWORD='synthetic one'", "export PG_REPLICATION_PASSWORD='synthetic two'", "export PG_HOST='db.internal'"} {
		if !strings.Contains(env, want) {
			t.Fatalf("env missing %q:\n%s", want, env)
		}
	}
	manifest := withStdio(t, dir, "", func() {
		if err := RunServiceK8sSecret(ctx, scope, "pg-1", "org-app", "app-runtime", []string{"postgres-password=DATABASE_PASSWORD", "ca.crt"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(manifest, "DATABASE_PASSWORD: ") || !strings.Contains(manifest, "ca.crt: ") {
		t.Fatalf("manifest:\n%s", manifest)
	}
	show := withStdio(t, dir, "", func() {
		if err := RunServiceShow(ctx, scope, "pg-1", true); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(show, "synthetic") {
		t.Fatalf("show --json leaked a value: %s", show)
	}
	var shown serviceShowJSON
	if err := json.Unmarshal([]byte(show), &shown); err != nil || len(shown.Fields) != 4 || len(shown.Tags) != 1 {
		t.Fatalf("show: %s %v", show, err)
	}

	if err := guardPlainSecret("get", "service:pg-1"); err == nil || !strings.Contains(err.Error(), "fd0 service") {
		t.Fatalf("plain secret commands reach services: %v", err)
	}
	if err := RunServiceRename(ctx, scope, "pg-1", "pg-main", false); err != nil {
		t.Fatal(err)
	}
	if err := RunServiceMove(ctx, "pg-main", scope, "other", false); err != nil {
		t.Fatal(err)
	}
	got = withStdio(t, dir, "", func() {
		if err := RunServiceGet(ctx, "other", "pg-main", "postgres-password", true); err != nil {
			t.Fatal(err)
		}
	})
	if got != "synthetic one" {
		t.Fatalf("value after rename and move: %q", got)
	}
	if err := RunServiceRemove(ctx, "other", "pg-main", true); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRestoreRestampsFields(t *testing.T) {
	dir := serviceTestEnv(t)
	ctx, scope := newTestVault(t)
	if err := RunServiceAdd(ctx, ServiceAddOpts{Name: "api", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"old", "new"} {
		var err error
		withStdio(t, dir, v, func() { err = RunServiceSet(ctx, ServiceSetOpts{Name: "api", Scope: scope, Field: "token"}) })
		if err != nil {
			t.Fatal(err)
		}
	}
	var seq uint64
	withSession(t, ctx, func(s *Session) {
		history, err := s.SecretHistory(scope, serviceNamePrefix+"api")
		if err != nil || len(history) < 3 {
			t.Fatalf("history: %v %d", err, len(history))
		}
		seq = history[1].Seq
	})
	if err := RunServiceRestore(ctx, scope, "api", seq); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		rec, err := s.GetTypedSecret(scope, serviceNamePrefix+"api")
		if err != nil {
			t.Fatal(err)
		}
		svc, err := decodeServiceRecord(*rec)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := svc.Field("token")
		if f.Value != "old" || f.Revision < 2 {
			t.Fatalf("restored field: %+v", f)
		}
	})
}
