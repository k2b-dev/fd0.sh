package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPassFieldSetKeepsTypeAndRejectsEmptyStdin(t *testing.T) {
	// In-process agent and test vault only; no installed binary or server.
	isolation := shortTempDir(t)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx, scope := newTestVault(t)
	if err := RunPassAdd(ctx, PassAddOpts{Name: "Login", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	set := func(o PassFieldSetOpts) error {
		o.Item, o.Scope, o.Path = "Login", scope, "password"
		return RunPassFieldSet(ctx, o)
	}
	fieldType := func() string {
		t.Helper()
		var typ string
		withSession(t, ctx, func(s *Session) {
			record, err := s.GetTypedSecret(scope, "pass:Login")
			if err != nil {
				t.Fatal(err)
			}
			item, err := decodePassRecord(*record)
			if err != nil {
				t.Fatal(err)
			}
			f, err := item.Field("password")
			if err != nil {
				t.Fatal(err)
			}
			typ = f.Type
		})
		return typ
	}

	if err := set(PassFieldSetOpts{Value: "synthetic-1", Secret: true}); err != nil {
		t.Fatal(err)
	}
	if err := set(PassFieldSetOpts{Value: "synthetic-2"}); err != nil {
		t.Fatal(err)
	}
	if got := fieldType(); got != "secret" {
		t.Fatalf("rotation without --type changed the field to %q", got)
	}

	stdin := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(stdin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	saved := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = saved })
	if err := set(PassFieldSetOpts{Value: "-"}); err == nil {
		t.Fatal("empty stdin overwrote the stored value")
	}

	if err := set(PassFieldSetOpts{Value: "synthetic-3", Kind: "text"}); err != nil {
		t.Fatal(err)
	}
	if got := fieldType(); got != "text" {
		t.Fatalf("explicit --type text was ignored: %q", got)
	}
}
