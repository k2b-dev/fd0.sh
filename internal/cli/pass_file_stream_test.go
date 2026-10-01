package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPassFileStreamsThroughStdinAndStdout(t *testing.T) {
	// In-process agent and test vault only.
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx, scope := newTestVault(t)
	if err := RunPassAdd(ctx, PassAddOpts{Name: "Broker", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	creds := []byte("-----BEGIN NATS USER JWT-----\nsynthetic\n------END NATS USER JWT------\n")
	in := filepath.Join(isolation, "in")
	if err := os.WriteFile(in, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	out := filepath.Join(isolation, "out")
	stdout, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	savedIn, savedOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdin, stdout
	t.Cleanup(func() { os.Stdin, os.Stdout = savedIn, savedOut })

	if err := RunPassFileAdd(ctx, PassFileAddOpts{Item: "Broker", Scope: scope, File: "-"}); err == nil {
		t.Fatal("stdin upload without PATH was accepted")
	}
	if err := RunPassFileAdd(ctx, PassFileAddOpts{Item: "Broker", Scope: scope, File: "-", Path: "Credentials/runtime.creds"}); err != nil {
		t.Fatal(err)
	}
	if err := RunPassFileExport(ctx, scope, "Broker", "Credentials/runtime.creds", "-", false); err != nil {
		t.Fatal(err)
	}
	_ = stdout.Close()
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(creds) {
		t.Fatalf("round trip changed the file: %q", got)
	}
}
