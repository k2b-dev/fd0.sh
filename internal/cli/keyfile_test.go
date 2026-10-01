package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

const testMachineKey = "c3ludGhldGljLW1hY2hpbmUta2V5LWZvci10ZXN0cy0wMDE=" // 48 chars, synthetic

func writeKeyFile(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "fd0.key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadKeyFileContract(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testMachineKey+"\n", 0o600)
	key, err := ReadKeyFile(path)
	if err != nil || string(key) != testMachineKey {
		t.Fatalf("read: %q %v", key, err)
	}
	if _, err := ReadKeyFile(writeKeyFile(t, t.TempDir(), testMachineKey, 0o640)); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("group-readable key accepted: %v", err)
	}
	if _, err := ReadKeyFile(writeKeyFile(t, t.TempDir(), "short", 0o600)); err == nil {
		t.Fatal("short key accepted")
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink accepted: %v", err)
	}
	if _, err := ReadKeyFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	big := writeKeyFile(t, t.TempDir(), strings.Repeat("a", keyFileMaxBytes+1), 0o600)
	if _, err := ReadKeyFile(big); err == nil {
		t.Fatal("oversized key accepted")
	}
	if key, err := ReadKeyFile(writeKeyFile(t, t.TempDir(), strings.Repeat("a", keyFileMaxBytes), 0o600)); err != nil || len(key) != keyFileMaxBytes {
		t.Fatalf("maximum size rejected: %v", err)
	}
	if key, err := ReadKeyFile(writeKeyFile(t, t.TempDir(), strings.Repeat("b", keyFileMinChars)+"\r\n", 0o600)); err != nil || len(key) != keyFileMinChars {
		t.Fatalf("CRLF or minimum length: %q %v", key, err)
	}
	if _, err := ReadKeyFile(writeKeyFile(t, t.TempDir(), strings.Repeat("b", keyFileMinChars-1)+"\n", 0o600)); err == nil {
		t.Fatal("31-byte key accepted")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadKeyFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	stdin := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(stdin, []byte(testMachineKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = f
	key, err = ReadKeyFile("-")
	os.Stdin = saved
	_ = f.Close()
	if err != nil || string(key) != testMachineKey {
		t.Fatalf("stdin: %q %v", key, err)
	}
}

func TestKeyFileInitAndUnlockWithoutPrompt(t *testing.T) {
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_HOME", filepath.Join(isolation, "machine"))
	t.Setenv("FD0_SSH_SOCK", "") // in-process agent serves no SSH socket
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx := context.Background()
	keyPath := writeKeyFile(t, isolation, testMachineKey+"\n", 0o400)
	if err := RunInit(ctx, keyPath); err != nil {
		t.Fatal(err)
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	server, err := agent.Listen(paths, agent.Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	go func() { _ = server.Serve(serveCtx) }()
	t.Cleanup(func() { cancel(); server.Close() })
	client := agent.NewClient(paths.AgentSock)
	if !waitAgentReady(client) {
		t.Fatal("agent did not become ready")
	}
	unlocked := func() bool {
		st, err := client.Status()
		return err == nil && st.Unlocked
	}
	if err := RunUnlock(ctx, "", "", keyPath); err != nil || !unlocked() {
		t.Fatalf("key-file unlock: %v", err)
	}
	// Idempotent for jobs that call it every run, without reading the key.
	if err := RunUnlock(ctx, "", "", filepath.Join(isolation, "missing.key")); err != nil {
		t.Fatalf("unlocked agent needed the key file: %v", err)
	}
	if err := RunLock(ctx); err != nil {
		t.Fatal(err)
	}
	wrong := writeKeyFile(t, t.TempDir(), strings.Repeat("x", 48), 0o600)
	if err := RunUnlock(ctx, "", "", wrong); err == nil || unlocked() {
		t.Fatal("wrong key unlocked the vault")
	}
	if err := RunUnlock(ctx, "", "yubikey", keyPath); err == nil {
		t.Fatal("key file combined with --method yubikey")
	}
	if err := RunUnlock(ctx, "", "", keyPath); err != nil || !unlocked() {
		t.Fatalf("unlock after lock: %v", err)
	}
}

func TestServerPinFormatAndMatch(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []string{"12345 67890", strings.Repeat("12345 ", 12) + "x"} {
		if _, err := WithServerPin(ctx, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	real, err := ServerFingerprint("https://example.invalid", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := WithServerPin(ctx, real)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkExpectedFingerprint(serverPinFrom(pinned), "https://example.invalid", make([]byte, 32)); err != nil {
		t.Fatalf("matching safety number rejected: %v", err)
	}
	other := make([]byte, 32)
	other[0] = 1
	if err := checkExpectedFingerprint(serverPinFrom(pinned), "https://example.invalid", other); err != ErrServerPinMismatch {
		t.Fatalf("different key accepted: %v", err)
	}
	if serverPinFrom(ctx) != "" {
		t.Fatal("pin leaked into an unrelated context")
	}
}

func TestExplicitMethodIDMustBeTheOneThatUnlocks(t *testing.T) {
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_HOME", filepath.Join(isolation, "machine"))
	t.Setenv("FD0_SSH_SOCK", "")
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx := context.Background()
	first := writeKeyFile(t, isolation, testMachineKey, 0o600)
	secondKey := strings.Repeat("s", 40)
	second := writeKeyFile(t, t.TempDir(), secondKey, 0o600)
	if err := RunInit(ctx, first); err != nil {
		t.Fatal(err)
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	server, err := agent.Listen(paths, agent.Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	go func() { _ = server.Serve(serveCtx) }()
	t.Cleanup(func() { cancel(); server.Close() })
	if !waitAgentReady(agent.NewClient(paths.AgentSock)) {
		t.Fatal("agent did not become ready")
	}
	if err := RunUnlock(ctx, "", "", first); err != nil {
		t.Fatal(err)
	}
	stdin := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(stdin, []byte(secondKey+"\n"+secondKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = f
	err = RunAuthAdd(ctx)
	os.Stdin = saved
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	uctx, err := chain.ReplayUser(paths.UserChain)
	if err != nil || uctx == nil || len(uctx.LatestAuthSet.Payload.Active) != 2 {
		t.Fatalf("auth methods: %v", err)
	}
	firstID := uctx.LatestAuthSet.Payload.Active[0].MethodID
	secondID := uctx.LatestAuthSet.Payload.Active[1].MethodID
	if err := RunLock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RunUnlock(ctx, "", firstID, second); err == nil {
		t.Fatal("the second method's key unlocked although the first was requested")
	}
	if err := RunUnlock(ctx, "", secondID, second); err != nil {
		t.Fatalf("matching method and key: %v", err)
	}
}
