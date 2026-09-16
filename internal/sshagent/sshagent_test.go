package sshagent

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh/agent"
)

// staticProvider is a KeyProvider that returns a fixed list, useful
// for unit testing the agent without standing up a vault.
type staticProvider struct {
	keys []KeyEntry
}

func (s *staticProvider) WithKeys(use func([]KeyEntry) error) error { return use(s.keys) }

func TestListAndSignViaSocket(t *testing.T) {
	// Two ed25519 keys.
	k1, err := sshkey.NewEd25519("first", "first@host")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := sshkey.NewEd25519("second", "second@host")
	if err != nil {
		t.Fatal(err)
	}
	src := &staticProvider{keys: []KeyEntry{
		{Key: k1, Comment: k1.Comment},
		{Key: k2, Comment: k2.Comment},
	}}

	sock := filepath.Join(t.TempDir(), "ssh.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	a := New(src)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(a, conn)
		}
	}()

	// Connect a client over the socket; verify List + Sign.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := agent.NewClient(c)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("client List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].Comment != "first@host" {
		t.Errorf("comment[0]=%q", keys[0].Comment)
	}

	// Sign a challenge with k1; verify with k1's pubkey.
	pub1, _ := k1.PublicKey()
	msg := []byte("hello agent")
	sig, err := client.Sign(pub1, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := pub1.Verify(msg, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestEmptyProvider(t *testing.T) {
	src := &staticProvider{keys: nil}
	a := New(src)
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty list, got %d", len(keys))
	}
}

func TestMutatingMethodsRefused(t *testing.T) {
	src := &staticProvider{keys: nil}
	a := New(src)
	if err := a.Add(agent.AddedKey{}); err == nil || !strings.Contains(err.Error(), "Add not supported") {
		t.Errorf("Add: %v", err)
	}
	if err := a.RemoveAll(); err == nil || !strings.Contains(err.Error(), "RemoveAll not supported") {
		t.Errorf("RemoveAll: %v", err)
	}
	if err := a.Lock([]byte{}); err == nil {
		t.Errorf("Lock should be refused")
	}
	if err := a.Unlock([]byte{}); err == nil {
		t.Errorf("Unlock should be refused")
	}
}

func TestDefaultSocketPath(t *testing.T) {
	p := DefaultSocketPath()
	if !strings.Contains(p, "ssh-") || !strings.HasSuffix(p, ".sock") {
		t.Errorf("DefaultSocketPath = %q", p)
	}
}

func TestDefaultSocketPathIsolatesCustomFD0Home(t *testing.T) {
	t.Setenv("FD0_HOME", filepath.Join(t.TempDir(), "one"))
	one := DefaultSocketPath()
	t.Setenv("FD0_HOME", filepath.Join(t.TempDir(), "two"))
	two := DefaultSocketPath()
	if one == two {
		t.Fatalf("custom FD0_HOME values should get distinct SSH sockets: %q", one)
	}
	if !strings.HasSuffix(one, ".sock") || !strings.HasSuffix(two, ".sock") {
		t.Fatalf("socket paths must keep .sock suffix: %q %q", one, two)
	}
}

func TestEnsureSocketDirRemovesStale(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "subdir", "ssh.sock")
	// Pre-create a fake file at the target path.
	_ = EnsureSocketDir(sock)
	// Manually drop a file there.
	_, _ = net.Listen("unix", sock)
	// Second EnsureSocketDir should clean it up.
	if err := EnsureSocketDir(sock); err != nil {
		t.Fatalf("second EnsureSocketDir: %v", err)
	}
}

type failingProvider struct{}

func (failingProvider) WithKeys(func([]KeyEntry) error) error {
	return errors.New("PRIVATE_ERROR_CANARY")
}

func TestProviderFailuresAreNotEmptySuccessOrSecretLogs(t *testing.T) {
	a := New(failingProvider{})
	key, err := sshkey.NewEd25519("synthetic", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.PublicKey()
	_, listErr := a.List()
	_, signErr := a.Sign(pub, []byte("challenge"))
	_, signersErr := a.Signers()
	for _, err := range []error{listErr, signErr, signersErr} {
		if err == nil {
			t.Fatal("provider failure swallowed")
		}
		if strings.Contains(err.Error(), "PRIVATE_ERROR_CANARY") {
			t.Fatal("provider details reached protocol logging")
		}
	}
}
