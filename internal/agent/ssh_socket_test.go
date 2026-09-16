package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	fd0sshagent "github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh/agent"
)

func TestExistingSSHConnectionLosesSigningAuthorityAfterLock(t *testing.T) {
	key, err := sshkey.NewEd25519("live-lock", "live-lock@fd0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLifecycleTestServer(t, time.Hour, time.Hour)
	fetcher := func(context.Context) ([]fd0sshagent.KeyEntry, error) {
		if !srv.handleStatus().Status.Unlocked {
			return nil, nil
		}
		return []fd0sshagent.KeyEntry{{Key: key, Comment: key.Comment}}, nil
	}

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleSSHConn(
			slog.New(slog.NewTextHandler(io.Discard, nil)),
			serverConn,
			&liveSSHProvider{ctx: context.Background(), server: srv, fetcher: fetcher},
		)
		close(done)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		<-done
	})

	client := agent.NewClient(clientConn)
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys before lock = %d, want 1", len(keys))
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(pub, []byte("before lock")); err != nil {
		t.Fatalf("sign before lock: %v", err)
	}

	srv.lock()
	keys, err = client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys after lock = %d, want 0", len(keys))
	}
	if _, err := client.Sign(pub, []byte("after lock")); err == nil {
		t.Fatal("existing SSH connection retained signing authority after lock")
	}
}
