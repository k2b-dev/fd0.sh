package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	fd0ssh "github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	sshwire "golang.org/x/crypto/ssh/agent"
)

func sshTestClient(t *testing.T, p *liveSSHProvider) sshwire.ExtendedAgent {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { handleSSHConn(p.server.log, server, p); close(done) }()
	t.Cleanup(func() { client.Close(); <-done })
	client.SetDeadline(time.Now().Add(10 * time.Second))
	return sshwire.NewClient(client)
}

func TestSSHConcurrentListAndSignShareFetch(t *testing.T) {
	srv := newLifecycleTestServer(t, time.Hour, time.Hour)
	key, err := sshkey.NewEd25519("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.PublicKey()
	var calls atomic.Int32
	p := &liveSSHProvider{ctx: context.Background(), server: srv, fetcher: func(context.Context) ([]fd0ssh.KeyEntry, error) {
		calls.Add(1)
		// Model a slow replay. Every connection is already open before the burst.
		time.Sleep(150 * time.Millisecond)
		return []fd0ssh.KeyEntry{{Key: key}}, nil
	}}
	const n = 32
	clients := make([]sshwire.ExtendedAgent, n)
	for i := range clients {
		clients[i] = sshTestClient(t, p)
	}
	start := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				ks, e := c.List()
				if e == nil && len(ks) != 1 {
					e = fmt.Errorf("got %d keys", len(ks))
				}
				errs <- e
				return
			}
			msg := []byte("concurrent challenge")
			sig, e := c.Sign(pub, msg)
			if e == nil {
				e = pub.Verify(msg, sig)
			}
			errs <- e
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if got := calls.Load(); got >= n/2 {
		t.Fatalf("fetch was not coalesced: %d fetches", got)
	}
}

func TestSSHFetchCannotOutliveAuthorization(t *testing.T) {
	for _, transition := range []string{"lock", "idle expiry", "max expiry", "reunlock"} {
		t.Run(transition, func(t *testing.T) {
			srv := newLifecycleTestServer(t, time.Hour, time.Hour)
			srv.unlockSession = "original"
			key, _ := sshkey.NewEd25519("test", "test")
			pub, _ := key.PublicKey()
			entered, release := make(chan struct{}), make(chan struct{})
			p := &liveSSHProvider{ctx: context.Background(), server: srv, fetcher: func(context.Context) ([]fd0ssh.KeyEntry, error) {
				close(entered)
				<-release
				return []fd0ssh.KeyEntry{{Key: key}}, nil
			}}
			c := sshTestClient(t, p)
			result := make(chan error, 1)
			go func() { _, err := c.Sign(pub, []byte("must not sign")); result <- err }()
			<-entered
			switch transition {
			case "lock":
				srv.lock()
			case "idle expiry":
				srv.mu.Lock()
				srv.lastActivity = time.Now().Add(-2 * time.Hour)
				srv.mu.Unlock()
			case "max expiry":
				srv.mu.Lock()
				srv.unlockedAt = time.Now().Add(-2 * time.Hour)
				srv.mu.Unlock()
			case "reunlock":
				srv.lock()
				srv.mu.Lock()
				srv.superPriv = crypto.NewSecretCopy(make([]byte, 64))
				srv.unlockSession = "new"
				srv.unlockedAt = time.Now()
				srv.lastActivity = time.Now()
				srv.mu.Unlock()
			}
			close(release)
			if err := <-result; err == nil {
				t.Fatal("signed after authorization changed")
			}
		})
	}
}

func TestSSHFetchErrorsAndKeyChanges(t *testing.T) {
	srv := newLifecycleTestServer(t, time.Hour, time.Hour)
	key, _ := sshkey.NewEd25519("test", "test")
	var keys []fd0ssh.KeyEntry
	failure := errors.New("PRIVATE_CANARY_DO_NOT_LOG")
	p := &liveSSHProvider{ctx: context.Background(), server: srv, fetcher: func(context.Context) ([]fd0ssh.KeyEntry, error) { return keys, failure }}
	c := sshTestClient(t, p)
	if _, err := c.List(); err == nil {
		t.Fatal("fetch error became empty success")
	}
	failure = nil
	keys = []fd0ssh.KeyEntry{{Key: key}}
	if got, err := c.List(); err != nil || len(got) != 1 {
		t.Fatalf("recovery: %d %v", len(got), err)
	}
	// A completed fetch is not reused. Deletion affects already open connections.
	keys = nil
	if got, err := c.List(); err != nil || len(got) != 0 {
		t.Fatalf("deletion: %d %v", len(got), err)
	}
	pub, _ := key.PublicKey()
	if _, err := c.Sign(pub, []byte("deleted")); err == nil {
		t.Fatal("deleted key signed")
	}
	keys = []fd0ssh.KeyEntry{{Key: key}}
	a := fd0ssh.New(p)
	signers, err := a.Signers()
	if err != nil || len(signers) != 1 {
		t.Fatal("signers", err)
	}
	srv.lock()
	if _, err := signers[0].Sign(nil, []byte("locked")); err == nil {
		t.Fatal("exported signer survived lock")
	}
}

func TestSSHShutdownCancelsFetch(t *testing.T) {
	srv := newLifecycleTestServer(t, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	p := &liveSSHProvider{ctx: ctx, server: srv, fetcher: func(ctx context.Context) ([]fd0ssh.KeyEntry, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		done <- p.WithKeys(func([]fd0ssh.KeyEntry) error { t.Error("used keys after cancellation"); return nil })
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation swallowed")
		}
	case <-time.After(time.Second):
		t.Fatal("fetch did not cancel")
	}
}

func TestSSHCommittedWriteDuringFetchDiscardsSnapshot(t *testing.T) {
	srv := newLifecycleTestServer(t, time.Hour, time.Hour)
	key, _ := sshkey.NewEd25519("old", "old")
	pub, _ := key.PublicKey()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p := &liveSSHProvider{ctx: context.Background(), server: srv, fetcher: func(context.Context) ([]fd0ssh.KeyEntry, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return []fd0ssh.KeyEntry{{Key: key}}, nil
		}
		return nil, nil // The committed write removed the key.
	}}
	c := sshTestClient(t, p)
	done := make(chan error, 1)
	go func() { _, err := c.Sign(pub, []byte("deleted during fetch")); done <- err }()
	<-entered
	srv.mu.Lock()
	srv.sshRevision++
	srv.mu.Unlock()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("signed with a snapshot predating a committed write")
	}
	if calls.Load() != 2 {
		t.Fatalf("want fresh fetch after write, got %d", calls.Load())
	}
}
