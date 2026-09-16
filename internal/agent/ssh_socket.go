package agent

// SSH-agent socket integration. fd0-agent serves the standard
// ssh-agent protocol on a second Unix socket (XDG_RUNTIME_DIR by
// default; see internal/sshagent.DefaultSocketPath) so any ssh
// client (ssh, scp, git, ...) can transparently use keys held in the
// fd0 vault.
//
// Trust model:
//   - Vault must be unlocked to enumerate or sign; locked vault
//     returns the empty identity list (industry-standard "no
//     identities" — ssh client tries the next method).
//   - No per-sign approval prompt. Vault unlock is the consent.
//   - Sign + List only (Bitwarden minimalism); add/remove/lock at
//     the protocol level are explicitly refused.
//
// Concurrent operations share only an in-flight fetch. Completed snapshots are
// not cached, so later requests observe key additions, edits, removal and sync.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sync/singleflight"
)

// SSHKeyFetcher is what the agent uses to enumerate available SSH
// keys. The concrete implementation lives in cmd/fd0-agent so it can
// import cli.CollectKeyEntries without the agent package taking a cli
// dependency (which would be a cycle).
type SSHKeyFetcher func(context.Context) ([]sshagent.KeyEntry, error)

// liveSSHProvider is shared by every connection on a socket. The server mutex
// is never held during a fetch (which calls back into the agent over IPC).
type liveSSHProvider struct {
	ctx     context.Context
	server  *Server
	fetcher SSHKeyFetcher
	flights singleflight.Group
}

func (p *liveSSHProvider) WithKeys(use func([]sshagent.KeyEntry) error) error {
	ctx, cancel := context.WithTimeout(p.ctx, time.Minute)
	defer cancel()
	s := p.server
	s.mu.Lock()
	epoch := s.unlockSession
	s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.Lock()
		s.expireUnlockedHeld(time.Now())
		if s.superPriv == nil || s.unlockSession != epoch {
			defer s.mu.Unlock()
			return use(nil)
		}
		revision := s.sshRevision
		// New sessions and committed writes must not join an older snapshot.
		result := p.flights.DoChan(fmt.Sprintf("%s/%d", epoch, revision), func() (any, error) {
			fetchCtx, stop := context.WithTimeout(p.ctx, time.Minute)
			defer stop()
			return p.fetcher(fetchCtx)
		})
		s.mu.Unlock()
		var fetched singleflight.Result
		select {
		case fetched = <-result:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		s.expireUnlockedHeld(time.Now())
		if s.superPriv == nil || s.unlockSession != epoch {
			defer s.mu.Unlock()
			return use(nil)
		}
		if s.sshRevision != revision {
			s.mu.Unlock()
			continue // A writer committed during fetch; read its new state.
		}
		defer s.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		if fetched.Err != nil {
			return errors.New("ssh-agent: key fetch failed")
		}
		keys := fetched.Val.([]sshagent.KeyEntry)
		// Key use, committed writes and lock have one ordering. Slow file/IPC
		// work is outside this mutex and never delays vault lock.
		if err := use(keys); err != nil {
			return err
		}
		s.lastActivity = time.Now()
		s.signalLifecycle()
		return nil
	}
}

// StartSSHSocket launches the SSH-agent socket listener. Overlapping requests
// in one unlock session share a fetch; different unlock sessions may overlap.
// The fetcher must honor cancellation and be safe for concurrent calls.
func (s *Server) StartSSHSocket(ctx context.Context, log *slog.Logger, socketPath string, fetcher SSHKeyFetcher) (func(), error) {
	l, err := sshagent.Listen(socketPath)
	if err != nil {
		return nil, err
	}
	log.Info("ssh-agent socket listening", "sock", socketPath)
	provider := &liveSSHProvider{ctx: ctx, server: s, fetcher: fetcher}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Warn("ssh-agent accept", "err", err)
				continue
			}
			go handleSSHConn(log, conn, provider)
		}
	}()
	stop := func() {
		_ = l.Close()
		wg.Wait()
	}
	return stop, nil
}

// handleSSHConn never captures signing material for a connection's lifetime.
func handleSSHConn(log *slog.Logger, conn net.Conn, provider sshagent.KeyProvider) {
	defer conn.Close()
	a := sshagent.New(provider)
	if err := agent.ServeAgent(a, conn); err != nil {
		log.Debug("ssh-agent: serve finished", "err", err)
	}
}
