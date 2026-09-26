package cli

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh"
	sshwire "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSSHGrantsFreshAuthenticationLockRestartAndRevocation(t *testing.T) {
	ctx, scope, server := newTestVaultWithAgent(t)
	home := shortTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(home, "ssh", "fd0.conf"))
	socket := filepath.Join(home, "ssh.sock")
	t.Setenv("FD0_SSH_SOCK", socket)
	paths, _ := fdhome.Resolve()
	client := agent.NewClient(paths.AgentSock)
	if err := RunHostAdd(ctx, HostAddOpts{Alias: "granted", Hostname: "server.example.test", User: "admin", WithKey: true, Scope: scope}); err != nil {
		t.Fatal(err)
	}
	hostKey, _ := sshkey.NewEd25519("server", "")
	hostSigner, _ := hostKey.Signer()
	known := filepath.Join(home, "known_hosts")
	os.WriteFile(known, []byte(knownhosts.Line([]string{"server.example.test"}, hostSigner.PublicKey())+"\n"), 0600)
	req := agent.SSHGrantReq{Action: "prepare", ScopeID: scope, Name: "granted", KnownHosts: known}
	preview, err := ManageSSHGrant(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Action = "create"
	req.Digest = preview.Digest
	if _, err := ManageSSHGrant(ctx, req); err == nil {
		t.Fatal("unlocked session created grant without authentication")
	}
	req.Authentication = &agent.UnlockReq{MethodType: proto.AuthPassphrase, Passphrase: []byte("wrong")}
	if _, err := ManageSSHGrant(ctx, req); err == nil {
		t.Fatal("wrong passphrase created grant")
	}
	req.Authentication.Passphrase = []byte("correct horse battery staple")
	req.Digest = strings.Repeat("0", 64)
	if _, err := ManageSSHGrant(ctx, req); err == nil {
		t.Fatal("unreviewed grant accepted")
	}
	req.Digest = preview.Digest
	// Changing the trusted server after review must require a new preview.
	otherHost, _ := sshkey.NewEd25519("other-server", "")
	otherPublic, _ := otherHost.PublicKey()
	os.WriteFile(known, []byte(knownhosts.Line([]string{"server.example.test"}, otherPublic)+"\n"), 0600)
	req.Authentication.Passphrase = []byte("correct horse battery staple")
	if _, err := ManageSSHGrant(ctx, req); err == nil {
		t.Fatal("changed server key accepted with stale preview")
	}
	os.WriteFile(known, []byte(knownhosts.Line([]string{"server.example.test"}, hostSigner.PublicKey())+"\n"), 0600)
	req.Authentication.Passphrase = []byte("correct horse battery staple")
	granted, err := ManageSSHGrant(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	id := granted.Grants[0].ID
	before, _ := client.Status()
	if before.SSHGrantCount != 1 {
		t.Fatal("grant not active", before)
	}
	// Generic writers, including older clients without this field, cannot change
	// or erase approvals; unrelated writes must retain them.
	withSession(t, ctx, func(s *Session) {
		s.Body.SSHGrants = nil
		if err := s.ReSeal(); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		if len(s.Body.SSHGrants) != 1 {
			t.Fatal("grant erased via ReSeal")
		}
		s.Body.SSHGrants[0].Name = "injected"
		if err := s.ReSeal(); err != nil {
			t.Fatal(err)
		}
	})
	result, _ := client.SSHGrant(agent.SSHGrantReq{Action: "list"})
	if len(result.Grants) != 1 || result.Grants[0].Name != "granted" {
		t.Fatal("grant changed via generic ReSeal")
	}
	// Serve actual SSH-agent frames; no installed daemon or network host used.
	serveSSH := func(srv *agent.Server) func() {
		stop, err := srv.StartSSHSocket(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), socket, func(context.Context) ([]sshagent.KeyEntry, error) { return nil, nil })
		if err != nil {
			t.Fatal(err)
		}
		return stop
	}
	stopSSH := serveSSH(server)
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetBody(); err == nil {
		t.Fatal("SSH grant kept vault open")
	}
	status, _ := client.Status()
	if status.Unlocked || status.SSHGrantCount != 1 {
		t.Fatal(status)
	}
	conn, err := prepareGrantedSSHConnection(scope, "granted")
	if err != nil || conn.Alias != "granted" {
		t.Fatal(conn, err)
	}
	if _, err := prepareGrantedSSHConnection(scope, "other"); err == nil {
		t.Fatal("unapproved alias connected")
	}
	sock, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	sshClient := sshwire.NewClient(sock)
	keys, err := sshClient.List()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	public, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	session := []byte("synthetic-kex-session")
	signature, _ := hostSigner.Sign(rand.Reader, session)
	binding := ssh.Marshal(struct {
		Host, Session, Signature []byte
		Forward                  bool
	}{hostSigner.PublicKey().Marshal(), session, ssh.Marshal(signature), false})
	if _, err := sshClient.Extension("session-bind@openssh.com", binding); err != nil {
		t.Fatal(err)
	}
	data := ssh.Marshal(struct {
		Session               []byte
		Message               byte
		User, Service, Method string
		HasSignature          bool
		Algorithm             string
		Public, Host          []byte
	}{session, 50, "admin", "ssh-connection", "publickey-hostbound-v00@openssh.com", true, public.Type(), public.Marshal(), hostSigner.PublicKey().Marshal()})
	sig, err := sshClient.Sign(public, data)
	if err != nil || public.Verify(data, sig) != nil {
		t.Fatal("locked grant could not authenticate", err)
	}
	if _, err := sshClient.Sign(public, []byte("generic signing")); err == nil {
		t.Fatal("grant authorized arbitrary signing")
	}
	if err := client.LockAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := sshClient.Sign(public, data); err == nil {
		t.Fatal("existing socket retained access after lock-all")
	}
	stopSSH()
	server.Close()
	// Restart: persisted selection exists but keys must not be loaded until unlock.
	restarted, err := agent.Listen(paths, agent.Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	restartCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer restarted.Close()
	go restarted.Serve(restartCtx)
	if !waitAgentReady(client) {
		t.Fatal("restart failed")
	}
	status, _ = client.Status()
	if status.Unlocked || status.SSHGrantCount != 0 {
		t.Fatal("restart activated keys before unlock")
	}
	unlock := func() {
		t.Helper()
		if _, err := client.Unlock(paths.Vault, paths.UserChain, proto.AuthPassphrase, agent.UnlockCredential{Passphrase: []byte("correct horse battery staple")}); err != nil {
			t.Fatal(err)
		}
	}
	unlock()
	status, _ = client.Status()
	if status.SSHGrantCount != 1 {
		t.Fatal("unlock did not reactivate saved grant")
	}
	// Metadata changes preserve grants; destination changes disable them.
	withSession(t, ctx, func(s *Session) {
		r, err := s.GetTypedSecret(scope, "host:granted")
		if err != nil {
			t.Fatal(err)
		}
		h, err := decodeHost(*r)
		if err != nil {
			t.Fatal(err)
		}
		h.Description = "new label"
		if err := s.SetTypedSecret(ctx, scope, r.Name, r.Type, h.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	status, _ = client.Status()
	if status.SSHGrantCount != 1 {
		t.Fatal("metadata edit disabled grant")
	}
	withSession(t, ctx, func(s *Session) {
		r, _ := s.GetTypedSecret(scope, "host:granted")
		h, _ := decodeHost(*r)
		h.User = "root"
		if err := s.SetTypedSecret(ctx, scope, r.Name, r.Type, h.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	status, _ = client.Status()
	if status.SSHGrantCount != 0 {
		t.Fatal("changed destination retained grant")
	}
	withSession(t, ctx, func(s *Session) {
		r, _ := s.GetTypedSecret(scope, "host:granted")
		h, _ := decodeHost(*r)
		h.User = "admin"
		if err := s.SetTypedSecret(ctx, scope, r.Name, r.Type, h.Marshal()); err != nil {
			t.Fatal(err)
		}
		keyRecord, err := s.GetTypedSecret(scope, "ssh:"+h.KeyName)
		if err != nil {
			t.Fatal(err)
		}
		replacement, _ := sshkey.NewEd25519(h.KeyName, "")
		if err := s.SetTypedSecret(ctx, scope, keyRecord.Name, keyRecord.Type, replacement.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	status, _ = client.Status()
	if status.SSHGrantCount != 0 {
		t.Fatal("rotated client key retained grant")
	}
	if err := RunSSHRevoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	client.Lock()
	unlock()
	result, _ = client.SSHGrant(agent.SSHGrantReq{Action: "list"})
	if len(result.Grants) != 0 {
		t.Fatal("revoked grant reappeared")
	}
}
