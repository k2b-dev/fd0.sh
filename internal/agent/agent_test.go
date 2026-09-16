package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

func TestAgentRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FD0_HOME", dir)
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	// Build a small vault.
	pub, priv, _ := crypto.GenerateIdentity()
	pass := []byte("secret-pass")
	salt, _ := crypto.RandomBytes(16)
	pp, _ := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	encSP, err := vault.EncryptSuperPriv(priv.Bytes(), pub.Bytes(), "am_p", uk)
	if err != nil {
		t.Fatal(err)
	}
	method := proto.AuthMethod{
		MethodID:           "am_p",
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}
	genesis, err := chain.BuildUserAuthSet(
		chain.LocalSigner{Priv: priv},
		pub.Bytes(),
		0,
		nil,
		[]proto.AuthMethod{method},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.AppendUser(paths.UserChain, genesis); err != nil {
		t.Fatal(err)
	}
	prefix, err := genesis.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	authTipHash := proto.HashPrefix(prefix)
	body := &proto.VaultBody{
		SuperPriv:        priv.Bytes(),
		AuthTip:          proto.ChainTip{Seq: 0, Hash: authTipHash[:]},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, pub.Bytes(), body, []vault.WrapInput{{
		MethodID: "am_p", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		t.Fatal(err)
	}
	// Start agent.
	srv, err := Listen(paths, Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()
	cli := NewClient(paths.AgentSock)
	// Initially locked.
	st, err := cli.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("expected locked")
	}
	// Unlock against the matching canonical user chain.
	ur, err := cli.Unlock(paths.Vault, paths.UserChain, proto.AuthPassphrase, UnlockCredential{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if len(ur.UserSuperPub) != 32 {
		t.Fatal("bad super pub")
	}
	// Sign roundtrip.
	msg := []byte("hello-fd0")
	sig, err := cli.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.Verify(pub, msg, sig) {
		t.Fatal("sign verify failed")
	}
	// OpenSeal: seal something to our X25519 pub and ask agent to open it.
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	want := []byte("oek_payload_32_bytes_aaaaaaaaaaa")[:32]
	sealed, err := crypto.SealAnonymous(want, xPub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cli.OpenSeal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	// A successful vault commit invalidates any in-flight SSH snapshot.
	srv.mu.Lock()
	beforeRevision := srv.sshRevision
	srv.mu.Unlock()
	if err := cli.ReSeal(paths.Vault, ur.RedactedBody); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	afterRevision := srv.sshRevision
	srv.mu.Unlock()
	if afterRevision != beforeRevision+1 {
		t.Fatal("vault commit did not invalidate SSH snapshot")
	}
	// Lock.
	if err := cli.Lock(); err != nil {
		t.Fatal(err)
	}
	st, _ = cli.Status()
	if st.Unlocked {
		t.Fatal("expected locked after Lock")
	}
	// A slow unlock must not install keys after its operation budget expires.
	// Default Argon2 work is deliberately much slower than this deadline.
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer timeoutCancel()
	resp := srv.handleUnlockContext(timeoutCtx, &UnlockReq{
		VaultPath:     paths.Vault,
		UserChainPath: paths.UserChain,
		MethodType:    proto.AuthPassphrase,
		Passphrase:    append([]byte(nil), pass...),
	})
	if resp.Err != unlockTimeoutMessage {
		t.Fatalf("expired unlock error=%q want %q", resp.Err, unlockTimeoutMessage)
	}
	if srv.handleStatus().Status.Unlocked {
		t.Fatal("expired unlock installed a live session")
	}
	// Verify socket file persists.
	if _, err := os.Stat(filepath.Join(dir, "agent.sock")); err != nil {
		t.Fatal(err)
	}
}

func TestWipeOpenResultClearsRejectedUnlockMaterial(t *testing.T) {
	res := vault.OpenResult{
		Body: &proto.VaultBody{
			SuperPriv: []byte{1, 2, 3, 4},
		},
		UnlockKey:  []byte{5, 6, 7, 8},
		PayloadKey: []byte{9, 10, 11, 12},
	}
	wipeOpenResult(&res)
	for name, secret := range map[string][]byte{
		"super private key": res.Body.SuperPriv,
		"unlock key":        res.UnlockKey,
		"payload key":       res.PayloadKey,
	} {
		for i, b := range secret {
			if b != 0 {
				t.Fatalf("%s byte %d was not wiped: %d", name, i, b)
			}
		}
	}
}

// Status carries the two facts a client needs to decide whether it can use this
// agent and whether it may stop it. Neither is the release version.
func TestStatusReportsProtocolAndLauncher(t *testing.T) {
	t.Setenv(StartedByEnv, StartedByDesktop)
	s := newLifecycleTestServer(t, time.Hour, time.Hour)
	s.cfg.StartedBy = StartedByFromEnv()
	st := s.handleStatus().Status
	if st.Protocol != ProtocolVersion {
		t.Fatalf("protocol=%d want %d", st.Protocol, ProtocolVersion)
	}
	if st.StartedBy != StartedByDesktop {
		t.Fatalf("started by=%q want %q", st.StartedBy, StartedByDesktop)
	}

	// An agent must not be able to describe itself as something a client would
	// recognise as its own.
	t.Setenv(StartedByEnv, "definitely-fd0-desktop")
	if got := StartedByFromEnv(); got != "" {
		t.Fatalf("unknown launcher survived as %q", got)
	}
}

func TestSpawnAsMarksTheChildAndSpawnDoesNot(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-agent")
	// Always writes a line, so "the child has not run yet" cannot be mistaken
	// for "the child ran without the marker".
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'started_by=[%s]\\n' \"$"+StartedByEnv+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		parentEnv string
		startedBy string
		want      string
	}{
		{name: "marked", startedBy: StartedByDesktop, want: "started_by=[" + StartedByDesktop + "]\n"},
		{name: "unmarked", want: "started_by=[]\n"},
		// A CLI spawn inside a marked process must not inherit ownership.
		{name: "inherited marker dropped", parentEnv: StartedByDesktop, want: "started_by=[]\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.parentEnv != "" {
				t.Setenv(StartedByEnv, tt.parentEnv)
			}
			log := filepath.Join(dir, tt.name+".log")
			if err := SpawnAs(script, log, tt.startedBy); err != nil {
				t.Fatal(err)
			}
			// Generous on purpose: this deadline is only ever reached when the
			// marker is genuinely wrong, while a short one turns "the child
			// has not been scheduled yet" into a failure under parallel load.
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(log)
				if err == nil && string(data) == tt.want {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			data, _ := os.ReadFile(log)
			t.Fatalf("child environment=%q want %q", data, tt.want)
		})
	}
}
