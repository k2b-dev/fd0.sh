package desktopbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

type handlerFunc func(context.Context, string, json.RawMessage) (any, error)

func (f handlerFunc) Handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	return f(ctx, method, params)
}

func TestServerRoundTrip(t *testing.T) {
	server := Server{Handler: handlerFunc(func(_ context.Context, method string, params json.RawMessage) (any, error) {
		if method != "bridge.handshake" {
			t.Fatalf("method=%q", method)
		}
		return map[string]int{"protocol": ProtocolVersion}, nil
	})}
	input := strings.NewReader(`{"version":1,"id":"request-1","method":"bridge.handshake","params":{}}` + "\n")
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != "request-1" || response.Error != nil {
		t.Fatalf("response=%+v", response)
	}
}

func TestServerRejectsUnknownEnvelopeFieldsWithoutEchoingSecrets(t *testing.T) {
	server := Server{Handler: handlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})}
	secret := "must-not-be-echoed"
	input := strings.NewReader(`{"version":1,"id":"x","method":"vault.unlock","unexpected":"` + secret + `"}` + "\n")
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("response echoed request secret")
	}
	if !strings.Contains(output.String(), `"code":"bad_request"`) {
		t.Fatalf("output=%s", output.String())
	}
}

func TestServerRejectsMultipleJSONValues(t *testing.T) {
	server := Server{Handler: handlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})}
	input := strings.NewReader(`{"version":1,"id":"x","method":"bridge.handshake","params":{}} {"second":true}` + "\n")
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"code":"bad_request"`) {
		t.Fatalf("output=%s", output.String())
	}
}

func TestServerBoundsOversizedResponsesAndContinues(t *testing.T) {
	calls := 0
	server := Server{Handler: handlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		calls++
		if calls == 1 {
			return strings.Repeat("x", MaxFrameBytes), nil
		}
		return map[string]bool{"ok": true}, nil
	})}
	input := strings.NewReader(
		`{"version":1,"id":"large","method":"inventory.list","params":{}}` + "\n" +
			`{"version":1,"id":"next","method":"bridge.handshake","params":{}}` + "\n",
	)
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("responses=%d, want 2", len(lines))
	}
	var large, next Response
	if err := json.Unmarshal(lines[0], &large); err != nil {
		t.Fatal(err)
	}
	if large.Error == nil || large.Error.Code != "response_too_large" {
		t.Fatalf("large response=%+v", large)
	}
	if err := json.Unmarshal(lines[1], &next); err != nil {
		t.Fatal(err)
	}
	if next.Error != nil || next.ID != "next" {
		t.Fatalf("next response=%+v", next)
	}
}

func TestWriteIsolatedMarkerRefusesDefaultHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := WriteIsolatedMarker(filepath.Join(home, ".fd0")); err == nil {
		t.Fatal("expected production-home refusal")
	}
	if _, err := os.Stat(filepath.Join(home, ".fd0")); !os.IsNotExist(err) {
		t.Fatalf("production home was touched: %v", err)
	}
	isolated := filepath.Join(home, "fd0 Desktop Dev")
	if err := WriteIsolatedMarker(isolated); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(isolated, ".desktop-isolated"))
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != isolatedMarker {
		t.Fatalf("marker=%q", marker)
	}
	linked := filepath.Join(home, "linked desktop")
	if err := os.Symlink(isolated, linked); err != nil {
		t.Fatal(err)
	}
	if err := WriteIsolatedMarker(linked); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("symlink err=%v", err)
	}
}

func TestNewServiceFromEnvIsolatedMode(t *testing.T) {
	userHome := filepath.Join(t.TempDir(), "user")
	if err := os.MkdirAll(userHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	home := filepath.Join(t.TempDir(), "desktop")
	if err := WriteIsolatedMarker(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FD0_HOME", home)
	t.Setenv("FD0_DESKTOP_MODE", "isolated")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(t.TempDir(), "fd0-agent"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(t.TempDir(), "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")

	service, err := NewServiceFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if service.Home != home || service.Mode != "isolated" {
		t.Fatalf("service=%+v", service)
	}
}

func TestNewServiceFromEnvIsolatedModeFailsClosed(t *testing.T) {
	userHome := filepath.Join(t.TempDir(), "user")
	if err := os.MkdirAll(userHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	agentBin := filepath.Join(t.TempDir(), "fd0-agent")
	sshSock := filepath.Join(t.TempDir(), "ssh.sock")

	tests := []struct {
		name        string
		home        func() string
		marker      bool
		sshSock     string
		syncDisable string
		want        string
	}{
		{
			name:        "production home",
			home:        func() string { return filepath.Join(userHome, ".fd0") },
			marker:      true,
			sshSock:     sshSock,
			syncDisable: "1",
			want:        "refuses the production fd0 home",
		},
		{
			name:        "missing marker",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			sshSock:     sshSock,
			syncDisable: "1",
			want:        "isolated home marker",
		},
		{
			name:        "relative ssh socket",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			marker:      true,
			sshSock:     "ssh.sock",
			syncDisable: "1",
			want:        "must be absolute",
		},
		{
			name:        "sync not disabled",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			marker:      true,
			sshSock:     sshSock,
			syncDisable: "",
			want:        "requires FD0_AGENT_SYNC_DISABLED=1",
		},
		{
			name:        "production ssh socket",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			marker:      true,
			sshSock:     productionSSHSocketPath(),
			syncDisable: "1",
			want:        "refuses the production SSH agent socket",
		},
		{
			name:        "ssh socket inside production home",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			marker:      true,
			sshSock:     filepath.Join(userHome, ".fd0", "ssh.sock"),
			syncDisable: "1",
			want:        "refuses the production SSH agent socket",
		},
		{
			name:        "agent socket reused for ssh",
			home:        func() string { return filepath.Join(t.TempDir(), "desktop") },
			marker:      true,
			sshSock:     "$AGENT_SOCK",
			syncDisable: "1",
			want:        "must differ from the fd0 agent socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := tt.home()
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
			if tt.marker {
				if err := os.WriteFile(filepath.Join(home, ".desktop-isolated"), []byte(isolatedMarker), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("FD0_HOME", home)
			t.Setenv("FD0_DESKTOP_MODE", "isolated")
			t.Setenv("FD0_AGENT_BIN", agentBin)
			sshSock := tt.sshSock
			if sshSock == "$AGENT_SOCK" {
				sshSock = filepath.Join(home, "agent.sock")
			}
			t.Setenv("FD0_SSH_SOCK", sshSock)
			t.Setenv("FD0_AGENT_SYNC_DISABLED", tt.syncDisable)
			_, err := NewServiceFromEnv()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestNewServiceFromEnvRejectsSymlinkMarker(t *testing.T) {
	userHome := filepath.Join(t.TempDir(), "user")
	if err := os.MkdirAll(userHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	home := filepath.Join(t.TempDir(), "desktop")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(target, []byte(isolatedMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".desktop-isolated")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FD0_HOME", home)
	t.Setenv("FD0_DESKTOP_MODE", "isolated")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(t.TempDir(), "fd0-agent"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(t.TempDir(), "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	_, err := NewServiceFromEnv()
	if err == nil || !strings.Contains(err.Error(), "marker must not be a symlink") {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeParamsRejectsMultipleJSONValues(t *testing.T) {
	var params struct {
		Value string `json:"value"`
	}
	if err := decodeParams(json.RawMessage(`{"value":"first"} {"value":"second"}`), &params); err == nil {
		t.Fatal("expected multiple-value rejection")
	}
}

func TestTrustedContactsAreSortedAndMarkExistingMembers(t *testing.T) {
	alice := bytes.Repeat([]byte{1}, 32)
	benny := bytes.Repeat([]byte{2}, 32)
	contacts := trustedContacts(map[string]proto.PinnedIdentity{
		"Benny":   {SuperPub: benny, Label: "Benny"},
		"alice":   {SuperPub: alice, Label: "alice"},
		"invalid": {SuperPub: []byte("short"), Label: "invalid"},
	}, [][]byte{benny})
	if len(contacts) != 2 {
		t.Fatalf("contacts=%+v", contacts)
	}
	if contacts[0].Label != "alice" || contacts[0].Shared {
		t.Fatalf("first contact=%+v", contacts[0])
	}
	if contacts[1].Label != "Benny" || !contacts[1].Shared {
		t.Fatalf("second contact=%+v", contacts[1])
	}
}

func TestScopeMembersIncludeSelfTrustedAndUnknown(t *testing.T) {
	self := bytes.Repeat([]byte{1}, 32)
	benny := bytes.Repeat([]byte{2}, 32)
	unknown := bytes.Repeat([]byte{3}, 32)
	members := scopeMembers(map[string]proto.PinnedIdentity{
		"Benny": {SuperPub: benny, Label: "Benny"},
	}, [][]byte{unknown, benny, self}, self, nil)
	if len(members) != 3 {
		t.Fatalf("members=%+v", members)
	}
	if !members[0].Self || members[0].Label != "You" {
		t.Fatalf("self=%+v", members[0])
	}
	if members[1].Label != "Benny" || !members[1].Trusted || members[1].Self {
		t.Fatalf("trusted=%+v", members[1])
	}
	if members[2].Label != "Unknown member" || members[2].Trusted || members[2].Self {
		t.Fatalf("unknown=%+v", members[2])
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(members[2].ID); err != nil || !bytes.Equal(decoded, unknown) {
		t.Fatalf("member id=%q err=%v", members[2].ID, err)
	}
}

func TestPassFieldViewsDoNotExposeTOTPCode(t *testing.T) {
	field, err := passitem.NewTOTPField(passitem.TOTPValue{Secret: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	field.Name = "one-time password"
	fields := []passitem.Field{field}
	views := passFieldViews(fields, "", "Login")
	if len(views) != 1 {
		t.Fatalf("views=%+v", views)
	}
	if views[0].Value != "" || !views[0].Sensitive || !views[0].Copyable {
		t.Fatalf("TOTP detail leaks code or lacks protection: %+v", views[0])
	}
}

func TestAuthMethodSummariesAndSelection(t *testing.T) {
	home := t.TempDir()
	paths := fdhome.Paths{
		Home:      home,
		Config:    filepath.Join(home, "config.toml"),
		Chains:    filepath.Join(home, "chains"),
		UserChain: filepath.Join(home, "chains", "user.cbor"),
	}
	if err := os.MkdirAll(paths.Chains, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	yubikeyParams, err := proto.Marshal(proto.YubikeyPublicParams{
		PinPolicy:   "never",
		TouchPolicy: "always",
	})
	if err != nil {
		t.Fatal(err)
	}
	methods := []proto.AuthMethod{
		{MethodID: "am_z", MethodType: proto.AuthYubikey, PublicParams: yubikeyParams},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	event, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, methods)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.AppendUser(paths.UserChain, event); err != nil {
		t.Fatal(err)
	}
	if err := fdhome.SetAuthDefaultMethod(paths.Config, "am_z"); err != nil {
		t.Fatal(err)
	}

	summaries, err := authMethodSummaries(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[0].ID != "am_a" || summaries[0].Label != "Passphrase" {
		t.Fatalf("summaries=%+v", summaries)
	}
	if summaries[1].ID != "am_z" || summaries[1].Label != "YubiKey" || summaries[1].PINMode != "none" || summaries[1].TouchPolicy != "always" || !summaries[1].Default {
		t.Fatalf("yubikey summary=%+v", summaries[1])
	}

	selected, err := selectAuthMethod(paths, methods, "")
	if err != nil {
		t.Fatal(err)
	}
	if selected.MethodID != "am_z" {
		t.Fatalf("default selected=%q", selected.MethodID)
	}
	selected, err = selectAuthMethod(paths, methods, proto.AuthPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if selected.MethodID != "am_a" {
		t.Fatalf("type selected=%q", selected.MethodID)
	}
	if _, err := selectAuthMethod(paths, methods, "am_missing"); err == nil {
		t.Fatal("expected missing-method error")
	}
}

func TestYubikeyPINMode(t *testing.T) {
	tests := []struct {
		name   string
		params []byte
		want   string
	}{
		{name: "legacy", want: "optional"},
		{name: "invalid", params: []byte("not-cbor"), want: "optional"},
		{name: "touch only", params: mustYubikeyParams(t, "never"), want: "none"},
		{name: "pin once", params: mustYubikeyParams(t, "once"), want: "required"},
		{name: "pin always", params: mustYubikeyParams(t, "always"), want: "required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := yubikeyPINMode(proto.AuthMethod{MethodType: proto.AuthYubikey, PublicParams: tt.params})
			if got != tt.want {
				t.Fatalf("got=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestAgentCompatibility(t *testing.T) {
	yubikey := &Service{ExpectedVersion: "1.2.3", ExpectedFlavor: "yubikey"}
	standard := &Service{ExpectedVersion: "1.2.3", ExpectedFlavor: "standard"}
	tests := []struct {
		name    string
		service *Service
		status  *agent.StatusResp
		want    bool
	}{
		{name: "matching", service: yubikey, status: &agent.StatusResp{Protocol: 1, Version: "1.2.3", Flavor: "yubikey"}, want: true},
		// A separately installed CLI always carries its own release string.
		{name: "different release version", service: yubikey, status: &agent.StatusResp{Protocol: 1, Version: "client-v0.12.0", Flavor: "yubikey"}, want: true},
		// Agents that predate the protocol field all speak protocol 1.
		{name: "legacy metadata", service: standard, status: &agent.StatusResp{}, want: true},
		{name: "newer protocol", service: standard, status: &agent.StatusResp{Protocol: agent.ProtocolVersion + 1}},
		{name: "standard agent cannot serve a yubikey build", service: yubikey, status: &agent.StatusResp{Protocol: 1, Flavor: "standard"}},
		{name: "yubikey agent serves a standard build", service: standard, status: &agent.StatusResp{Protocol: 1, Flavor: "yubikey"}, want: true},
		{name: "missing status", service: standard},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			use := tt.service.inspectAgent(tt.status)
			if use.compatible != tt.want {
				t.Fatalf("compatible=%v want %v (reason %q)", use.compatible, tt.want, use.reason)
			}
			if use.compatible == (use.reason != "") {
				t.Fatalf("compatible=%v with reason %q", use.compatible, use.reason)
			}
		})
	}
}

// A CLI-started agent from another release must be used as it is: not
// restarted, not stopped, not reported as a problem. This is the everyday
// setup of anyone who installs the fd0 CLI and fd0 Desktop separately.
func TestAgentStartedElsewhereIsUsedNotReplaced(t *testing.T) {
	// Not t.TempDir(): its path carries the test name, and a Unix socket path
	// is capped near 104 bytes.
	home, err := os.MkdirTemp("", "fd0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("FD0_HOME", home)
	t.Setenv("FD0_SSH_SOCK", filepath.Join(home, "ssh.sock"))
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	// Started by something other than the desktop app (no StartedBy marker)
	// and built from a different release than the app below.
	server, err := agent.Listen(paths, agent.Config{
		IdleTimeout: time.Hour,
		MaxLifetime: time.Hour,
		Version:     "client-v0.12.0",
		Flavor:      buildinfo.Flavor,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	defer server.Close()
	client := agent.NewClient(paths.AgentSock)
	if err := agent.WaitReady(paths.AgentSock, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	service := &Service{
		Home:            home,
		AgentBin:        filepath.Join(home, "fd0-agent-that-must-not-run"),
		Mode:            "system",
		ExpectedVersion: "0.1.0",
		ExpectedFlavor:  buildinfo.Flavor,
	}
	status, err := service.status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.AgentRunning || status.AgentIncompatible {
		t.Fatalf("status=%+v, want a running, compatible agent", status)
	}
	if status.AgentStartedBy != agentStartedByExternal || status.Version != "client-v0.12.0" {
		t.Fatalf("status=%+v, want an external agent reporting its own version", status)
	}

	// Unlocking must go past the compatibility gate and reach the vault (there
	// is none here) instead of replacing the agent. AgentBin does not exist, so
	// any attempt to start a replacement would fail loudly.
	if _, err := service.unlock(context.Background(), "", []byte("passphrase"), nil); err == nil {
		t.Fatal("expected a vault error")
	} else {
		var methodErr *methodError
		if !errors.As(err, &methodErr) || methodErr.bridge.Code != "vault_invalid" {
			t.Fatalf("unlock err=%v, want vault_invalid", err)
		}
	}

	// The one button that stops an agent must refuse for a foreign one.
	if _, err := service.restartAgent(); err == nil {
		t.Fatal("expected a refusal to restart a foreign agent")
	} else {
		var methodErr *methodError
		if !errors.As(err, &methodErr) || methodErr.bridge.Code != "agent_not_ours" {
			t.Fatalf("restart err=%v, want agent_not_ours", err)
		}
	}

	if !client.IsRunning() {
		t.Fatal("the agent this app did not start was terminated")
	}
	if _, err := os.Stat(paths.AgentPID); err != nil {
		t.Fatalf("agent pid file was removed: %v", err)
	}
}

func TestUnusableAgentPointsAtItsOwner(t *testing.T) {
	use := agentUsability{reason: "The running service was built without YubiKey support."}
	var foreign, own *methodError
	if !errors.As(unusableAgentError(use, agentStartedByExternal), &foreign) {
		t.Fatal("expected a method error")
	}
	if !errors.As(unusableAgentError(use, agentStartedByDesktop), &own) {
		t.Fatal("expected a method error")
	}
	if !strings.Contains(foreign.bridge.Action, "fd0 agent stop") || strings.Contains(foreign.bridge.Action, "Support") {
		t.Fatalf("foreign action=%q", foreign.bridge.Action)
	}
	if !strings.Contains(own.bridge.Action, "Support") {
		t.Fatalf("own action=%q", own.bridge.Action)
	}
}

func TestPinSyncServerRejectsHostedIdentityMismatchBeforeVaultMutation(t *testing.T) {
	t.Setenv("FD0_SERVER", hostedServerURL)
	service := &Service{
		HostedServerURL: hostedServerURL,
		HostedServerPub: bytes.Repeat([]byte{0x11}, 32),
	}
	_, err := service.pinSyncServer(
		context.Background(),
		hostedServerURL,
		strings.Repeat("22", 32),
	)
	var methodErr *methodError
	if !errors.As(err, &methodErr) || methodErr.bridge.Code != "hosted_server_identity_mismatch" {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateCurrentServerRejectsConfigurationChange(t *testing.T) {
	t.Setenv("FD0_SERVER", "https://new.example")
	service := &Service{}
	err := service.validateCurrentServer("https://old.example")
	var methodErr *methodError
	if !errors.As(err, &methodErr) || methodErr.bridge.Code != "server_changed" {
		t.Fatalf("err=%v", err)
	}
}

func TestStopDesktopAgentCleansStaleFiles(t *testing.T) {
	root := t.TempDir()
	paths := fdhome.Paths{
		AgentPID:  filepath.Join(root, "agent.pid"),
		AgentSock: filepath.Join(root, "agent.sock"),
	}
	sshSock := filepath.Join(root, "ssh.sock")
	t.Setenv("FD0_SSH_SOCK", sshSock)
	for _, path := range []string{paths.AgentPID, paths.AgentSock, sshSock} {
		if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := stopDesktopAgent(paths); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.AgentPID, paths.AgentSock, cli.SSHSocketPathForRender()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path still exists: %s", path)
		}
	}
}

func mustYubikeyParams(t *testing.T, pinPolicy string) []byte {
	t.Helper()
	data, err := proto.Marshal(proto.YubikeyPublicParams{PinPolicy: pinPolicy})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestServerWipesAttachmentResult(t *testing.T) {
	result := &FieldAttachmentResult{Name: "key.pem", Data: []byte("secret-key")}
	server := Server{Handler: handlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		return result, nil
	})}
	input := strings.NewReader(`{"version":1,"id":"request-1","method":"file.value","params":{}}` + "\n")
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"data":"c2VjcmV0LWtleQ=="`) {
		t.Fatalf("output=%s", output.String())
	}
	for i, value := range result.Data {
		if value != 0 {
			t.Fatalf("result byte %d was not wiped", i)
		}
	}
}
