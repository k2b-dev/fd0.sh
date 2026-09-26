package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ManageSSHGrant serializes persistent changes with ordinary CLI writers.
// The agent independently validates credentials and the reviewed digest.
func ManageSSHGrant(ctx context.Context, r agent.SSHGrantReq) (*agent.SSHGrantResp, error) {
	if r.Action == "list" {
		paths, err := fdhome.Resolve()
		if err != nil {
			return nil, err
		}
		return agent.NewClient(paths.AgentSock).SSHGrant(r)
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if r.Action == "prepare" || r.Action == "create" {
		record, err := s.GetTypedSecret(r.ScopeID, "host:"+r.Name)
		if err != nil {
			return nil, err
		}
		r.ScopeID = record.ScopeID
		hosts, err := loadHosts(s, "")
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			if h.Alias == r.Name && h.Scope != r.ScopeID {
				return nil, errors.New("rename duplicate host aliases before creating an SSH grant")
			}
		}
		if err := renderSSHForConnect(s); err != nil {
			return nil, err
		}
	}
	return s.Agent.SSHGrant(r)
}

func RunSSHGrant(ctx context.Context, scope, name, method, knownHosts string) error {
	// A terminal is a UX boundary, not proof of human presence. Credentials are
	// never accepted through command-line flags, environment variables or MCP.
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("run fd0 ssh grant yourself in an interactive terminal; fresh authentication is required")
	}
	r := agent.SSHGrantReq{Action: "prepare", ScopeID: scope, Name: name, KnownHosts: knownHosts}
	preview, err := ManageSSHGrant(ctx, r)
	if err != nil {
		return err
	}
	if len(preview.Grants) != 1 {
		return errors.New("invalid SSH grant preview")
	}
	g := preview.Grants[0]
	r.ScopeID = g.ScopeID
	fmt.Fprintf(os.Stderr, "Allow SSH while fd0 is locked on this device:\n  %s: %s@%s:%d\n  Key: %s\n", terminalSafe(g.Name), terminalSafe(g.User), terminalSafe(g.Hostname), effectiveSSHPort(g.Port), g.Fingerprint)
	for _, fp := range g.HostFingerprints {
		fmt.Fprintf(os.Stderr, "  Server key: %s\n", fp)
	}
	if g.Jump != "" {
		fmt.Fprintf(os.Stderr, "  Jump host(s): %s — each required jump host needs its own grant.\n", terminalSafe(g.Jump))
	}
	fmt.Fprintln(os.Stderr, "Requires host-bound OpenSSH authentication; agent forwarding stays unavailable while locked.\nAuthenticate again to authorize exactly this grant. Ctrl+C cancels.")
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	methods, err := LoadGrantAuthMethods(paths)
	if err != nil {
		return err
	}
	if method == "" {
		cfg, err := fdhome.LoadConfig(paths.Config)
		if err != nil {
			return err
		}
		method = cfg.Auth.DefaultMethod
	}
	chosen, err := pickUnlockMethod(methods, method)
	if err != nil {
		return err
	}
	auth := &agent.UnlockReq{MethodType: chosen.MethodType}
	switch chosen.MethodType {
	case proto.AuthPassphrase:
		auth.Passphrase, err = ReadPassphrase("Authorize SSH grant — passphrase: ")
	case proto.AuthYubikey:
		auth.YubikeyPIN, err = readYubikeyUnlockPIN(chosen, ReadOptionalPIN)
		fmt.Fprintln(os.Stderr, "Touch your YubiKey if requested.")
	default:
		return errors.New("unsupported authentication method")
	}
	defer crypto.Wipe(auth.Passphrase)
	defer crypto.Wipe(auth.YubikeyPIN)
	if err != nil {
		return err
	}
	r.Action = "create"
	r.Digest = preview.Digest
	r.Authentication = auth
	result, err := ManageSSHGrant(ctx, r)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ SSH grant saved: %s\n", result.Grants[0].ID)
	return nil
}

func RunSSHGrants(ctx context.Context, asJSON bool) error {
	result, err := ManageSSHGrant(ctx, agent.SSHGrantReq{Action: "list"})
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Device: %s\n", result.DeviceID)
	for _, g := range result.Grants {
		state := "inactive (unlock or reapprove changed host/key)"
		if g.Active {
			state = "active"
		}
		fmt.Printf("%s  %s  %s@%s  %s\n", g.ID, terminalSafe(g.Name), terminalSafe(g.User), terminalSafe(g.Hostname), state)
	}
	if len(result.Grants) == 0 {
		fmt.Println("No visible SSH grants. Unlock to load saved grants after an agent restart.")
	}
	return nil
}

func RunSSHRevoke(ctx context.Context, id string) error {
	_, err := ManageSSHGrant(ctx, agent.SSHGrantReq{Action: "revoke", ID: id})
	if err == nil {
		fmt.Fprintln(os.Stderr, "✓ SSH grant removed")
	}
	return err
}

func RunLockAll(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	c := agent.NewClient(paths.AgentSock)
	if !c.IsRunning() {
		return nil
	}
	if err := c.LockAll(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ vault and all SSH grants locked (existing SSH sessions are not disconnected)")
	return nil
}

// A locked connection uses the already-rendered projection and only an active
// exact alias. It never unlocks the vault or resolves arbitrary prefixes.
func prepareGrantedSSHConnection(scope, name string) (OpenSSHConnection, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return OpenSSHConnection{}, err
	}
	result, err := agent.NewClient(paths.AgentSock).SSHGrant(agent.SSHGrantReq{Action: "list"})
	if err != nil {
		return OpenSSHConnection{}, err
	}
	var selected *agent.SSHGrantView
	for i := range result.Grants {
		g := &result.Grants[i]
		if g.Active && g.Name == name && (scope == "" || g.ScopeID == scope) {
			if selected != nil {
				return OpenSSHConnection{}, errors.New("ambiguous SSH grant")
			}
			selected = g
		}
	}
	if selected == nil {
		return OpenSSHConnection{}, fmt.Errorf("no active SSH grant for %q; unlock fd0 first (use a scope ID while locked)", name)
	}
	if sshAgentSocketDisabledByEnv() {
		return OpenSSHConnection{}, errors.New("fd0 SSH agent socket is disabled")
	}
	if err := checkSSHAgentSocket(SSHSocketPathForRender()); err != nil {
		return OpenSSHConnection{}, err
	}
	if _, err := os.Stat(SSHConfPath()); err != nil {
		return OpenSSHConnection{}, errors.New("SSH configuration is missing; unlock fd0 and reconnect to regenerate it")
	}
	config, err := sshConnectConfigPath()
	if err != nil {
		return OpenSSHConnection{}, err
	}
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return OpenSSHConnection{}, err
	}
	return OpenSSHConnection{Alias: name, ConfigPath: config, SSHBinary: bin}, nil
}

func effectiveSSHPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

func LoadGrantAuthMethods(paths fdhome.Paths) ([]proto.AuthMethod, error) {
	st, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		return nil, err
	}
	if st == nil || st.LatestAuthSet == nil {
		return nil, errors.New("no active authentication methods")
	}
	return st.LatestAuthSet.Payload.Active, nil
}
