package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RunInit performs first-time setup: generate identity, ask for passphrase,
// build a passphrase auth.set genesis, write user.cbor and vault.enc.
func RunInit(ctx context.Context, keyFile string) error {
	var pass []byte
	var err error
	if keyFile != "" {
		pass, err = ReadKeyFile(keyFile)
	} else {
		pass, err = ReadPassphraseConfirm("Choose a passphrase: ", "Confirm passphrase: ")
	}
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	result, err := InitWithPassphrase(ctx, pass)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "✓ identity created (%s…)\n", b64sub(result.UserSuperPub))
	fmt.Fprintf(os.Stderr, "✓ vault written to %s\n", result.VaultPath)
	fmt.Fprintln(os.Stderr, "Run `fd0 unlock` to start the agent.")
	return nil
}

// InitResult describes the identity and vault created by InitWithPassphrase.
// It intentionally contains no private key material.
type InitResult struct {
	UserSuperPub []byte
	VaultPath    string
}

// InitWithPassphrase performs the non-interactive core of RunInit. The caller
// owns and must wipe pass. Accepting bytes keeps credentials out of process
// arguments and environment variables for structured frontends.
func InitWithPassphrase(ctx context.Context, pass []byte) (*InitResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}
	if VaultExists(paths) {
		return nil, fmt.Errorf("vault already exists at %s; refuse to overwrite", paths.Vault)
	}
	if _, err := os.Stat(paths.UserChain); err == nil {
		return nil, fmt.Errorf("user chain already exists at %s; refuse to overwrite", paths.UserChain)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	// Wave C-3': pub/priv are typed. Wire-format APIs (vault
	// wraps, proto VaultBody, chain.LocalSigner) consume []byte;
	// convert via .Bytes() at the boundary. Wipe the priv
	// material via the typed Wipe (which delegates to
	// crypto.Wipe with KeepAlive safeguard).
	defer priv.Wipe()
	pubBytes := pub.Bytes()
	privBytes := priv.Bytes()
	defer crypto.Wipe(privBytes)

	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		return nil, err
	}
	unlockKey, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		return nil, fmt.Errorf("derive K_unlock: %w", err)
	}
	defer crypto.Wipe(unlockKey)

	methodID := "am_" + ulid.Make().String()
	encSP, err := vault.EncryptSuperPriv(privBytes, pubBytes, methodID, unlockKey)
	if err != nil {
		return nil, err
	}

	// Genesis auth.set. LocalSigner now holds the typed priv so
	// the wrong-size-priv panic in ed25519.Sign is structurally
	// impossible — only ParseEd25519Priv (or GenerateIdentity)
	// can produce a non-zero Ed25519Priv.
	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pubBytes, 0, nil, []proto.AuthMethod{{
		MethodID:           methodID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}})
	if err != nil {
		return nil, err
	}
	if err := chain.AppendUser(paths.UserChain, g); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(paths.UserChain)
			_ = os.Remove(paths.Vault)
		}
	}()
	// Compute auth_tip.
	prefix, err := g.PrevHashInput()
	if err != nil {
		return nil, err
	}
	authTipHash := proto.HashPrefix(prefix)

	// Build initial vault body.
	body := &proto.VaultBody{
		SuperPriv:        privBytes,
		AuthTip:          proto.ChainTip{Seq: 0, Hash: authTipHash[:]},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, pubBytes, body, []vault.WrapInput{{
		MethodID:     methodID,
		MethodType:   proto.AuthPassphrase,
		PublicParams: pp,
		UnlockKey:    unlockKey,
	}}); err != nil {
		return nil, err
	}
	committed = true

	return &InitResult{
		UserSuperPub: append([]byte(nil), pubBytes...),
		VaultPath:    paths.Vault,
	}, nil
}

// RunUnlock starts the agent if necessary, then sends the credential
// for the chosen auth method.
//
// Method selection (in order):
//  1. Explicit --method flag, if non-empty.
//  2. Multiple methods on a TTY: ask, preselecting the device-local default.
//  3. Otherwise use the configured default or first method by method_id.
//
// For passphrase methods we prompt "Passphrase: ". For YubiKey methods
// we inspect public_params.pin_policy: touch-only methods skip the PIN
// prompt, PIN-protected methods prompt for "YubiKey PIV PIN", and legacy
// methods without policy metadata keep the optional prompt. Platform-local
// unlock sends no credential bytes; the agent invokes its configured provider.
// Prompts read from non-TTY stdin when piped, so shell tests can drive them.
// RunUnlock starts the agent and unlocks the vault. With keyFile it never
// prompts: the key file is the passphrase of an unattended identity, and an
// already unlocked agent is left as it is so jobs can call it every run.
func RunUnlock(ctx context.Context, agentBin, method, keyFile string) error {
	if keyFile != "" && method != "" && method != proto.AuthPassphrase && !strings.HasPrefix(method, "am_") {
		return errors.New("--key-file unlocks a passphrase method; do not combine it with --method " + method)
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	if !VaultExists(paths) {
		return errors.New("no vault found — run `fd0 init` first")
	}

	uctx, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		return fmt.Errorf("replay user chain: %w", err)
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain — run `fd0 init` first")
	}
	activeMethods := uctx.LatestAuthSet.Payload.Active
	if method != "" {
		if _, err := pickUnlockMethod(activeMethods, method); err != nil {
			return err
		}
	}

	c := agent.NewClient(paths.AgentSock)
	if c.IsRunning() && !sshAgentSocketDisabledByEnv() {
		sshSock := SSHSocketPathForRender()
		if err := checkSSHAgentSocket(sshSock); err != nil {
			fmt.Fprintf(os.Stderr, "warn: repairing fd0 SSH agent socket at %s\n", sshSock)
			if err := agent.StopByPIDFile(paths.AgentPID, 2*time.Second); err != nil {
				return sshAgentSocketUnavailable(sshSock, err)
			}
			c = agent.NewClient(paths.AgentSock)
		}
	}
	if !c.IsRunning() {
		if err := agent.Spawn(agentBin, paths.AgentLog); err != nil {
			return err
		}
		if err := agent.WaitReady(paths.AgentSock, agentReadyTimeout); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "✓ agent started")
	}
	// With a key file, resolve the method before anything else so a wrong
	// selection fails the same way whether or not the agent is unlocked.
	var keyMethod proto.AuthMethod
	if keyFile != "" {
		selector := method
		if selector == "" {
			selector = proto.AuthPassphrase
		}
		keyMethod, err = pickUnlockMethod(activeMethods, selector)
		if err != nil {
			return err
		}
		if keyMethod.MethodType != proto.AuthPassphrase {
			return errors.New("--key-file needs a passphrase method")
		}
	}
	st, err := c.Status()
	if err != nil {
		return fmt.Errorf("agent status: %w", err)
	}
	if st.Unlocked {
		fmt.Fprintln(os.Stderr, "✓ vault already unlocked")
		return nil
	}
	var chosen proto.AuthMethod
	var cred agent.UnlockCredential
	if keyFile != "" {
		// Read only when an unlock is actually needed: an unlocked agent is
		// left as it is, without checking the key.
		chosen = keyMethod
		cred.Passphrase, err = ReadKeyFile(keyFile)
	} else {
		chosen, cred, err = promptAuthentication(paths, activeMethods, method)
	}
	defer crypto.Wipe(cred.Passphrase)
	defer crypto.Wipe(cred.YubikeyPIN)
	if err != nil {
		return err
	}
	if strings.HasPrefix(method, "am_") {
		// An explicitly chosen method must be the one that unlocks.
		cred.MethodID = chosen.MethodID
	}
	ur, err := c.Unlock(paths.Vault, paths.UserChain, chosen.MethodType, cred)
	if err != nil {
		return friendlyUnlockError(err)
	}
	fmt.Fprintf(os.Stderr, "✓ vault unlocked (%s)\n", chosen.MethodType)
	// A vault written by the retired v1 compactor is unreadable until its
	// scope history is restored from the server. Do it here so the user
	// never has to know it happened; a failure is a warning, never a failed
	// unlock (the vault is unlocked either way, and every read path retries
	// the migration on its own).
	if err := MigrateLegacyScopesAfterUnlock(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warn: %v\n", err)
	}
	if shouldHintInteractiveFirstSync(paths.Config, ur) {
		fmt.Fprintln(os.Stderr, "  run `fd0 sync` once to verify and pin the server; background sync resumes after that")
	}
	if !sshAgentSocketDisabledByEnv() {
		sshSock := SSHSocketPathForRender()
		if err := checkSSHAgentSocket(sshSock); err != nil {
			fmt.Fprintf(os.Stderr, "warn: %v\n", sshAgentSocketUnavailable(sshSock, err))
		}
	}
	return nil
}

func promptUnlockMethod(active []proto.AuthMethod, in io.Reader, out io.Writer, defaultID string) (proto.AuthMethod, error) {
	if len(active) == 0 {
		return proto.AuthMethod{}, errors.New("no active auth methods")
	}
	ordered := append([]proto.AuthMethod(nil), active...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].MethodID < ordered[j].MethodID
	})
	if len(ordered) == 1 {
		return ordered[0], nil
	}

	selected := 0
	if defaultID != "" {
		for i, method := range ordered {
			if method.MethodID == defaultID {
				selected = i
			}
		}
	}
	fmt.Fprintln(out, "Choose authentication method:")
	for i, method := range ordered {
		fmt.Fprintf(out, "  %d) %s\n", i+1, unlockMethodLabel(method))
	}

	reader := bufio.NewReader(in)
	for {
		fmt.Fprintf(out, "Select [%d]: ", selected+1)
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if readErr != nil {
				return proto.AuthMethod{}, fmt.Errorf("choose unlock method: %w", readErr)
			}
			return ordered[selected], nil
		}
		selection, parseErr := strconv.Atoi(line)
		if parseErr == nil && selection >= 1 && selection <= len(ordered) {
			return ordered[selection-1], nil
		}
		fmt.Fprintf(out, "Enter a number between 1 and %d.\n", len(ordered))
		if readErr != nil {
			return proto.AuthMethod{}, fmt.Errorf("choose unlock method: %w", readErr)
		}
	}
}

func unlockMethodLabel(method proto.AuthMethod) string {
	label := terminalSafe(method.MethodType)
	switch method.MethodType {
	case proto.AuthPassphrase:
		label = "Passphrase"
	case proto.AuthYubikey:
		switch yubikeyPINPromptMode(method) {
		case yubikeyPINPromptNever:
			label = "YubiKey (touch only)"
		case yubikeyPINPromptRequired:
			label = "YubiKey (PIN)"
		default:
			label = "YubiKey"
		}
	}
	if method.MethodID == "" {
		return label
	}
	id := terminalSafe(method.MethodID)
	if len(id) > 14 {
		id = id[:14] + "…"
	}
	return label + " · " + id
}

func friendlyUnlockError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, vault.ErrYubikeyNotConfigured) {
		return errors.New("YubiKey unlock is enrolled, but the running fd0-agent was built without YubiKey/PIV support; install the yubikey flavor and run `fd0 agent restart`")
	}
	msg := err.Error()
	if strings.Contains(msg, "unlock timed out") ||
		strings.Contains(msg, "i/o timeout") {
		return errors.New("unlock timed out; run `fd0 agent status` before retrying because the agent may already have completed the unlock")
	}
	if strings.Contains(msg, "pin longer than 8 bytes") ||
		strings.Contains(msg, "yubikey PIN: must be at most 8 characters") {
		return errors.New("YubiKey PIV PINs are 6-8 ASCII characters; if this key was enrolled as touch-only, press Enter instead of entering your fd0 passphrase")
	}
	if strings.Contains(msg, "message authentication failed") ||
		strings.Contains(msg, "no matching auth method or wrong credential") {
		return errors.New("unlock failed: wrong passphrase or unlock method; if this worked before, the vault or auth chain may be inconsistent")
	}
	return err
}

type readPINFunc func(prompt string) ([]byte, error)

func readYubikeyUnlockPIN(m proto.AuthMethod, readPIN readPINFunc) ([]byte, error) {
	switch yubikeyPINPromptMode(m) {
	case yubikeyPINPromptNever:
		// Touch-only methods were enrolled with PINPolicyNever. Do not
		// prompt for unrelated credentials; the agent receives an empty
		// PIN and the card enforces touch policy.
		return nil, nil
	case yubikeyPINPromptRequired:
		pin, err := readPIN("YubiKey PIV PIN: ")
		if err != nil {
			return nil, err
		}
		if len(pin) == 0 {
			return nil, errors.New("YubiKey PIV PIN cannot be empty for this auth method")
		}
		return pin, nil
	default:
		return readPIN("YubiKey PIV PIN (press Enter for touch-only legacy methods): ")
	}
}

type yubikeyPINPrompt int

const (
	yubikeyPINPromptOptional yubikeyPINPrompt = iota
	yubikeyPINPromptNever
	yubikeyPINPromptRequired
)

func yubikeyPINPromptMode(m proto.AuthMethod) yubikeyPINPrompt {
	var pp proto.YubikeyPublicParams
	if err := proto.Unmarshal(m.PublicParams, &pp); err != nil {
		return yubikeyPINPromptOptional
	}
	switch strings.ToLower(strings.TrimSpace(pp.PinPolicy)) {
	case "never":
		return yubikeyPINPromptNever
	case "once", "always":
		return yubikeyPINPromptRequired
	default:
		return yubikeyPINPromptOptional
	}
}

func shouldHintInteractiveFirstSync(configPath string, ur *agent.UnlockResp) bool {
	if os.Getenv(FD0AutoPinEnv) == "1" || ur == nil || len(ur.RedactedBody) == 0 {
		return false
	}
	cfg, err := fdhome.LoadConfig(configPath)
	if err != nil || !cfg.Sync.OnUnlockEnabled() {
		return false
	}
	var body proto.VaultBody
	if err := proto.Unmarshal(ur.RedactedBody, &body); err != nil {
		return false
	}
	return len(body.PinnedServers) == 0
}

// pickUnlockMethod implements the method-selection rules documented on
// RunUnlock. Returns a copy of the chosen AuthMethod (so the caller
// holds nothing that aliases the chain replay state).
func pickUnlockMethod(active []proto.AuthMethod, requested string) (proto.AuthMethod, error) {
	if len(active) == 0 {
		return proto.AuthMethod{}, errors.New("no active auth methods")
	}
	if requested != "" {
		requested = strings.TrimSpace(requested)
		for _, m := range active {
			if m.MethodID == requested {
				return m, nil
			}
		}
		for _, m := range active {
			if m.MethodType == requested {
				return m, nil
			}
		}
		return proto.AuthMethod{}, fmt.Errorf("--method=%q: no enrolled method matches; have %s",
			requested, summariseMethodSelectors(active))
	}
	// No request: pick the FIRST method by method_id. We do NOT pick
	// "the only type" because deterministic ordering matters more than
	// "guess what the user meant"; --method gives the override knob.
	out := active[0]
	for _, m := range active[1:] {
		if m.MethodID < out.MethodID {
			out = m
		}
	}
	return out, nil
}

// distinctMethodTypes returns the set of distinct method types
// present in `active`. Used to detect ambiguous method choices.
func distinctMethodTypes(active []proto.AuthMethod) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(active))
	for _, m := range active {
		if _, ok := seen[m.MethodType]; ok {
			continue
		}
		seen[m.MethodType] = struct{}{}
		out = append(out, m.MethodType)
	}
	return out
}

func summariseMethodTypes(active []proto.AuthMethod) string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(active))
	for _, m := range active {
		if _, ok := seen[m.MethodType]; ok {
			continue
		}
		seen[m.MethodType] = struct{}{}
		out = append(out, m.MethodType)
	}
	return strings.Join(out, ", ")
}

func summariseMethodSelectors(active []proto.AuthMethod) string {
	types := summariseMethodTypes(active)
	ids := make([]string, 0, len(active))
	for _, m := range active {
		if m.MethodID != "" {
			ids = append(ids, m.MethodID)
		}
	}
	if len(ids) == 0 {
		return types
	}
	if types == "" {
		return strings.Join(ids, ", ")
	}
	return types + " (method ids: " + strings.Join(ids, ", ") + ")"
}

// RunLock asks the running agent to forget vault secrets.
func RunLock(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		fmt.Fprintln(os.Stderr, "agent is not running")
		return nil
	}
	if err := cli.Lock(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ vault locked")
	if st, err := cli.Status(); err == nil && st.SSHGrantCount+st.SecretGrantCount > 0 {
		fmt.Fprintf(os.Stderr, "%d SSH grants and %d value grants remain active; use fd0 lock --all to stop them.\n", st.SSHGrantCount, st.SecretGrantCount)
	}
	return nil
}

// statusJSON is the machine-readable `fd0 status --json` shape.
type statusJSON struct {
	Agent         string         `json:"agent"` // "running" or "not_running"
	Unlocked      bool           `json:"unlocked"`
	SSHGrantCount    int            `json:"sshGrantCount"`
	SecretGrantCount int            `json:"secretGrantCount"`
	Servers       []pinnedStatus `json:"servers,omitempty"`
}

// pinnedStatus is a pinned server and its safety number, so another device
// (for example a machine identity using `fd0 sync --pin`) can be checked
// against it.
type pinnedStatus struct {
	URL          string `json:"url"`
	SafetyNumber string `json:"safetyNumber"`
}

// pinnedServers lists the vault's pinned servers; it needs an unlocked vault.
func pinnedServers(ctx context.Context) ([]pinnedStatus, error) {
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	out := make([]pinnedStatus, 0, len(s.Body.PinnedServers))
	for url, pin := range s.Body.PinnedServers {
		fp, err := ServerFingerprint(url, pin.ServerPub)
		if err != nil {
			return nil, err
		}
		out = append(out, pinnedStatus{URL: url, SafetyNumber: fp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, nil
}

// RunStatus prints agent state.
// Pinned servers are read only on request: opening the vault refreshes the
// agent's idle timer, and status is often polled.
func RunStatus(ctx context.Context, asJSON, withServers bool) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(statusJSON{Agent: "not_running"})
		}
		fmt.Println("agent: not running")
		return nil
	}
	st, err := cli.Status()
	if err != nil {
		return err
	}
	var servers []pinnedStatus
	if st.Unlocked && withServers {
		if servers, err = pinnedServers(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read pinned servers: %v\n", err)
		}
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(statusJSON{Agent: "running", Unlocked: st.Unlocked, SSHGrantCount: st.SSHGrantCount, SecretGrantCount: st.SecretGrantCount, Servers: servers})
	}
	if st.SSHGrantCount > 0 {
		fmt.Printf("SSH grants: %d active (fd0 lock --all stops them)\n", st.SSHGrantCount)
	}
	if st.SecretGrantCount > 0 {
		fmt.Printf("Value grants: %d active (fd0 lock --all stops them)\n", st.SecretGrantCount)
	}
	if !st.Unlocked {
		fmt.Println("agent: running, locked")
		return nil
	}
	fmt.Printf("agent:  running, unlocked since %d\n", st.SinceUnix)
	fmt.Printf("super_pub: %s\n", b64full(st.UserSuperPub))
	for _, srv := range servers {
		fmt.Printf("server: %s\nsafety number:\n%s\n", srv.URL, indent(srv.SafetyNumber, "  "))
	}
	return nil
}

// b64sub returns the first 12 base64 chars of b for human prefixes.
func b64sub(b []byte) string {
	s := b64full(b)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func b64full(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(b)+2)/3*4)
	n := len(b)
	for i := 0; i < n; i += 3 {
		var v uint32
		switch {
		case i+3 <= n:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		case i+2 == n:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8
		default:
			v = uint32(b[i]) << 16
		}
		out = append(out, enc[(v>>18)&63], enc[(v>>12)&63], enc[(v>>6)&63], enc[v&63])
	}
	switch n % 3 {
	case 1:
		out = out[:len(out)-2]
		out = append(out, '=', '=')
	case 2:
		out = out[:len(out)-1]
		out = append(out, '=')
	}
	return string(out)
}

const agentReadyTimeout = 5 * 1000_000_000 // 5s in nanoseconds; small enough.

// guard so go vet doesn't flag ed25519 unused if removed by edits.
var _ = ed25519.PublicKeySize
