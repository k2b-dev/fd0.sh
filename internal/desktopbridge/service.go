package desktopbridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

const isolatedMarker = "fd0-desktop-isolated-v1\n"

const (
	hostedServerURL    = "https://api.fd0.sh"
	hostedServerPubHex = "bf7109e16fbcc477dba8d446751b67249633a4ea047ff06cc6ca90f4a5cc8218"
)

type Service struct {
	Home            string
	AgentBin        string
	Mode            string
	ExpectedVersion string
	ExpectedFlavor  string
	HostedServerURL string
	HostedServerPub []byte
}

type HandshakeResult struct {
	Protocol     int      `json:"protocol"`
	Capabilities []string `json:"capabilities"`
	Mode         string   `json:"mode"`
}

type StatusResult struct {
	VaultExists  bool `json:"vaultExists"`
	AgentRunning bool `json:"agentRunning"`
	// AgentIncompatible is set only when the running agent genuinely cannot
	// serve this app (see inspectAgent); a different release version is not
	// such a case. AgentIncompatibleReason is one sentence, fit to display.
	AgentIncompatible       bool   `json:"agentIncompatible,omitempty"`
	AgentIncompatibleReason string `json:"agentIncompatibleReason,omitempty"`
	// AgentStartedBy is agentStartedByDesktop or agentStartedByExternal while
	// an agent runs, and empty otherwise.
	AgentStartedBy    string              `json:"agentStartedBy,omitempty"`
	Unlocked          bool                `json:"unlocked"`
	UnlockedSince     int64               `json:"unlockedSince,omitempty"`
	Version           string              `json:"version,omitempty"`
	Flavor            string              `json:"flavor,omitempty"`
	ExpectedVersion   string              `json:"expectedVersion,omitempty"`
	ExpectedFlavor    string              `json:"expectedFlavor,omitempty"`
	Yubikey           bool                `json:"yubikey"`
	IdleTimeoutMillis int64               `json:"idleTimeoutMillis,omitempty"`
	MaxLifetimeMillis int64               `json:"maxLifetimeMillis,omitempty"`
	AuthMethods       []AuthMethodSummary `json:"authMethods,omitempty"`
	Readiness         ReadinessState      `json:"readiness"`
}

type AuthMethodSummary struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	PINMode     string `json:"pinMode,omitempty"`
	TouchPolicy string `json:"touchPolicy,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

type SyncPreparation struct {
	ServerURL            string `json:"serverUrl"`
	ServerPub            string `json:"serverPub"`
	Fingerprint          string `json:"fingerprint"`
	Label                string `json:"label,omitempty"`
	Hosted               bool   `json:"hosted"`
	AlreadyPinned        bool   `json:"alreadyPinned"`
	RequiresConfirmation bool   `json:"requiresConfirmation"`
}

func NewServiceFromEnv() (*Service, error) {
	mode := strings.TrimSpace(os.Getenv("FD0_DESKTOP_MODE"))
	if mode == "" {
		mode = "system"
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	home, err := filepath.Abs(paths.Home)
	if err != nil {
		return nil, err
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	productionHome := filepath.Clean(filepath.Join(userHome, ".fd0"))
	if mode == "isolated" {
		resolvedHome, err := filepath.EvalSymlinks(home)
		if err != nil {
			return nil, fmt.Errorf("desktop bridge: resolve isolated home: %w", err)
		}
		resolvedProductionHome := evalPathIfPresent(productionHome)
		if pathWithin(resolvedProductionHome, resolvedHome) {
			return nil, errors.New("desktop bridge: isolated mode refuses the production fd0 home")
		}
		markerPath := filepath.Join(home, ".desktop-isolated")
		markerInfo, err := os.Lstat(markerPath)
		if err != nil {
			return nil, fmt.Errorf("desktop bridge: isolated home marker: %w", err)
		}
		if markerInfo.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("desktop bridge: isolated home marker must not be a symlink")
		}
		marker, err := os.ReadFile(markerPath)
		if err != nil {
			return nil, fmt.Errorf("desktop bridge: isolated home marker: %w", err)
		}
		if string(marker) != isolatedMarker {
			return nil, errors.New("desktop bridge: invalid isolated home marker")
		}
		sshSock := strings.TrimSpace(os.Getenv("FD0_SSH_SOCK"))
		if sshSock == "" {
			return nil, errors.New("desktop bridge: FD0_SSH_SOCK is required in isolated mode")
		}
		if !filepath.IsAbs(sshSock) {
			return nil, errors.New("desktop bridge: FD0_SSH_SOCK must be absolute")
		}
		sshSock = filepath.Clean(sshSock)
		resolvedSSHSock := evalPathIfPresent(sshSock)
		if resolvedSSHSock == evalPathIfPresent(paths.AgentSock) {
			return nil, errors.New("desktop bridge: FD0_SSH_SOCK must differ from the fd0 agent socket")
		}
		if pathWithin(resolvedProductionHome, resolvedSSHSock) || resolvedSSHSock == evalPathIfPresent(productionSSHSocketPath()) {
			return nil, errors.New("desktop bridge: isolated mode refuses the production SSH agent socket")
		}
		if os.Getenv("FD0_AGENT_SYNC_DISABLED") != "1" {
			return nil, errors.New("desktop bridge: isolated mode requires FD0_AGENT_SYNC_DISABLED=1")
		}
	} else if mode != "system" {
		return nil, fmt.Errorf("desktop bridge: unsupported mode %q", mode)
	}
	agentBin := strings.TrimSpace(os.Getenv("FD0_AGENT_BIN"))
	if agentBin == "" {
		return nil, errors.New("desktop bridge: FD0_AGENT_BIN is required")
	}
	hostedPub, err := hex.DecodeString(hostedServerPubHex)
	if err != nil || len(hostedPub) != 32 {
		return nil, errors.New("desktop bridge: invalid embedded hosted server identity")
	}
	return &Service{
		Home:            home,
		AgentBin:        agentBin,
		Mode:            mode,
		ExpectedVersion: strings.TrimSpace(os.Getenv("FD0_DESKTOP_VERSION")),
		ExpectedFlavor:  buildinfo.Flavor,
		HostedServerURL: hostedServerURL,
		HostedServerPub: hostedPub,
	}, nil
}

func WriteIsolatedMarker(home string) error {
	if !filepath.IsAbs(home) {
		return errors.New("isolated fd0 home must be absolute")
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	productionHome := evalPathIfPresent(filepath.Join(userHome, ".fd0"))
	if pathWithin(productionHome, evalPathIfPresent(home)) {
		return errors.New("refusing to mark the production fd0 home as isolated")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(home)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("isolated fd0 home must not be a symlink")
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return err
	}
	if pathWithin(productionHome, resolvedHome) {
		return errors.New("refusing to mark the production fd0 home as isolated")
	}
	return os.WriteFile(filepath.Join(home, ".desktop-isolated"), []byte(isolatedMarker), 0o600)
}

func evalPathIfPresent(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs
	}
	return filepath.Join(evalPathIfPresent(parent), filepath.Base(abs))
}

func pathWithin(base, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func productionSSHSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join("/tmp", "fd0")
	} else {
		dir = filepath.Join(dir, "fd0")
	}
	return filepath.Join(dir, "ssh-"+strconv.Itoa(os.Getuid())+".sock")
}

func (s *Service) Handle(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "bridge.handshake":
		return HandshakeResult{
			Protocol: ProtocolVersion,
			Mode:     s.Mode,
			Capabilities: []string{
				"status", "unlock", "lock", "inventory", "item-detail",
				"item-history", "item-version", "item-restore",
				"deleted-items", "totp-parse",
				"field-value", "pass-save", "secret-save", "ssh-host-save",
				"ssh-key-list", "ssh-key-generate", "ssh-key-edit",
				"config-import", "item-move", "item-rename", "item-remove", "scope-create",
				"scope-rename", "scope-leave", "scope-share", "scope-members", "identity-cards",
				"recovery-export", "recovery-import", "auth-default", "agent-prepare-update",
				"agent-restart", "structured-sync",
			},
		}, nil
	case "vault.status":
		return s.status()
	case "vault.unlock":
		var params struct {
			Passphrase []byte `json:"passphrase"`
			PIN        []byte `json:"pin,omitempty"`
			Method     string `json:"method,omitempty"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Passphrase)
		defer crypto.Wipe(params.PIN)
		return s.unlock(ctx, params.Method, params.Passphrase, params.PIN)
	case "vault.create":
		var params struct {
			Passphrase []byte `json:"passphrase"`
			Label      string `json:"label"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Passphrase)
		return s.createVault(ctx, params.Passphrase, params.Label)
	case "vault.lock":
		return s.lock()
	case "agent.prepareUpdate":
		return s.prepareUpdate()
	case "agent.restart":
		return s.restartAgent()
	case "recovery.export":
		var params struct {
			Passphrase []byte `json:"passphrase"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Passphrase)
		if len(params.Passphrase) < 12 {
			return nil, fail("validation", "Use a recovery passphrase with at least 12 characters.", "A longer generated phrase is safer.", false)
		}
		data, err := cli.ExportRecoveryWithPassphrase(ctx, params.Passphrase)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return struct {
			Data []byte `json:"data"`
		}{Data: data}, nil
	case "recovery.exportFile":
		var params struct {
			Path       string `json:"path"`
			Passphrase []byte `json:"passphrase"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Passphrase)
		if len(params.Passphrase) < 12 {
			return nil, fail("validation", "Use a recovery passphrase with at least 12 characters.", "A longer generated phrase is safer.", false)
		}
		return s.exportRecoveryFile(ctx, params.Path, params.Passphrase)
	case "recovery.import":
		var params struct {
			Data               []byte `json:"data"`
			RecoveryPassphrase []byte `json:"recoveryPassphrase"`
			NewPassphrase      []byte `json:"newPassphrase"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Data)
		defer crypto.Wipe(params.RecoveryPassphrase)
		defer crypto.Wipe(params.NewPassphrase)
		if len(params.Data) == 0 || len(params.Data) > 4*1024*1024 {
			return nil, fail("validation", "That recovery file is empty or too large.", "Choose an fd0 recovery file smaller than 4 MB.", false)
		}
		version, err := cli.RecoveryVersion(params.Data)
		if err != nil {
			return nil, mapRecoveryError(err)
		}
		if version == 1 && len(params.NewPassphrase) < 12 {
			return nil, fail("validation", "Use a local passphrase with at least 12 characters.", "This passphrase protects the restored vault on this device.", false)
		}
		if _, err := cli.ImportRecoveryWithPassphrases(ctx, params.Data, params.RecoveryPassphrase, params.NewPassphrase); err != nil {
			return nil, mapRecoveryError(err)
		}
		paths, err := fdhome.Resolve()
		if err != nil {
			return nil, err
		}
		state, err := chain.ReplayUser(paths.UserChain)
		if err != nil || state == nil {
			return nil, errors.New("restored user chain is unavailable")
		}
		if err := markRecoveryVerified(paths, state.TipHash); err != nil {
			return nil, err
		}
		return s.status()
	case "recovery.inspect":
		var params struct {
			Data []byte `json:"data"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Data)
		if len(params.Data) == 0 || len(params.Data) > 4*1024*1024 {
			return nil, fail("validation", "That recovery file is empty or too large.", "Choose an fd0 recovery file smaller than 4 MB.", false)
		}
		version, err := cli.RecoveryVersion(params.Data)
		if err != nil {
			return nil, mapRecoveryError(err)
		}
		return struct {
			Version uint8 `json:"version"`
		}{Version: version}, nil
	case "auth.default":
		var params struct {
			Method string `json:"method"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.setDefaultAuthMethod(params.Method)
	case "inventory.list":
		return s.listInventory(ctx)
	case "deleted.list":
		return s.deletedItems(ctx)
	case "totp.parse":
		var params struct {
			URI string `json:"uri"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		value, err := passitem.ParseTOTPURI(params.URI)
		if err != nil {
			return nil, fail("validation", "That setup link is not a valid TOTP account.", err.Error(), false)
		}
		return value, nil
	case "item.detail":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.itemDetail(ctx, params)
	case "item.history":
		var params ItemHistoryParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.itemHistory(ctx, params)
	case "item.version":
		var params ItemVersionParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.itemVersion(ctx, params)
	case "item.restore":
		var params ItemRestoreParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.itemRestore(ctx, params)
	case "field.value":
		var params FieldValueParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.fieldValue(ctx, params)
	case "file.value":
		var params FieldValueParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.fieldAttachment(ctx, params)
	case "pass.save":
		var params SavePassParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.savePass(ctx, params)
	case "pass.editData":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.passEditData(ctx, params)
	case "pass.favorite":
		var params struct {
			RecordRef
			Favorite bool `json:"favorite"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.setPassFavorite(ctx, params.RecordRef, params.Favorite)
	case "secret.save":
		var params SaveSecretParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.saveSecret(ctx, params)
	case "secret.editData":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.secretEditData(ctx, params)
	case "sshHost.save":
		var params SaveSSHHostParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.saveSSHHost(ctx, params)
	case "sshHost.editData":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.sshHostEditData(ctx, params)
	case "sshKey.generate":
		var params GenerateSSHKeyParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.generateSSHKey(ctx, params)
	case "sshKey.list":
		var params struct {
			ScopeID string `json:"scopeId"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.listSSHKeys(ctx, params.ScopeID)
	case "sshKey.editData":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.sshKeyEditData(ctx, params)
	case "sshKey.save":
		var params SaveSSHKeyParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.saveSSHKey(ctx, params)
	case "config.import":
		var params ImportConfigParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		defer crypto.Wipe(params.Data)
		return s.importConfig(ctx, params)
	case "item.remove":
		var params RecordRef
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.removeItem(ctx, params)
	case "item.move":
		var params MoveItemParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.moveItem(ctx, params)
	case "item.rename":
		var params RenameItemParams
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.renameItem(ctx, params)
	case "scope.create":
		var params struct {
			Label string `json:"label"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		if strings.TrimSpace(params.Label) == "" {
			return nil, fail("validation", "Vault name is required.", "", false)
		}
		if err := cli.RunScopeCreate(ctx, strings.TrimSpace(params.Label)); err != nil {
			return nil, mapDomainError(err)
		}
		return map[string]bool{"ok": true}, nil
	case "scope.rename":
		var params struct {
			ScopeID string `json:"scopeId"`
			Label   string `json:"label"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		if _, err := proto.ParseScopeID(params.ScopeID); err != nil {
			return nil, fail("validation", "That vault reference is invalid.", "", false)
		}
		params.Label = strings.TrimSpace(params.Label)
		if params.Label == "" {
			return nil, fail("validation", "Vault name is required.", "", false)
		}
		if err := cli.RunScopeRename(ctx, params.ScopeID, params.Label); err != nil {
			return nil, mapDomainError(err)
		}
		return map[string]bool{"ok": true}, nil
	case "scope.leave":
		var params struct {
			ScopeID string `json:"scopeId"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		if _, err := proto.ParseScopeID(params.ScopeID); err != nil {
			return nil, fail("validation", "That vault reference is invalid.", "", false)
		}
		if err := cli.RunScopeLeave(ctx, params.ScopeID, true); err != nil {
			return nil, mapDomainError(err)
		}
		return map[string]bool{"ok": true}, nil
	case "scope.shareInfo":
		var params struct {
			ScopeID string `json:"scopeId"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.scopeShareInfo(ctx, params.ScopeID)
	case "scope.addMember":
		var params struct {
			ScopeID string `json:"scopeId"`
			Label   string `json:"label"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.addScopeMember(ctx, params.ScopeID, params.Label)
	case "scope.removeMember":
		var params struct {
			ScopeID  string `json:"scopeId"`
			MemberID string `json:"memberId"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.removeScopeMember(ctx, params.ScopeID, params.MemberID)
	case "card.export":
		return s.exportIdentityCard(ctx)
	case "card.inspect":
		var params struct {
			URL string `json:"url"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.inspectIdentityCard(params.URL)
	case "card.import":
		var params struct {
			URL   string `json:"url"`
			Label string `json:"label"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.importIdentityCard(ctx, params.URL, params.Label)
	case "sync.prepare":
		if s.Mode == "isolated" {
			return nil, fail("sync_disabled", "Sync is disabled for the isolated development vault.", "Use a dedicated test server before enabling sync.", false)
		}
		return s.prepareSync(ctx)
	case "sync.pin":
		if s.Mode == "isolated" {
			return nil, fail("sync_disabled", "Sync is disabled for the isolated development vault.", "Use a dedicated test server before enabling sync.", false)
		}
		var params struct {
			ServerURL string `json:"serverUrl"`
			ServerPub string `json:"serverPub"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		return s.pinSyncServer(ctx, params.ServerURL, params.ServerPub)
	case "sync.run":
		if s.Mode == "isolated" {
			return nil, fail("sync_disabled", "Sync is disabled for the isolated development vault.", "Use a dedicated test server before enabling sync.", false)
		}
		var params struct {
			ServerURL string `json:"serverUrl"`
		}
		if err := decodeParams(raw, &params); err != nil {
			return nil, err
		}
		if err := s.validateCurrentServer(params.ServerURL); err != nil {
			return nil, err
		}
		if err := cli.RunSyncPrimary(ctx, params.ServerURL); err != nil {
			return nil, mapDomainError(err)
		}
		paths, err := fdhome.Resolve()
		if err != nil {
			return nil, err
		}
		if err := markSyncComplete(paths); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, nil
	default:
		return nil, fail("unknown_method", "The desktop app requested an unsupported operation.", "Update fd0 Desktop.", false)
	}
}

func (s *Service) prepareSync(ctx context.Context) (*SyncPreparation, error) {
	server, err := cli.ResolvePrimary("")
	if err != nil {
		return nil, mapDomainError(err)
	}
	preview, err := cli.InspectServer(ctx, server)
	if err != nil {
		return nil, mapDomainError(err)
	}
	hosted := preview.URL == s.HostedServerURL
	if hosted && !bytes.Equal(preview.ServerPub, s.HostedServerPub) {
		return nil, fail(
			"hosted_server_identity_mismatch",
			"fd0 stopped because the hosted service identity does not match this app release.",
			"Do not continue. Update fd0 Desktop or contact fd0 support.",
			false,
		)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	alreadyPinned := false
	if pinned, ok := session.Body.PinnedServers[preview.URL]; ok {
		if !bytes.Equal(pinned.ServerPub, preview.ServerPub) {
			return nil, mapDomainError(cli.ErrPinnedKeyMismatch)
		}
		alreadyPinned = true
	}
	return &SyncPreparation{
		ServerURL:            preview.URL,
		ServerPub:            hex.EncodeToString(preview.ServerPub),
		Fingerprint:          preview.Fingerprint,
		Label:                preview.Label,
		Hosted:               hosted,
		AlreadyPinned:        alreadyPinned,
		RequiresConfirmation: !hosted && !alreadyPinned,
	}, nil
}

func (s *Service) pinSyncServer(ctx context.Context, serverURL, serverPub string) (map[string]bool, error) {
	if err := s.validateCurrentServer(serverURL); err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(strings.TrimSpace(serverPub))
	if err != nil || len(pub) != 32 {
		return nil, fail("bad_request", "fd0 received an invalid server identity.", "Start the sync again.", false)
	}
	if serverURL == s.HostedServerURL && !bytes.Equal(pub, s.HostedServerPub) {
		return nil, fail(
			"hosted_server_identity_mismatch",
			"fd0 stopped because the hosted service identity does not match this app release.",
			"Do not continue. Update fd0 Desktop or contact fd0 support.",
			false,
		)
	}
	if err := cli.PinServer(ctx, serverURL, pub); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) validateCurrentServer(serverURL string) error {
	current, err := cli.ResolvePrimary("")
	if err != nil {
		return mapDomainError(err)
	}
	previewURL, err := cli.NormalizeServerURL(serverURL)
	if err != nil {
		return fail("bad_request", "fd0 received an invalid server address.", "Start the sync again.", false)
	}
	currentURL, err := cli.NormalizeServerURL(current)
	if err != nil {
		return mapDomainError(err)
	}
	if previewURL != currentURL {
		return fail("server_changed", "The configured fd0 service changed while sync was starting.", "Review the service setting and start sync again.", true)
	}
	return nil
}

func decodeParams(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decodeOne(decoder, target); err != nil {
		return fail("bad_request", "The desktop app sent invalid data.", "", false)
	}
	return nil
}

func (s *Service) status() (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	result := StatusResult{
		Yubikey:         buildinfo.YubikeyEnabled,
		ExpectedVersion: s.ExpectedVersion,
		ExpectedFlavor:  s.ExpectedFlavor,
	}
	if result.Readiness, err = loadReadiness(paths); err != nil {
		return StatusResult{}, err
	}
	if _, err := os.Stat(paths.Vault); err == nil {
		result.VaultExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return StatusResult{}, err
	}
	if result.VaultExists {
		state, err := chain.ReplayUser(paths.UserChain)
		if err != nil {
			return StatusResult{}, mapDomainError(err)
		}
		if state != nil && result.Readiness.RecoveryAuthTip != "" && result.Readiness.RecoveryAuthTip != hex.EncodeToString(state.TipHash) {
			result.Readiness.RecoveryVerifiedAt = 0
		}
		methods, err := authMethodSummaries(paths)
		if err != nil {
			return StatusResult{}, mapDomainError(err)
		}
		result.AuthMethods = methods
	}
	client := agent.NewClient(paths.AgentSock)
	if !client.IsRunning() {
		return result, nil
	}
	result.AgentRunning = true
	status, err := client.Status()
	if err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	result.Unlocked = status.Unlocked
	result.UnlockedSince = status.SinceUnix
	result.Version = status.Version
	result.Flavor = status.Flavor
	result.Yubikey = status.YubikeyEnabled
	result.IdleTimeoutMillis = status.IdleTimeoutMillis
	result.MaxLifetimeMillis = status.MaxLifetimeMillis
	result.AgentStartedBy = agentStartedBy(status)
	if use := s.inspectAgent(status); !use.compatible {
		result.AgentIncompatible = true
		result.AgentIncompatibleReason = use.reason
	}
	return result, nil
}

func (s *Service) exportRecoveryFile(ctx context.Context, path string, passphrase []byte) (map[string]bool, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, fail("validation", "Choose a valid recovery file location.", "", false)
	}
	data, err := cli.ExportRecoveryWithPassphrase(ctx, passphrase)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer crypto.Wipe(data)
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	expectedPub := append([]byte(nil), session.UserSuperPub...)
	if session.UserState == nil {
		session.Close()
		return nil, errors.New("user chain is unavailable")
	}
	authTip := append([]byte(nil), session.UserState.TipHash...)
	session.Close()
	if err := cli.VerifyRecoveryWithPassphrase(data, passphrase, expectedPub); err != nil {
		return nil, mapRecoveryError(err)
	}
	staged := path + ".new"
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(staged, path); err != nil {
		_ = os.Remove(staged)
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	if err := markRecoveryVerified(paths, authTip); err != nil {
		return nil, err
	}
	return map[string]bool{"saved": true, "verified": true}, nil
}

// Values of StatusResult.AgentStartedBy.
const (
	agentStartedByDesktop  = "desktop"
	agentStartedByExternal = "external"
)

// agentUsability answers "can this app work with the agent that currently
// serves this home", plus the reason when it cannot, phrased for the user.
type agentUsability struct {
	compatible bool
	reason     string
}

// inspectAgent applies the compatibility rule.
//
// Compatibility means "can serve", not "same release string". There is exactly
// one agent per FD0_HOME, and on any machine with a separately installed CLI it
// is perfectly normal for that agent to come from a different release than the
// desktop app — they are shipped and updated independently. Comparing release
// versions therefore declared healthy setups broken forever, and the app then
// tried to restart an agent it could not replace.
//
// Two things actually decide it:
//
//   - Protocol. agent.ProtocolVersion covers the op codes and frame shapes the
//     two sides exchange, and is bumped only when an old peer would misread a
//     reply. Agents built before the field report 0, and every one of those
//     releases speaks protocol 1, so 0 is read as 1.
//   - Flavor. A standard-flavor agent has no PIV support compiled in and truly
//     cannot unlock a YubiKey vault, so a YubiKey build cannot borrow one. The
//     other direction is fine: a yubikey agent does everything a standard one
//     does, so a standard app is happy with it.
//
// The release version is carried for display and diagnostics only.
func (s *Service) inspectAgent(status *agent.StatusResp) agentUsability {
	if status == nil {
		return agentUsability{reason: "The fd0 background service did not report its status."}
	}
	protocol := status.Protocol
	if protocol == 0 {
		protocol = 1
	}
	if protocol != agent.ProtocolVersion {
		return agentUsability{reason: fmt.Sprintf(
			"The running service speaks fd0 service protocol %d and this app speaks %d.", protocol, agent.ProtocolVersion)}
	}
	if buildinfo.NormalizeFlavor(s.ExpectedFlavor) == buildinfo.FlavorYubikey &&
		buildinfo.NormalizeFlavor(status.Flavor) != buildinfo.FlavorYubikey {
		return agentUsability{reason: "The running service was built without YubiKey support, so it cannot unlock a YubiKey vault."}
	}
	return agentUsability{compatible: true}
}

// agentStartedBy reports whether this app started the running agent. Anything
// that does not say "desktop" — including agents older than the field — counts
// as external, because ownership is what licenses stopping a process and this
// app must never assume ownership it cannot prove.
func agentStartedBy(status *agent.StatusResp) string {
	if status != nil && status.StartedBy == agent.StartedByDesktop {
		return agentStartedByDesktop
	}
	return agentStartedByExternal
}

// Both sentinels block stopping the running agent. They differ only in what
// this app can honestly say about it.
var (
	errForeignAgent  = errors.New("desktop bridge: the running agent was started by another program")
	errUnprovenAgent = errors.New("desktop bridge: the running agent did not report who started it")
)

// stopOwnAgent stops the agent only when this app started it. A shell-started
// agent holds the keys of that shell session; terminating it would lock the
// user out of their own terminal, which is never this app's call — no matter
// which button in this app was pressed. Unprovable ownership fails closed:
// `fd0 agent stop` remains the way out, and it needs no answer from the agent.
func stopOwnAgent(paths fdhome.Paths) error {
	client := agent.NewClient(paths.AgentSock)
	if client.IsRunning() {
		status, err := client.Status()
		if err != nil {
			return errUnprovenAgent
		}
		if agentStartedBy(status) != agentStartedByDesktop {
			return errForeignAgent
		}
	}
	return stopDesktopAgent(paths)
}

// notOurAgentError phrases a refusal to stop somebody else's agent. missed says
// what this app therefore could not do; action says what the user can do.
func notOurAgentError(err error, missed, action string) error {
	cause := "Another program started the fd0 background service."
	if errors.Is(err, errUnprovenAgent) {
		cause = "The fd0 background service is running but did not report who started it."
	}
	return fail(
		"agent_not_ours",
		cause+" fd0 Desktop does not stop a service it did not start, so it cannot "+missed+".",
		action,
		true,
	)
}

// unusableAgentError explains a running-but-unusable agent and, crucially,
// points at the program that owns it instead of at this app's repair button.
func unusableAgentError(use agentUsability, startedBy string) error {
	if startedBy == agentStartedByDesktop {
		return fail("agent_incompatible", use.reason, "Restart the local service from Support.", true)
	}
	return fail(
		"agent_incompatible_foreign",
		"Another program started the fd0 background service for this vault, and this app cannot use it. "+use.reason,
		"fd0 Desktop does not stop a service it did not start. Run `fd0 agent stop` in the terminal you started it from, then try again.",
		true,
	)
}

func authMethodSummaries(paths fdhome.Paths) ([]AuthMethodSummary, error) {
	state, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		return nil, err
	}
	if state == nil || state.LatestAuthSet == nil {
		return nil, nil
	}
	defaultMethod := ""
	if cfg, err := fdhome.LoadConfig(paths.Config); err == nil {
		defaultMethod = strings.TrimSpace(cfg.Auth.DefaultMethod)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	methods := append([]proto.AuthMethod(nil), state.LatestAuthSet.Payload.Active...)
	sortAuthMethods(methods)
	result := make([]AuthMethodSummary, 0, len(methods))
	for _, method := range methods {
		summary := AuthMethodSummary{
			ID:      method.MethodID,
			Type:    method.MethodType,
			Default: defaultMethod == method.MethodID || defaultMethod == method.MethodType,
		}
		switch method.MethodType {
		case proto.AuthPassphrase:
			summary.Label = "Passphrase"
		case proto.AuthYubikey:
			summary.Label = "YubiKey"
			summary.PINMode = yubikeyPINMode(method)
			var params proto.YubikeyPublicParams
			if err := proto.Unmarshal(method.PublicParams, &params); err == nil {
				summary.TouchPolicy = strings.ToLower(strings.TrimSpace(params.TouchPolicy))
			}
		default:
			summary.Label = method.MethodType
		}
		result = append(result, summary)
	}
	return result, nil
}

func sortAuthMethods(methods []proto.AuthMethod) {
	for i := 1; i < len(methods); i++ {
		for j := i; j > 0 && methods[j].MethodID < methods[j-1].MethodID; j-- {
			methods[j], methods[j-1] = methods[j-1], methods[j]
		}
	}
}

func selectAuthMethod(paths fdhome.Paths, methods []proto.AuthMethod, selector string) (*proto.AuthMethod, error) {
	if len(methods) == 0 {
		return nil, fail("method_unavailable", "This vault has no active unlock method.", "Open Support before changing local files.", false)
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		if cfg, err := fdhome.LoadConfig(paths.Config); err == nil {
			selector = strings.TrimSpace(cfg.Auth.DefaultMethod)
		}
	}
	sorted := append([]proto.AuthMethod(nil), methods...)
	sortAuthMethods(sorted)
	if selector == "" {
		return &sorted[0], nil
	}
	for i := range sorted {
		if sorted[i].MethodID == selector {
			return &sorted[i], nil
		}
	}
	for i := range sorted {
		if sorted[i].MethodType == selector {
			return &sorted[i], nil
		}
	}
	return nil, fail("method_unavailable", "That unlock method is no longer enrolled on this device.", "Choose another method.", false)
}

func yubikeyPINMode(method proto.AuthMethod) string {
	var params proto.YubikeyPublicParams
	if err := proto.Unmarshal(method.PublicParams, &params); err != nil {
		return "optional"
	}
	switch strings.ToLower(strings.TrimSpace(params.PinPolicy)) {
	case "never":
		return "none"
	case "once", "always":
		return "required"
	default:
		return "optional"
	}
}

func (s *Service) setDefaultAuthMethod(selector string) (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	selector = strings.TrimSpace(selector)
	if selector != "" {
		state, err := chain.ReplayUser(paths.UserChain)
		if err != nil {
			return StatusResult{}, mapDomainError(err)
		}
		if state == nil || state.LatestAuthSet == nil {
			return StatusResult{}, fail("method_unavailable", "This vault has no active unlock method.", "", false)
		}
		if _, err := selectAuthMethod(paths, state.LatestAuthSet.Payload.Active, selector); err != nil {
			return StatusResult{}, err
		}
	}
	if err := fdhome.SetAuthDefaultMethod(paths.Config, selector); err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	return s.status()
}

func friendlyDesktopUnlockError(methodType string, err error) error {
	if errors.Is(err, vault.ErrYubikeyNotConfigured) {
		return fail("yubikey_unavailable", "This fd0 Desktop build does not include YubiKey support.", "Install the YubiKey desktop build, then restart fd0.", false)
	}
	message := err.Error()
	if strings.Contains(message, "pin longer than 8 bytes") || strings.Contains(message, "must be at most 8 characters") {
		return fail("invalid_pin", "YubiKey PIV PINs are 6 to 8 characters.", "Do not enter your fd0 passphrase.", false)
	}
	if methodType == proto.AuthYubikey {
		return fail("unlock_failed", "The YubiKey could not unlock this vault.", "Check the key, touch it when prompted, and verify the PIV PIN if required.", false)
	}
	return fail("unlock_failed", "That passphrase did not unlock the vault.", "Check the passphrase and try again.", false)
}

func mapRecoveryError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "decrypt failed"):
		return fail("recovery_failed", "The recovery file or recovery passphrase is incorrect.", "Check both and try again.", false)
	case strings.Contains(message, "bad magic"), strings.Contains(message, "unsupported version"), strings.Contains(message, "decode"):
		return fail("invalid_recovery", "That is not a supported fd0 recovery file.", "Choose a recovery file exported by fd0.", false)
	default:
		return mapDomainError(err)
	}
}

func (s *Service) unlock(ctx context.Context, selector string, passphrase, pin []byte) (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	client := agent.NewClient(paths.AgentSock)
	if client.IsRunning() {
		if current, err := client.Status(); err == nil {
			// Coexist with whoever got here first. A running agent is the
			// user's unlocked session — replacing it, as this used to do on a
			// version difference, silently logs their shell out of fd0.
			if use := s.inspectAgent(current); !use.compatible {
				return StatusResult{}, unusableAgentError(use, agentStartedBy(current))
			}
			if current.Unlocked {
				return s.status()
			}
		}
	}
	userState, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	if userState == nil || userState.LatestAuthSet == nil {
		return StatusResult{}, fail("vault_invalid", "This vault has no unlock method.", "Open Support to inspect the vault.", false)
	}
	method, err := selectAuthMethod(paths, userState.LatestAuthSet.Payload.Active, selector)
	if err != nil {
		return StatusResult{}, err
	}
	var credential agent.UnlockCredential
	switch method.MethodType {
	case proto.AuthPassphrase:
		if len(passphrase) == 0 {
			return StatusResult{}, fail("validation", "Enter your vault passphrase.", "", false)
		}
		if len(pin) > 0 {
			return StatusResult{}, fail("validation", "A YubiKey PIN cannot be used with passphrase unlock.", "", false)
		}
		credential.Passphrase = passphrase
	case proto.AuthYubikey:
		if len(passphrase) > 0 {
			return StatusResult{}, fail("validation", "Your fd0 passphrase is not a YubiKey PIN.", "Choose Passphrase or clear the passphrase field.", false)
		}
		pinMode := yubikeyPINMode(*method)
		if pinMode == "none" && len(pin) > 0 {
			return StatusResult{}, fail("validation", "This YubiKey method is touch-only and does not use a PIN.", "Clear the PIN and try again.", false)
		}
		if pinMode == "required" && len(pin) == 0 {
			return StatusResult{}, fail("validation", "Enter the YubiKey PIV PIN.", "", false)
		}
		if len(pin) > 0 && (len(pin) < 6 || len(pin) > 8) {
			return StatusResult{}, fail("validation", "YubiKey PIV PINs are 6 to 8 characters.", "Do not enter your fd0 passphrase.", false)
		}
		credential.YubikeyPIN = pin
	default:
		return StatusResult{}, fail("method_unavailable", "This unlock method is not supported by fd0 Desktop.", "Use the fd0 CLI for this method.", false)
	}
	if !client.IsRunning() {
		if os.Getenv("FD0_AGENT_MANAGED") == "1" {
			return StatusResult{}, fail("agent_unavailable", "The fd0 background service is not running.", "Open Support and repair the local service.", true)
		}
		if err := s.startOwnAgent(paths); err != nil {
			return StatusResult{}, err
		}
	}
	_, err = client.Unlock(paths.Vault, paths.UserChain, method.MethodType, credential)
	if err != nil {
		return StatusResult{}, friendlyDesktopUnlockError(method.MethodType, err)
	}
	return s.status()
}

func (s *Service) createVault(ctx context.Context, passphrase []byte, label string) (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	if cli.VaultExists(paths) {
		return StatusResult{}, fail("vault_exists", "An fd0 vault already exists on this device.", "Unlock the existing vault instead.", false)
	}
	if len(passphrase) < 12 {
		return StatusResult{}, fail("validation", "Use a passphrase with at least 12 characters.", "", false)
	}
	if _, err := cli.InitWithPassphrase(ctx, passphrase); err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	status, err := s.unlock(ctx, proto.AuthPassphrase, passphrase, nil)
	if err != nil {
		return StatusResult{}, err
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Personal"
	}
	if err := cli.RunScopeCreate(ctx, label); err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	return status, nil
}

func (s *Service) lock() (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	client := agent.NewClient(paths.AgentSock)
	if !client.IsRunning() {
		return s.status()
	}
	if err := client.Lock(); err != nil {
		return StatusResult{}, mapDomainError(err)
	}
	return s.status()
}

func (s *Service) prepareUpdate() (map[string]bool, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	if err := stopOwnAgent(paths); err != nil {
		if errors.Is(err, errForeignAgent) || errors.Is(err, errUnprovenAgent) {
			return nil, notOurAgentError(err, "stop it for the update",
				"Run `fd0 agent stop` in the terminal you started it from, then install the update.")
		}
		return nil, fail("agent_stop_failed", "fd0 could not stop the current agent for the update.", "Close other fd0 commands and try again.", true)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) restartAgent() (StatusResult, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return StatusResult{}, err
	}
	if err := stopOwnAgent(paths); err != nil {
		if errors.Is(err, errForeignAgent) || errors.Is(err, errUnprovenAgent) {
			return StatusResult{}, notOurAgentError(err, "restart it now",
				"Run `fd0 agent stop` in the terminal you started it from; fd0 starts its own service the next time you unlock.")
		}
		return StatusResult{}, fail("agent_restart_failed", "fd0 could not restart the local service.", "Close other fd0 commands and try again.", true)
	}
	if err := s.startOwnAgent(paths); err != nil {
		return StatusResult{}, err
	}
	return s.status()
}

// startOwnAgent starts an agent for this home and marks it as ours, which is
// what later allows stopOwnAgent to tell it apart from a shell-started one.
func (s *Service) startOwnAgent(paths fdhome.Paths) error {
	if err := agent.SpawnAs(s.AgentBin, paths.AgentLog, agent.StartedByDesktop); err != nil {
		return mapDomainError(err)
	}
	if err := agent.WaitReady(paths.AgentSock, 5*time.Second); err != nil {
		return mapDomainError(err)
	}
	return nil
}

func stopDesktopAgent(paths fdhome.Paths) error {
	client := agent.NewClient(paths.AgentSock)
	if !client.IsRunning() {
		_ = os.Remove(paths.AgentPID)
		_ = os.Remove(paths.AgentSock)
		_ = os.Remove(cli.SSHSocketPathForRender())
		return nil
	}
	if err := agent.StopByPIDFile(paths.AgentPID, 3*time.Second); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for client.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if client.IsRunning() {
		return errors.New("agent did not stop")
	}
	_ = os.Remove(paths.AgentPID)
	_ = os.Remove(paths.AgentSock)
	_ = os.Remove(cli.SSHSocketPathForRender())
	return nil
}

type SavePassParams struct {
	ScopeID    string         `json:"scopeId"`
	RecordName string         `json:"recordName"`
	Item       *passitem.Item `json:"item"`
	Create     bool           `json:"create,omitempty"`
}

func (s *Service) savePass(ctx context.Context, params SavePassParams) (map[string]bool, error) {
	params.RecordName = strings.TrimSpace(params.RecordName)
	if params.RecordName == "" || params.Item == nil {
		return nil, fail("validation", "A title and vault are required.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	recordKey := "pass:" + params.RecordName
	targetKey := "pass:" + strings.TrimSpace(params.Item.Title)
	existing, existingErr := session.GetTypedSecret(params.ScopeID, recordKey)
	if params.Create {
		if existingErr == nil {
			return nil, fail("duplicate", "An item with that title already exists in this vault.", "Choose another title or edit the existing item.", false)
		}
		if !errors.Is(existingErr, cli.ErrTypedSecretNotFound) {
			return nil, mapDomainError(existingErr)
		}
		item, err := preparePassSave(params.Item, nil)
		if err != nil {
			return nil, fail("validation", err.Error(), "", false)
		}
		params.Item = item
	} else {
		if existingErr != nil {
			if errors.Is(existingErr, cli.ErrTypedSecretNotFound) {
				return nil, fail("stale_item", "That password item no longer exists.", "Refresh the vault before saving.", false)
			}
			return nil, mapDomainError(existingErr)
		}
		if existing.Type != passitem.TypePassItem {
			return nil, fail("type_conflict", "That name belongs to a different item type.", "Refresh the vault and choose another title.", false)
		}
		if targetKey != recordKey {
			if err := requireMissingRecord(session, params.ScopeID, targetKey, "An item with that title already exists in this vault."); err != nil {
				return nil, err
			}
		}
		raw, err := existing.PayloadJSON()
		if err != nil {
			return nil, mapDomainError(err)
		}
		old, err := passitem.Decode(raw)
		if err != nil {
			return nil, mapDomainError(err)
		}
		item, err := preparePassSave(params.Item, old)
		if err != nil {
			return nil, fail("validation", err.Error(), "", false)
		}
		params.Item = item
		params.Item.Touch()
	}
	if err := params.Item.Validate(); err != nil {
		return nil, fail("validation", err.Error(), "", false)
	}
	var writeErr error
	if params.Create {
		writeErr = session.CreateTypedSecret(ctx, params.ScopeID, recordKey, passitem.TypePassItem, params.Item.Marshal())
	} else if targetKey != recordKey {
		writeErr = session.CreateTypedSecret(ctx, params.ScopeID, targetKey, passitem.TypePassItem, params.Item.Marshal())
	} else {
		writeErr = session.UpdateTypedSecret(ctx, params.ScopeID, recordKey, passitem.TypePassItem, passitem.TypePassItem, params.Item.Marshal())
	}
	if writeErr != nil {
		return nil, mapDomainError(writeErr)
	}
	if !params.Create && targetKey != recordKey {
		if err := session.RemoveTypedSecretOfType(ctx, params.ScopeID, recordKey, passitem.TypePassItem); err != nil {
			return nil, fail(
				"rename_partial",
				"The item was saved under its new title, but fd0 could not remove the old copy.",
				"Review both items before retrying.",
				false,
			)
		}
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) passEditData(ctx context.Context, ref RecordRef) (SavePassParams, error) {
	if err := ref.Validate(); err != nil {
		return SavePassParams{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return SavePassParams{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return SavePassParams{}, mapDomainError(err)
	}
	if record.Type != passitem.TypePassItem {
		return SavePassParams{}, fail("unsupported", "Only password items can be edited here.", "", false)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return SavePassParams{}, err
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return SavePassParams{}, err
	}
	return SavePassParams{
		ScopeID:    ref.ScopeID,
		RecordName: strings.TrimPrefix(ref.Name, "pass:"),
		Item:       item,
	}, nil
}

func (s *Service) setPassFavorite(ctx context.Context, ref RecordRef, favorite bool) (map[string]bool, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return nil, mapDomainError(err)
	}
	if record.Type != passitem.TypePassItem {
		return nil, fail("unsupported", "Only password items can be marked as favorites.", "", false)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return nil, err
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return nil, err
	}
	if item.Meta == nil {
		item.Meta = map[string]any{}
	}
	item.Meta["favorite"] = favorite
	item.Touch()
	if err := item.Validate(); err != nil {
		return nil, fail("validation", err.Error(), "", false)
	}
	if err := session.UpdateTypedSecret(ctx, ref.ScopeID, ref.Name, passitem.TypePassItem, passitem.TypePassItem, item.Marshal()); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

type SaveSecretParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	OldName string `json:"oldName,omitempty"`
	Create  bool   `json:"create,omitempty"`
}

func (s *Service) saveSecret(ctx context.Context, params SaveSecretParams) (map[string]bool, error) {
	params.Name = strings.TrimSpace(params.Name)
	if params.Name == "" {
		return nil, fail("validation", "Secret name is required.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	if params.Create {
		if params.OldName != "" {
			session.Close()
			return nil, fail("validation", "A new secret cannot rename another item.", "Refresh the vault and try again.", false)
		}
		if err := requireMissingRecord(session, params.ScopeID, params.Name, "A secret with that name already exists in this vault."); err != nil {
			session.Close()
			return nil, err
		}
	} else {
		if strings.TrimSpace(params.OldName) == "" {
			session.Close()
			return nil, fail("validation", "The original secret name is required for an edit.", "Refresh the vault and try again.", false)
		}
		if _, err := requireRecordType(session, params.ScopeID, params.OldName, "kv.string"); err != nil {
			session.Close()
			return nil, err
		}
		if params.OldName != params.Name {
			if err := requireMissingRecord(session, params.ScopeID, params.Name, "A secret with that name already exists in this vault."); err != nil {
				session.Close()
				return nil, err
			}
		}
	}
	session.Close()
	if err := cli.RunSecretSet(ctx, params.ScopeID, params.Name, params.Value); err != nil {
		return nil, mapDomainError(err)
	}
	if params.OldName != "" && params.OldName != params.Name {
		cleanupSession, err := cli.Open(ctx)
		if err != nil {
			return nil, fail("rename_partial", "The secret was saved under its new name, but fd0 could not remove the old copy.", "Review both items before retrying.", false)
		}
		defer cleanupSession.Close()
		if err := cleanupSession.RemoveTypedSecretOfType(ctx, params.ScopeID, params.OldName, "kv.string"); err != nil {
			return nil, fail("rename_partial", "The secret was saved under its new name, but fd0 could not remove the old copy.", "Review both items before retrying.", false)
		}
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) secretEditData(ctx context.Context, ref RecordRef) (SaveSecretParams, error) {
	if err := ref.Validate(); err != nil {
		return SaveSecretParams{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return SaveSecretParams{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return SaveSecretParams{}, mapDomainError(err)
	}
	if record.Type != "kv.string" {
		return SaveSecretParams{}, fail("unsupported", "Only general secrets can be edited here.", "Use the specialized item view for this record.", false)
	}
	value, ok := record.Payload.(string)
	if !ok {
		return SaveSecretParams{}, fail("invalid_record", "This secret has an unsupported stored value.", "Open Support before changing it.", false)
	}
	return SaveSecretParams{ScopeID: ref.ScopeID, Name: ref.Name, OldName: ref.Name, Value: value}, nil
}

type SaveSSHHostParams struct {
	ScopeID string        `json:"scopeId"`
	OldName string        `json:"oldName,omitempty"`
	Record  *sshhost.Host `json:"host"`
}

func (s *Service) saveSSHHost(ctx context.Context, params SaveSSHHostParams) (map[string]bool, error) {
	if params.Record == nil {
		return nil, fail("validation", "SSH host details are required.", "", false)
	}
	if err := params.Record.Validate(); err != nil {
		return nil, fail("validation", err.Error(), "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	if err := requireSSHKeyReference(session, params.ScopeID, params.Record.KeyName); err != nil {
		return nil, err
	}
	newName := "host:" + params.Record.Alias
	if params.OldName == "" {
		if err := requireMissingRecord(session, params.ScopeID, newName, "An SSH host with that alias already exists."); err != nil {
			return nil, err
		}
	} else {
		if _, err := requireRecordType(session, params.ScopeID, params.OldName, sshhost.TypeHost); err != nil {
			return nil, err
		}
		if params.OldName != newName {
			if err := requireMissingRecord(session, params.ScopeID, newName, "An SSH host with that alias already exists."); err != nil {
				return nil, err
			}
		}
	}
	var writeErr error
	switch {
	case params.OldName == "":
		writeErr = session.CreateTypedSecret(ctx, params.ScopeID, newName, sshhost.TypeHost, params.Record.Marshal())
	case params.OldName == newName:
		writeErr = session.UpdateTypedSecret(ctx, params.ScopeID, newName, sshhost.TypeHost, sshhost.TypeHost, params.Record.Marshal())
	default:
		writeErr = session.CreateTypedSecret(ctx, params.ScopeID, newName, sshhost.TypeHost, params.Record.Marshal())
	}
	if writeErr != nil {
		return nil, mapDomainError(writeErr)
	}
	if params.OldName != "" && params.OldName != newName {
		if err := session.RemoveTypedSecretOfType(ctx, params.ScopeID, params.OldName, sshhost.TypeHost); err != nil {
			return nil, fail("rename_partial", "The SSH host was saved under its new alias, but fd0 could not remove the old copy.", "Review both hosts before retrying.", false)
		}
	}
	if err := cli.RefreshSSHProjection(session); err != nil {
		return nil, fail(
			"ssh_projection_partial",
			"The server was saved, but fd0 could not refresh this device's SSH configuration.",
			"Open Support, then retry the SSH configuration refresh.",
			true,
		)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) sshHostEditData(ctx context.Context, ref RecordRef) (SaveSSHHostParams, error) {
	if err := ref.Validate(); err != nil {
		return SaveSSHHostParams{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return SaveSSHHostParams{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return SaveSSHHostParams{}, mapDomainError(err)
	}
	if record.Type != sshhost.TypeHost {
		return SaveSSHHostParams{}, fail("unsupported", "Only SSH hosts can be edited here.", "", false)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return SaveSSHHostParams{}, err
	}
	var wire sshhost.JSON
	if err := json.Unmarshal(raw, &wire); err != nil {
		return SaveSSHHostParams{}, err
	}
	host, err := sshhost.Unmarshal(wire)
	if err != nil {
		return SaveSSHHostParams{}, err
	}
	return SaveSSHHostParams{ScopeID: ref.ScopeID, OldName: ref.Name, Record: host}, nil
}

func requireRecordType(session *cli.Session, scopeID, name, expectedType string) (*cli.TypedRecord, error) {
	record, err := session.GetTypedSecret(scopeID, name)
	if err != nil {
		if errors.Is(err, cli.ErrTypedSecretNotFound) {
			return nil, fail("stale_item", "That item no longer exists.", "Refresh the vault before saving.", false)
		}
		return nil, mapDomainError(err)
	}
	if record.Type != expectedType {
		return nil, fail("type_conflict", "That name belongs to a different item type.", "Refresh the vault and choose another name.", false)
	}
	return record, nil
}

func requireMissingRecord(session *cli.Session, scopeID, name, message string) error {
	_, err := session.GetTypedSecret(scopeID, name)
	if err == nil {
		return fail("duplicate", message, "Choose another name or edit the existing item.", false)
	}
	if !errors.Is(err, cli.ErrTypedSecretNotFound) {
		return mapDomainError(err)
	}
	return nil
}

type GenerateSSHKeyParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

func (s *Service) generateSSHKey(ctx context.Context, params GenerateSSHKeyParams) (map[string]bool, error) {
	params.Name = strings.TrimSpace(params.Name)
	params.Comment = strings.TrimSpace(params.Comment)
	if err := validateSSHKeyMetadata(params.Name, params.Comment); err != nil {
		return nil, err
	}
	key, err := sshkey.NewEd25519(params.Name, params.Comment)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(key.Private)
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	if _, err := session.GetTypedSecret(params.ScopeID, "ssh:"+params.Name); err == nil {
		return nil, fail("duplicate", "An SSH key with that name already exists.", "Choose another name.", false)
	} else if !errors.Is(err, cli.ErrTypedSecretNotFound) {
		return nil, mapDomainError(err)
	}
	if err := session.SetTypedSecret(ctx, params.ScopeID, "ssh:"+params.Name, string(key.Type), key.Marshal()); err != nil {
		return nil, mapDomainError(err)
	}
	if err := cli.RefreshSSHProjectionIfEnabled(session); err != nil {
		return nil, fail(
			"ssh_projection_partial",
			"The SSH key was created, but fd0 could not refresh this device's SSH configuration.",
			"Open Support, then retry the SSH configuration refresh.",
			true,
		)
	}
	return map[string]bool{"ok": true}, nil
}

type ImportConfigParams struct {
	Kind    string `json:"kind"`
	ScopeID string `json:"scopeId"`
	Data    []byte `json:"data"`
}

type ImportConfigResult struct {
	Imported []string `json:"imported"`
	Skipped  []string `json:"skipped,omitempty"`
}

func (s *Service) importConfig(ctx context.Context, params ImportConfigParams) (ImportConfigResult, error) {
	if len(params.Data) == 0 || len(params.Data) > MaxFrameBytes/2 {
		return ImportConfigResult{}, fail("validation", "The selected config is empty or too large.", "Choose a config smaller than 512 KB.", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return ImportConfigResult{}, mapDomainError(err)
	}
	defer session.Close()
	result := ImportConfigResult{}
	switch params.Kind {
	case "kubernetes":
		_, entries, skipped, err := kubeconfig.ParseKubeconfig(params.Data)
		if err != nil {
			return result, fail("invalid_config", "That file is not a supported kubeconfig.", err.Error(), false)
		}
		if len(entries) == 0 {
			return result, fail("invalid_config", "No supported Kubernetes contexts were found.", strings.Join(skipped, " "), false)
		}
		for _, entry := range entries {
			if err := entry.Validate(); err != nil {
				result.Skipped = append(result.Skipped, entry.Name+": "+err.Error())
				continue
			}
			recordName := "kube:" + entry.Name
			if _, err := session.GetTypedSecret(params.ScopeID, recordName); err == nil {
				result.Skipped = append(result.Skipped, entry.Name+": already exists")
				continue
			} else if !errors.Is(err, cli.ErrTypedSecretNotFound) {
				return result, mapDomainError(err)
			}
			if err := session.SetTypedSecret(ctx, params.ScopeID, recordName, kubeconfig.TypeKubeconfig, entry.Marshal()); err != nil {
				return result, mapDomainError(err)
			}
			result.Imported = append(result.Imported, entry.Name)
		}
		result.Skipped = append(result.Skipped, skipped...)
	case "talos":
		_, entries, err := talosctx.ParseTalosconfig(params.Data)
		if err != nil {
			return result, fail("invalid_config", "That file is not a supported talosconfig.", err.Error(), false)
		}
		if len(entries) == 0 {
			return result, fail("invalid_config", "No Talos contexts were found.", "", false)
		}
		for _, entry := range entries {
			if err := entry.Validate(); err != nil {
				result.Skipped = append(result.Skipped, entry.Name+": "+err.Error())
				continue
			}
			recordName := "talos:" + entry.Name
			if _, err := session.GetTypedSecret(params.ScopeID, recordName); err == nil {
				result.Skipped = append(result.Skipped, entry.Name+": already exists")
				continue
			} else if !errors.Is(err, cli.ErrTypedSecretNotFound) {
				return result, mapDomainError(err)
			}
			if err := session.SetTypedSecret(ctx, params.ScopeID, recordName, talosctx.TypeTalosContext, entry.Marshal()); err != nil {
				return result, mapDomainError(err)
			}
			result.Imported = append(result.Imported, entry.Name)
		}
	default:
		return result, fail("validation", "Unsupported config type.", "", false)
	}
	if len(result.Imported) == 0 {
		return result, fail("invalid_config", "No valid contexts could be imported.", strings.Join(result.Skipped, " "), false)
	}
	return result, nil
}

type RemoveItemResult struct {
	OK   bool              `json:"ok"`
	Undo ItemVersionParams `json:"undo"`
}

func (s *Service) removeItem(ctx context.Context, ref RecordRef) (RemoveItemResult, error) {
	if err := ref.Validate(); err != nil {
		return RemoveItemResult{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return RemoveItemResult{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return RemoveItemResult{}, mapDomainError(err)
	}
	if isSSHKeyType(record.Type) {
		usages, err := sshKeyUsages(session, ref.ScopeID, strings.TrimPrefix(ref.Name, "ssh:"))
		if err != nil {
			return RemoveItemResult{}, mapDomainError(err)
		}
		if len(usages) > 0 {
			return RemoveItemResult{}, fail(
				"ssh_key_in_use",
				fmt.Sprintf("This SSH key is still assigned to %d server(s).", len(usages)),
				"Choose another key for those servers before removing this key.",
				false,
			)
		}
	}
	history, err := session.SecretHistory(ref.ScopeID, ref.Name)
	if err != nil || len(history) == 0 || history[0].Tombstone() {
		if err == nil {
			err = errors.New("item has no restorable current version")
		}
		return RemoveItemResult{}, mapHistoryError(err)
	}
	restoreSeq := history[0].Seq
	if err := session.RemoveTypedSecret(ctx, ref.ScopeID, ref.Name); err != nil {
		return RemoveItemResult{}, mapDomainError(err)
	}
	var projectionErr error
	switch {
	case record.Type == sshhost.TypeHost:
		projectionErr = cli.RefreshSSHProjection(session)
	case isSSHKeyType(record.Type):
		projectionErr = cli.RefreshSSHProjectionIfEnabled(session)
	}
	if projectionErr != nil {
		return RemoveItemResult{}, fail(
			"ssh_projection_partial",
			"The item was removed, but fd0 could not refresh this device's SSH configuration.",
			"Open Support, then retry the SSH configuration refresh.",
			true,
		)
	}
	return RemoveItemResult{
		OK: true,
		Undo: ItemVersionParams{
			ScopeID: ref.ScopeID,
			Name:    ref.Name,
			Seq:     restoreSeq,
		},
	}, nil
}

func mapDomainError(err error) error {
	if err == nil {
		return nil
	}
	// Legacy-format vaults come first: they are the one failure a user can
	// hit on a completely healthy install, and the generic fallback ("fd0
	// could not complete that action") tells them nothing. Both cases below
	// leave local state untouched, which is why both say so.
	if errors.Is(err, cli.ErrLegacyScopeHistoryNeedsServer) {
		return fail(
			"legacy_history_repair_offline",
			"This vault was saved by an older version of fd0 and needs a one-time repair from your fd0 server before its items can be opened.",
			"Connect this device to the internet and open Sync to finish the repair. Nothing on this device has been changed, so it is safe to try again.",
			true,
		)
	}
	if errors.Is(err, cli.ErrLegacyScopeHistoryUnverifiable) {
		return fail(
			"legacy_history_repair_blocked",
			"This vault was saved by an older version of fd0, but the history your fd0 server returned does not match the history this device already trusts.",
			"Run `fd0 sync` from the command line to reconcile the difference, then reopen fd0. Nothing on this device has been changed.",
			false,
		)
	}
	if errors.Is(err, cli.ErrAgentLocked) {
		return fail("locked", "Your vault is locked.", "Unlock fd0 to continue.", false)
	}
	if errors.Is(err, cli.ErrAgentNotRunning) {
		return fail("agent_unavailable", "fd0 could not reach the local vault service.", "Try unlocking again.", true)
	}
	if errors.Is(err, cli.ErrServerIdentityChanged) {
		return fail("server_changed", "The fd0 service identity changed while you were confirming it.", "Start sync again and review the new fingerprint.", true)
	}
	if errors.Is(err, cli.ErrPinnedKeyMismatch) {
		return fail("server_identity_mismatch", "fd0 stopped because this service no longer matches its trusted identity.", "Do not continue. Open Support and verify the service independently.", false)
	}
	if errors.Is(err, cli.ErrServerInfoUnsigned) {
		return fail("server_identity_invalid", "The fd0 service did not provide a valid signed identity.", "Check the service address or try again later.", false)
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "another fd0 instance holds the lock"):
		return fail("busy", "fd0 is finishing another operation.", "Wait a moment and try again.", true)
	case strings.Contains(message, "no vault found"):
		return fail("vault_missing", "No fd0 vault was found.", "Create or restore a vault.", false)
	case strings.Contains(message, "rollback"):
		return fail("integrity_check_failed", "fd0 stopped because the local history failed an integrity check.", "Open Support before making more changes.", false)
	default:
		return err
	}
}
