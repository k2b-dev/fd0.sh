package fdhome

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the user-editable ~/.fd0/config.toml. All fields are optional;
// missing files / fields fall back to documented defaults.
type Config struct {
	DeviceID  string           `toml:"device_id"`
	ShortID   string           `toml:"short_id"`
	Sync      SyncConfig       `toml:"sync"`
	Client    ClientConfig     `toml:"client"`
	Agent     AgentConfig      `toml:"agent"`
	Auth      AuthConfig       `toml:"auth"`
	Clipboard ClipboardConfig  `toml:"clipboard"`
	Kube      ProjectionConfig `toml:"kube"`
	Talos     ProjectionConfig `toml:"talos"`
	Witnesses []WitnessConfig  `toml:"witness"`        // [[witness]] entries
	WitnessP  WitnessPolicy    `toml:"witness_policy"` // global cross-check policy
}

// AuthConfig collects device-local unlock preferences. It is not synced and
// does not change the enrolled auth methods.
type AuthConfig struct {
	// DefaultMethod is either an auth method type ("passphrase", "yubikey") or
	// a concrete method_id ("am_..."). Empty keeps the built-in deterministic
	// selection.
	DefaultMethod string `toml:"default_method"`
}

// WitnessConfig is one configured witness the client trusts. Per
// TRANSLOG.md §10 the witness pubkey is operator-pinned (no TOFU)
// because witnesses are operational identities, not peer-to-peer.
type WitnessConfig struct {
	URL    string `toml:"url"`
	PubHex string `toml:"pub"` // hex ed25519 pubkey
}

// WitnessPolicy expresses the cross-check policy: how many cosigns
// the client requires per sync round.
//
// MinCosigns is INDEPENDENT of len(Witnesses): the operator can
// configure 3 witnesses but require only 2 matching cosigns,
// leaving headroom for a single witness outage. A lagging or
// unreachable witness simply doesn't contribute, so MinCosigns is
// the absolute floor — there is no "lag tolerance" knob that
// silently lowers it (codex fix #3 hardened this against the
// timing-game attack where an adversary could DOS witnesses to
// drive the threshold to zero).
//
// Default policy (MinCosigns=0) DISABLES cross-check entirely; this
// matches the v1 OPTIONAL spec stance and lets single-user installs
// run without any witness infrastructure.
type WitnessPolicy struct {
	MinCosigns int `toml:"min_cosigns"`
}

// AgentConfig collects fd0-agent lifecycle knobs. Read by the agent when the
// matching CLI flag / env var are not set. Precedence: flag > env > config >
// default. Empty strings here mean "fall through to the next layer".
type AgentConfig struct {
	// IdleTimeout is a Go duration string ("5m", "30m"). Empty = use default.
	// Overridden by --idle-timeout flag and FD0_AGENT_IDLE env.
	IdleTimeout string `toml:"idle_timeout"`
	// MaxLifetime is a Go duration string ("8h", "24h"). Empty = use default.
	// Overridden by --max-lifetime flag and FD0_AGENT_MAX_LIFETIME env.
	MaxLifetime string `toml:"max_lifetime"`
}

// ClientConfig collects per-CLI knobs that aren't sync-related.
type ClientConfig struct {
	// LockWait is a Go duration string ("10s", "1m"). Empty = fail fast on
	// flock contention. Overridden by FD0_LOCK_WAIT env when set.
	LockWait string `toml:"lock_wait"`
}

// ProjectionConfig records local integration state for generated tool
// configs. Enabled is a pointer so the CLI can distinguish "not configured
// yet" from "explicitly disabled"; existing generated files act as a
// migration fallback only when Enabled is absent.
type ProjectionConfig struct {
	Enabled   *bool `toml:"enabled"`
	AutoMerge bool  `toml:"auto_merge"`
}

// SyncConfig drives the agent-managed background sync.
type SyncConfig struct {
	// Server is the LEGACY single-server URL. Kept for backward
	// compatibility with pre-v0.0.4 configs; when both Server and
	// Servers are set, Servers wins. Falls back to FD0_SERVER env
	// downstream if both are empty.
	Server string `toml:"server"`
	// Servers is the REMOVED pre-A1 multi-server array. It is kept in the
	// struct only so a stale config is rejected with a clear migration
	// message (ResolvedServer) — without the field, TOML would silently
	// ignore the key and fall back to the default server. Do not read it
	// for resolution; use Server.
	Servers []string `toml:"servers"`
	// Interval as Go duration string ("1h", "5m"). Empty/zero disables.
	Interval string `toml:"interval"`
	// OnUnlock controls the post-unlock auto-sync. Pointer so we can
	// distinguish "absent" (apply default = true) from "explicitly false".
	OnUnlock *bool `toml:"on_unlock"`
}

// DefaultServer is the hosted primary used when neither [sync].server nor
// FD0_SERVER is set (docs/HOSTING.md). A self-hoster who runs `fd0 init`
// against their own server overwrites this by writing config.toml. fd0 has
// a single write/read authority; redundancy is a server-side DR backup,
// not a second URL.
var DefaultServer = "https://api.fd0.sh"

// ResolvedServer returns the configured primary: Server, else DefaultServer.
// A still-present [sync].servers is a hard error — it was the multi-push
// model removed in A1; the message tells the operator to use `server`.
// Pure (config-only); flag/env override is applied one level up.
func (c SyncConfig) ResolvedServer() (string, error) {
	if len(c.Servers) > 0 {
		return "", fmt.Errorf("[sync].servers is no longer supported — fd0 writes to a single primary; replace it with:  server = %q  (see docs/REPLICATION.md)", c.Servers[0])
	}
	if c.Server != "" {
		return c.Server, nil
	}
	return DefaultServer, nil
}

// OnUnlockEnabled returns the effective on-unlock flag. Default is true
// when not set in config.
func (c SyncConfig) OnUnlockEnabled() bool {
	if c.OnUnlock == nil {
		return true
	}
	return *c.OnUnlock
}

// ClipboardConfig tunes `fd0 copy`. Read by the CLI when the user does not
// pass `--clear-after` on the command line.
type ClipboardConfig struct {
	// ClearAfterSeconds: 0 = disabled. Default applied by the CLI is 30s.
	ClearAfterSeconds int `toml:"clear_after_seconds"`
}

// LoadConfig reads ~/.fd0/config.toml. A missing file is not an error.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, err
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return c, err
	}
	return c, nil
}

// SetAuthDefaultMethod updates only [auth].default_method in config.toml. It
// intentionally avoids re-encoding the full Config struct so user comments and
// unrelated formatting survive.
func SetAuthDefaultMethod(path, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if value == "" {
			return nil
		}
		return os.WriteFile(path, []byte("[auth]\ndefault_method = "+strconv.Quote(value)+"\n"), 0o600)
	}
	out := updateAuthDefaultMethodText(string(data), value)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o600)
}

func updateAuthDefaultMethodText(in, value string) string {
	lines := strings.SplitAfter(in, "\n")
	if len(lines) == 1 && lines[0] == "" {
		if value == "" {
			return ""
		}
		return "[auth]\ndefault_method = " + strconv.Quote(value) + "\n"
	}

	authStart := -1
	defaultLine := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isTOMLTableHeader(trimmed) {
			if authStart >= 0 && i > authStart {
				break
			}
			if trimmed == "[auth]" {
				authStart = i
			}
			continue
		}
		if authStart >= 0 && defaultLine < 0 && isTOMLKey(trimmed, "default_method") {
			defaultLine = i
		}
	}

	defaultText := "default_method = " + strconv.Quote(value) + "\n"
	if authStart >= 0 {
		switch {
		case defaultLine >= 0 && value == "":
			lines = append(lines[:defaultLine], lines[defaultLine+1:]...)
		case defaultLine >= 0:
			lines[defaultLine] = defaultText
		case value != "":
			insertAt := authStart + 1
			lines = append(lines[:insertAt], append([]string{defaultText}, lines[insertAt:]...)...)
		}
		return strings.Join(lines, "")
	}

	if value == "" {
		return in
	}
	if !strings.HasSuffix(in, "\n") {
		in += "\n"
	}
	if strings.TrimSpace(in) != "" {
		in += "\n"
	}
	return in + "[auth]\n" + defaultText
}

func isTOMLTableHeader(trimmed string) bool {
	return strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")
}

func isTOMLKey(trimmed, key string) bool {
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return false
	}
	left, _, ok := strings.Cut(trimmed, "=")
	return ok && strings.TrimSpace(left) == key
}

// SyncIntervalDuration parses Sync.Interval; "" / parse-failure / zero return
// 0 meaning "auto-sync disabled".
func (c Config) SyncIntervalDuration() time.Duration {
	if c.Sync.Interval == "" {
		return 0
	}
	d, err := time.ParseDuration(c.Sync.Interval)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// WitnessCrossCheckEnabled returns true iff the client should
// perform cross-check on every sync. Disabled when no witnesses are
// configured OR MinCosigns is zero. Either knob can disable it
// independently — operators turning min_cosigns to 0 temporarily
// shouldn't have to also delete every [[witness]] block.
func (c Config) WitnessCrossCheckEnabled() bool {
	return len(c.Witnesses) > 0 && c.WitnessP.MinCosigns > 0
}
