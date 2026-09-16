// Package sshagent implements the ssh-agent protocol on a Unix domain
// socket so that standard SSH clients (ssh, scp, sftp, git, rsync, …)
// can transparently use keys held by fd0.
//
// Design choices, made deliberately to keep the implementation small
// and the trust surface narrow:
//
//   - Sign + List only. Add, Remove, Lock, Unlock from the agent
//     socket are explicitly unsupported. Key state is owned by the
//     fd0 vault; ssh-add cannot mutate it. This matches the Bitwarden
//     desktop ssh-agent posture and removes whole categories of misuse
//     (cf. SSH agent protocol §2.5 — implementations MAY decline ops).
//
//   - Vault-unlock is the consent boundary. No per-sign approval
//     prompt. The standard ssh-agent (OpenSSH, gpg-agent, gnome-
//     keyring) behaviour. If the vault is locked the key listing is
//     empty and sign returns failure; the user runs `fd0 unlock` and
//     retries, the SSH client picks the key up automatically.
//
//   - The KeyProvider is injected. This file does not know about the
//     vault or fdhome; it only knows how to translate
//     fd0-domain key objects into the agent protocol. Wiring lives
//     one layer up in cmd/fd0-agent and internal/agent.
package sshagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// KeyEntry is what the agent serves to ssh clients. The Key carries
// the signing material; Comment is what ssh-add -l displays.
type KeyEntry struct {
	Key     *sshkey.Key
	Comment string // free-form; falls back to key.Comment if empty
}

// KeyProvider lends keys only for the duration of an operation. Implementations
// must coordinate the callback with vault lock and expiry and must be safe for
// concurrent calls. A locked vault calls use with an empty slice; fetch failures
// return an error. Callers must never retain private key material.
type KeyProvider interface {
	WithKeys(use func([]KeyEntry) error) error
}

// fd0Agent implements agent.Agent (golang.org/x/crypto/ssh/agent).
// We intentionally only implement List and Sign; the other methods
// return an error so adversarial clients (and confused tooling) fail
// loudly rather than silently mutating state.
type fd0Agent struct {
	src KeyProvider
}

// New wraps a KeyProvider in an agent.Agent suitable for
// agent.ServeAgent.
func New(src KeyProvider) agent.Agent {
	return &fd0Agent{src: src}
}

// List returns public identities. Internal failures remain protocol failures,
// distinct from a successfully read empty or locked vault.
func (a *fd0Agent) List() ([]*agent.Key, error) {
	var out []*agent.Key
	err := a.src.WithKeys(func(entries []KeyEntry) error {
		for _, e := range entries {
			pub, err := e.Key.PublicKey()
			if err != nil {
				return errors.New("sshagent: invalid public key")
			}
			comment := e.Comment
			if comment == "" {
				comment = e.Key.Comment
			}
			out = append(out, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: comment})
		}
		return nil
	})
	if err != nil {
		return nil, errors.New("sshagent: cannot list identities")
	}
	return out, nil
}

// Sign produces a signature over `data` with the private key matching
// `key`. The agent rummages through the available identities for a
// pub-key match; if none match, returns an error.
//
// We do NOT honour SignWithFlags' fingerprint-specific algorithms
// because we only generate ed25519 (which uses one fixed algorithm);
// imported RSA keys deliberately decline RFC 8332 newer SHA modes —
// callers should rotate to ed25519 instead.
func (a *fd0Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	var signature *ssh.Signature
	err := a.src.WithKeys(func(entries []KeyEntry) error {
		target := key.Marshal()
		for _, e := range entries {
			pub, err := e.Key.PublicKey()
			if err != nil {
				return errors.New("sshagent: invalid public key")
			}
			if !equalBytes(pub.Marshal(), target) {
				continue
			}
			signer, err := e.Key.Signer()
			if err != nil {
				return errors.New("sshagent: invalid signing key")
			}
			signature, err = signer.Sign(rand.Reader, data)
			return err
		}
		return errors.New("sshagent: no matching identity")
	})
	// x/crypto's protocol server logs returned errors. Never expose provider
	// details, key comments, or decoded payloads through that logging path.
	if err != nil {
		return nil, errors.New("sshagent: signing unavailable")
	}
	return signature, nil
}

// SignWithFlags falls back to Sign — see comment above for rationale.
func (a *fd0Agent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.Sign(key, data)
}

// Add is explicitly unsupported. Adding keys goes via `fd0 key add` →
// vault → agent sees it on next List.
func (a *fd0Agent) Add(_ agent.AddedKey) error {
	return errors.New("sshagent: Add not supported (use `fd0 key add`)")
}

// Remove is explicitly unsupported. Use `fd0 key rm`.
func (a *fd0Agent) Remove(_ ssh.PublicKey) error {
	return errors.New("sshagent: Remove not supported (use `fd0 key rm`)")
}

// RemoveAll is explicitly unsupported.
func (a *fd0Agent) RemoveAll() error {
	return errors.New("sshagent: RemoveAll not supported")
}

// Lock is unsupported — vault lock/unlock state IS the agent's lock
// state; locking is via `fd0 lock`.
func (a *fd0Agent) Lock(_ []byte) error {
	return errors.New("sshagent: Lock not supported (use `fd0 lock`)")
}

// Unlock is unsupported — see Lock.
func (a *fd0Agent) Unlock(_ []byte) error {
	return errors.New("sshagent: Unlock not supported (use `fd0 unlock`)")
}

// Signers returns proxies that reauthorize every signature, never raw signers
// that could retain private keys after vault lock.
func (a *fd0Agent) Signers() ([]ssh.Signer, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	out := make([]ssh.Signer, 0, len(keys))
	for _, key := range keys {
		pub, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			return nil, err
		}
		out = append(out, &liveSigner{agent: a, public: pub})
	}
	return out, nil
}

type liveSigner struct {
	agent  *fd0Agent
	public ssh.PublicKey
}

func (s *liveSigner) PublicKey() ssh.PublicKey { return s.public }
func (s *liveSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.public, data)
}

// equalBytes compares two byte slices in constant time. Public keys
// aren't strictly a secret-equality case (they're public!) but
// constant-time compare is a cheap habit.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// DefaultSocketPath returns the conventional fd0 SSH-agent socket path.
// Honours XDG_RUNTIME_DIR per the freedesktop.org spec; falls back to /tmp
// on macOS where XDG isn't standardised. The filename includes the UID so
// two users sharing a host get separate sockets. Non-default FD0_HOME values
// get a per-home suffix so isolated test/demo vaults do not collide with the
// user's real fd0-agent socket.
func DefaultSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join("/tmp", "fd0")
	} else {
		dir = filepath.Join(dir, "fd0")
	}
	uid := os.Getuid()
	name := "ssh-" + strconv.Itoa(uid)
	if suffix := fd0HomeSocketSuffix(); suffix != "" {
		name += "-" + suffix
	}
	return filepath.Join(dir, name+".sock")
}

func fd0HomeSocketSuffix() string {
	home := os.Getenv("FD0_HOME")
	if home == "" {
		return ""
	}
	if abs, err := filepath.Abs(home); err == nil {
		home = abs
	}
	if userHome, err := os.UserHomeDir(); err == nil {
		defaultHome := filepath.Join(userHome, ".fd0")
		if abs, err := filepath.Abs(defaultHome); err == nil {
			defaultHome = abs
		}
		if home == defaultHome {
			return ""
		}
	}
	sum := sha256.Sum256([]byte(home))
	return hex.EncodeToString(sum[:])[:12]
}

// EnsureSocketDir creates the parent directory for the socket with
// 0700 permissions (owner-only) and removes any stale socket file at
// the target path. Returns the absolute path to use for Listen.
func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sshagent: mkdir %s: %w", dir, err)
	}
	// Stale socket left by previous agent? Remove — but only if the
	// path is actually a Unix socket. os.Stat would follow symlinks
	// and os.Remove would then delete whatever the path pointed at,
	// so a misconfigured FD0_SSH_SOCK=/path/to/important would
	// silently lose that file at agent boot. os.Lstat doesn't follow
	// the link; we additionally insist the mode is socket so regular
	// files, dirs, and symlinks are all refused.
	fi, err := os.Lstat(socketPath)
	if err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("sshagent: %s exists and is not a Unix socket (mode %s) — refusing to remove", socketPath, fi.Mode())
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("sshagent: remove stale %s: %w", socketPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sshagent: lstat %s: %w", socketPath, err)
	}
	return nil
}

// Listen opens the Unix socket at path with the conventional 0600
// permissions (only the owning UID can talk to it). Callers loop
// accepting connections and hand each to agent.ServeAgent(agent, conn).
func Listen(path string) (net.Listener, error) {
	if err := EnsureSocketDir(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("sshagent: listen %s: %w", path, err)
	}
	// net.Listen on Unix sockets creates the file with the process's
	// umask applied — usually 0755 minus 0022 = 0755. Tighten to 0600
	// explicitly so a hostile local user can't connect.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("sshagent: chmod 0600 %s: %w", path, err)
	}
	return l, nil
}
