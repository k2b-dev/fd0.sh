// Package agent implements fd0's local key-holding daemon and its IPC.
//
// Wire format (length-prefixed CBOR frames over a Unix domain socket):
//
//	+----+--------------------+
//	| 4B |   N B  CBOR frame  |
//	+----+--------------------+
//
// The 4-byte header is big-endian uint32 length. Max frame size 1 MiB.
//
// One request frame, one response frame, one round-trip.
package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// MaxFrame caps a single wire frame.
const MaxFrame = 1 << 20

// ProtocolVersion identifies this request/response contract — the op codes and
// the shape of the frames above — and is the only compatibility signal clients
// may use. It is deliberately not the release version: the CLI and the desktop
// app are installed and updated separately, so two different release strings
// serving the same protocol is the normal case, not a fault. Bump this only
// when an existing op changes meaning or an old client would misread a reply;
// purely additive fields do not need it.
//
// Agents built before this field existed report 0. Every such release speaks
// protocol 1, so clients MUST read an absent/zero value as 1.
const ProtocolVersion = 1

const (
	// StartedByEnv marks who launched an fd0-agent process. It exists so a
	// client can tell "the agent I supervise" from "an agent somebody else
	// started" — the only thing that licenses stopping the process.
	StartedByEnv = "FD0_AGENT_STARTED_BY"
	// StartedByDesktop is set by fd0 Desktop's background service (and by the
	// desktop bridge in development) on the agents it starts itself.
	StartedByDesktop = "desktop"
)

// StartedByFromEnv reads StartedByEnv and keeps only values this build knows.
// An unknown value is dropped rather than echoed: the result is shown to users,
// and an agent must never be able to describe itself as something it is not.
func StartedByFromEnv() string {
	if os.Getenv(StartedByEnv) == StartedByDesktop {
		return StartedByDesktop
	}
	return ""
}

// Op codes. Ints (small CBOR encoding) keep frames tight.
const (
	OpUnlock           uint8 = 1
	OpLock             uint8 = 2
	OpStatus           uint8 = 3
	OpSign             uint8 = 4
	OpOpenSeal         uint8 = 5
	OpReSeal           uint8 = 6
	OpGetBody          uint8 = 7
	OpRecoveryExport   uint8 = 8
	OpEncryptSuperPriv uint8 = 9
	OpAddWrap          uint8 = 10
	OpRemoveWrap       uint8 = 11
)

// Request is the client→agent envelope. Exactly one of the typed fields is
// populated, identified by Op.
type Request struct {
	Op               uint8                `cbor:"op"`
	Unlock           *UnlockReq           `cbor:"unlock,omitempty"`
	Sign             *SignReq             `cbor:"sign,omitempty"`
	OpenSeal         *OpenSealReq         `cbor:"open_seal,omitempty"`
	ReSeal           *ReSealReq           `cbor:"re_seal,omitempty"`
	RecoveryExport   *RecoveryExportReq   `cbor:"recovery_export,omitempty"`
	EncryptSuperPriv *EncryptSuperPrivReq `cbor:"encrypt_super_priv,omitempty"`
	AddWrap          *AddWrapReq          `cbor:"add_wrap,omitempty"`
	RemoveWrap       *RemoveWrapReq       `cbor:"remove_wrap,omitempty"`
}

// EncryptSuperPrivReq asks the agent to AEAD-encrypt super_priv under
// K_unlock with the protocol-domain AAD ("fd0-encrypted-super-priv-v1" ||
// user_super_pub || method_id). Used by `fd0 auth add` to build the new
// AuthMethod.encrypted_super_priv field for the next auth.set.
type EncryptSuperPrivReq struct {
	UnlockKey []byte `cbor:"unlock_key"`
	MethodID  string `cbor:"method_id"`
}
type EncryptSuperPrivResp struct {
	EncryptedSuperPriv []byte `cbor:"encrypted_super_priv"`
}

// AddWrapReq adds a new vault wrap (new K_unlock for the same payload_key).
// VaultPath is retained for wire compatibility; the agent only accepts its
// canonical fdhome vault path. The method must already be active in the
// verified current user chain.
type AddWrapReq struct {
	VaultPath    string `cbor:"vault_path"`
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	UnlockKey    []byte `cbor:"unlock_key"`
}
type AddWrapResp struct{}

// RemoveWrapReq drops a wrap from the vault. The agent refuses if the
// target is the currently-active method or if it would leave zero wraps.
type RemoveWrapReq struct {
	VaultPath string `cbor:"vault_path"`
	MethodID  string `cbor:"method_id"`
}
type RemoveWrapResp struct{}

// RecoveryExportReq asks the agent to AEAD-encrypt super_priv under K_recovery
// (the caller's choice, derived from a recovery passphrase). super_priv never
// leaves the agent in plaintext.
type RecoveryExportReq struct {
	UnlockKey    []byte `cbor:"unlock_key"`     // K_recovery (32 B)
	UserSuperPub []byte `cbor:"user_super_pub"` // for AAD binding
	Nonce        []byte `cbor:"nonce"`
}

// RecoveryExportResp returns the AEAD ciphertext.
type RecoveryExportResp struct {
	Encrypted []byte `cbor:"encrypted"`
}

// Response is the agent→client envelope.
type Response struct {
	Err              string                `cbor:"err,omitempty"`
	Status           *StatusResp           `cbor:"status,omitempty"`
	Unlock           *UnlockResp           `cbor:"unlock,omitempty"`
	Sign             *SignResp             `cbor:"sign,omitempty"`
	OpenSeal         *OpenSealResp         `cbor:"open_seal,omitempty"`
	ReSeal           *ReSealResp           `cbor:"re_seal,omitempty"`
	GetBody          *GetBodyResp          `cbor:"get_body,omitempty"`
	RecoveryExport   *RecoveryExportResp   `cbor:"recovery_export,omitempty"`
	EncryptSuperPriv *EncryptSuperPrivResp `cbor:"encrypt_super_priv,omitempty"`
	AddWrap          *AddWrapResp          `cbor:"add_wrap,omitempty"`
	RemoveWrap       *RemoveWrapResp       `cbor:"remove_wrap,omitempty"`
}

// GetBodyResp returns the redacted vault body cached by the agent at unlock.
type GetBodyResp struct {
	RedactedBody []byte `cbor:"redacted_body"`
	UserSuperPub []byte `cbor:"user_super_pub"`
}

// UnlockReq supplies a credential to open the agent's canonical vault.
//
// VaultPath and UserChainPath remain on the wire for compatibility, but the
// agent rejects non-empty values that differ from its own fdhome.Paths. An
// empty UserChainPath no longer disables rollback and revocation checks.
type UnlockReq struct {
	VaultPath     string `cbor:"vault_path"`
	UserChainPath string `cbor:"user_chain_path,omitempty"`
	MethodType    string `cbor:"method_type"` // "passphrase" | "yubikey"
	Passphrase    []byte `cbor:"passphrase,omitempty"`
	// YubikeyPIN is forwarded to the YubiKey resolver when MethodType
	// is "yubikey". Empty for slots provisioned with PINPolicyNever
	// (touch-only mode). The agent does not retain the PIN beyond
	// the resolver call.
	YubikeyPIN []byte `cbor:"yubikey_pin,omitempty"`
}

// UnlockResp returns the redacted VaultBody (super_priv replaced with zeros).
// The agent retains the actual super_priv in mlocked memory.
type UnlockResp struct {
	RedactedBody []byte `cbor:"redacted_body"` // CBOR of proto.VaultBody with super_priv = zeros
	UserSuperPub []byte `cbor:"user_super_pub"`
}

// StatusResp reports current state. SuperPub is empty when locked.
type StatusResp struct {
	UnlockSession  string `cbor:"unlock_session,omitempty"` // Changes on every unlock, including within one second.
	Unlocked       bool   `cbor:"unlocked"`
	SinceUnix      int64  `cbor:"since,omitempty"`
	UserSuperPub   []byte `cbor:"user_super_pub,omitempty"`
	ActiveMethodID string `cbor:"active_method_id,omitempty"`
	// Protocol is ProtocolVersion; 0 means an agent that predates the field
	// and is read as 1. Version below is informational only.
	Protocol int `cbor:"protocol,omitempty"`
	// StartedBy is StartedByDesktop when fd0 Desktop started this agent, and
	// empty for every other launcher (a shell, a CLI unlock, an old build).
	StartedBy         string `cbor:"started_by,omitempty"`
	Version           string `cbor:"version,omitempty"`
	Flavor            string `cbor:"flavor,omitempty"`
	YubikeyEnabled    bool   `cbor:"yubikey_enabled,omitempty"`
	IdleTimeoutMillis int64  `cbor:"idle_timeout_ms,omitempty"`
	MaxLifetimeMillis int64  `cbor:"max_lifetime_ms,omitempty"`
}

// SignReq asks for an Ed25519 signature over Payload (caller already prefixed
// the domain separator).
type SignReq struct {
	Payload []byte `cbor:"payload"`
}

// SignResp returns the 64-byte signature.
type SignResp struct {
	Signature []byte `cbor:"signature"`
}

// OpenSealReq carries a sealed-box ciphertext for the agent's X25519 priv.
type OpenSealReq struct {
	Sealed []byte `cbor:"sealed"`
}

// OpenSealResp returns the plaintext (typically a 32-byte OEK).
type OpenSealResp struct {
	Plain []byte `cbor:"plain"`
}

// ReSealReq asks the agent to re-seal the vault. The agent fills super_priv
// in-place, encrypts under its cached payload_key, and writes atomically.
// The on-disk wraps are preserved unchanged — credential rotation goes
// through OpAddWrap / OpRemoveWrap.
type ReSealReq struct {
	VaultPath    string `cbor:"vault_path"`
	RedactedBody []byte `cbor:"redacted_body"`
}

// ReSealResp is empty on success.
type ReSealResp struct{}

// ReSealWrap is retained for wire-compatibility with older builds; unused.
type ReSealWrap struct {
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	UnlockKey    []byte `cbor:"unlock_key,omitempty"`
}

// ---- frame I/O ----

// WriteFrame writes one length-prefixed CBOR frame.
//
// The marshaled body may carry sensitive material (passphrases, YubiKey
// PINs, K_unlock bytes embedded in UnlockReq / ReSealReq frames). We
// wipe the local buffer before returning so the bytes don't outlive
// the call on the heap. Bytes already on the wire are out of our reach.
func WriteFrame(w io.Writer, v any) error {
	body, err := proto.Marshal(v)
	if err != nil {
		return err
	}
	defer crypto.Wipe(body)
	if len(body) > MaxFrame {
		return fmt.Errorf("agent: frame too large (%d > %d)", len(body), MaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadFrame reads one length-prefixed CBOR frame into v.
//
// Same hygiene as WriteFrame: the on-the-wire buffer is wiped after
// Unmarshal copies the relevant fields into v. v itself can still
// hold sensitive bytes; the caller is responsible for wiping its
// fields.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return errors.New("agent: bad frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	defer crypto.Wipe(buf)
	return proto.Unmarshal(buf, v)
}

// dialUnix is overridden in tests if needed.
var dialUnix = func(addr string) (net.Conn, error) { return net.Dial("unix", addr) }
