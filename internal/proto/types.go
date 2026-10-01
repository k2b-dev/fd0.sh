package proto

// CBOR struct shapes for events, identity cards, vault, and recovery files.
//
// Field tags use `cbor:"<name>,keyasint?"`. We use string keys throughout to
// match the CDDL in PROTOCOL.md exactly. Determinism is enforced by the
// encoder mode (CoreDetEncOptions sorts map keys bytewise-lexically).

// ---- User identity chain (PROTOCOL.md §3) ----

// UserEvent is one entry in the user identity chain. Kind is always "auth.set".
type UserEvent struct {
	Kind         string         `cbor:"kind"`
	Seq          uint64         `cbor:"seq"`
	PrevHash     []byte         `cbor:"prev_hash"` // nil iff seq=0
	UserSuperPub []byte         `cbor:"user_super_pub"`
	Payload      AuthSetPayload `cbor:"payload"`
	Signature    []byte         `cbor:"signature"`
}

// userEventSigned is UserEvent without the signature field; signed_input is
// "fd0-user-event-v1" || cbor(userEventSigned).
type userEventSigned struct {
	Kind         string         `cbor:"kind"`
	Seq          uint64         `cbor:"seq"`
	PrevHash     []byte         `cbor:"prev_hash"`
	UserSuperPub []byte         `cbor:"user_super_pub"`
	Payload      AuthSetPayload `cbor:"payload"`
}

// AuthSetPayload is the payload of an auth.set event.
type AuthSetPayload struct {
	Active []AuthMethod `cbor:"active"`
}

// AuthMethod is one credential by which super_priv can be unwrapped.
type AuthMethod struct {
	MethodID           string `cbor:"method_id"`
	MethodType         string `cbor:"method_type"`
	PublicParams       []byte `cbor:"public_params"`
	EncryptedSuperPriv []byte `cbor:"encrypted_super_priv"`
}

// YubikeyPublicParams is the CBOR struct embedded as `public_params` for an
// AuthMethod with method_type == "yubikey".
//
// Layout rationale: a sealed-box is a libsodium anonymous box (32-byte
// ephemeral pub || ciphertext). Only the holder of the slot's private key
// can open it; touching the YubiKey is the proof-of-presence. We embed
// the slot's X25519 public key alongside so the unlock-side can verify it
// is talking to the right card before invoking PIV (and to surface a
// helpful "wrong YubiKey" error rather than a cryptic decrypt failure).
//
// SealedKUnlock decrypts to a 32-byte K_unlock that is then used as the
// AEAD key over WrappedKey.Wrapped (same shape as the passphrase path,
// just with a different K_unlock derivation).
type YubikeyPublicParams struct {
	X25519Pub     []byte `cbor:"x25519_pub"`      // 32-byte slot pubkey
	SealedKUnlock []byte `cbor:"sealed_k_unlock"` // sealed-box(K_unlock, X25519Pub)
	Slot          uint8  `cbor:"slot"`            // PIV slot id (default 0x9d)
	PinPolicy     string `cbor:"pin_policy,omitempty"`
	TouchPolicy   string `cbor:"touch_policy,omitempty"`
}

// SignedInput returns "fd0-user-event-v1" || cbor(UserEvent without signature).
func (e *UserEvent) SignedInput() ([]byte, error) {
	body, err := Marshal(userEventSigned{
		Kind: e.Kind, Seq: e.Seq, PrevHash: e.PrevHash,
		UserSuperPub: e.UserSuperPub, Payload: e.Payload,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainUserEvent), body...), nil
}

// PrevHashInput returns cbor(UserEvent without signature) — the input hashed
// to produce the next event's prev_hash.
func (e *UserEvent) PrevHashInput() ([]byte, error) {
	return Marshal(userEventSigned{
		Kind: e.Kind, Seq: e.Seq, PrevHash: e.PrevHash,
		UserSuperPub: e.UserSuperPub, Payload: e.Payload,
	})
}

// ---- Scope event chain (PROTOCOL.md §4) ----

// ScopeEvent is the wire form of every scope event.
type ScopeEvent struct {
	SignedPrefix SignedPrefix `cbor:"signed_prefix"`
	Signature    Signature    `cbor:"signature"`
}

// SignedPrefix is the part of a ScopeEvent covered by the signature and by
// the prev_hash chain. Per-kind payload lives under Payload.
//
// Scope is *string so genesis encodes as CBOR null (0xf6) per PROTOCOL.md
// §4.1 (`scope: tstr / nil, nil iff genesis`); a non-genesis event uses a
// non-nil pointer so CBOR emits a definite text-string. PrevHash uses the
// same nil-vs-bytes distinction implicitly: nil []byte is CBOR null.
type SignedPrefix struct {
	Kind          string        `cbor:"kind"`
	Scope         *string       `cbor:"scope"`
	PrevHash      []byte        `cbor:"prev_hash"`
	Author        []byte        `cbor:"author"`
	Seq           uint64        `cbor:"seq"`
	OEKVersion    uint64        `cbor:"oek_version"`
	KeyDeliveries []KeyDelivery `cbor:"key_deliveries"`
	Payload       Payload       `cbor:"payload"`
}

// Payload is a sum of member.change and secret.set payloads. Both fields are
// "omitempty" so the wire form has exactly one populated key per kind.
type Payload struct {
	// member.change
	Op            string `cbor:"op,omitempty"`
	Member        []byte `cbor:"member,omitempty"`
	EncProjection []byte `cbor:"enc_projection,omitempty"`
	// Role is the member's role on add or role ops; absent means admin
	// and keeps legacy events byte-identical.
	Role string `cbor:"role,omitempty"`
	// secret.set
	EncBody []byte `cbor:"enc_body,omitempty"`
}

// KeyDelivery is one sealed-box copy of the OEK to one recipient.
type KeyDelivery struct {
	RecipientPubkey []byte `cbor:"recipient_pubkey"`
	Sealed          []byte `cbor:"sealed"`
}

// Signature carries the signing key alongside the signature so verifiers can
// match the embedded key against author and against the scope's auth_list.
type Signature struct {
	SignerPubkey []byte `cbor:"signer_pubkey"`
	Signature    []byte `cbor:"signature"`
}

// SignedInput returns "fd0-event-v1" || cbor(SignedPrefix).
func (e *ScopeEvent) SignedInput() ([]byte, error) {
	body, err := Marshal(e.SignedPrefix)
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainEvent), body...), nil
}

// PrevHashInput returns cbor(SignedPrefix) — input hashed for next prev_hash.
func (e *ScopeEvent) PrevHashInput() ([]byte, error) { return Marshal(e.SignedPrefix) }

// ---- Plaintext bodies ----

// MemberProjection is the plaintext of a member.change enc_projection.
// It is the full set of current SecretRecords at this seq.
type MemberProjection struct {
	Secrets []SecretInProjection `cbor:"secrets"`
}

// SecretInProjection carries the secret id alongside its record so a new
// member receives a complete map on join.
type SecretInProjection struct {
	ID     string        `cbor:"id"`
	Record *SecretRecord `cbor:"record"`
}

// SecretBody is the plaintext of a secret.set enc_body.
type SecretBody struct {
	ID     string        `cbor:"id"`
	Record *SecretRecord `cbor:"record"` // nil = tombstone
}

// SecretRecord is the user-facing record stored under a secret id.
type SecretRecord struct {
	Name          string            `cbor:"name"`
	Type          string            `cbor:"type"`
	SchemaVersion uint64            `cbor:"schema_version"`
	Payload       any               `cbor:"payload"`
	Tags          map[string]string `cbor:"tags"`
}

// ---- Identity card (PROTOCOL.md §2.3) ----

// IdentityCard is the small CBOR-then-base64url document users exchange to
// pin each other's super_pub.
type IdentityCard struct {
	Version   uint8  `cbor:"version"`
	ShortID   string `cbor:"shortId"`
	SuperPub  []byte `cbor:"super_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
	ExpiresAt uint64 `cbor:"expires_at"`
	Signature []byte `cbor:"signature"`
}

type identityCardSigned struct {
	Version   uint8  `cbor:"version"`
	ShortID   string `cbor:"shortId"`
	SuperPub  []byte `cbor:"super_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
	ExpiresAt uint64 `cbor:"expires_at"`
}

// SignedInput returns "fd0-card-v1" || cbor(card without signature).
func (c *IdentityCard) SignedInput() ([]byte, error) {
	body, err := Marshal(identityCardSigned{
		Version: c.Version, ShortID: c.ShortID, SuperPub: c.SuperPub,
		IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainCard), body...), nil
}

// ---- Vault (PROTOCOL.md §6.1) ----

// VaultFile is the encrypted vault on disk. Body is decrypted into VaultBody.
type VaultFile struct {
	Magic              string       `cbor:"magic"`
	Version            uint8        `cbor:"version"`
	UserSuperPub       []byte       `cbor:"user_super_pub"`
	WrappedPayloadKeys []WrappedKey `cbor:"wrapped_payload_keys"`
	BodyNonce          []byte       `cbor:"body_nonce"`
	Body               []byte       `cbor:"body"`
}

// VaultFileHeader is VaultFile minus body; used as part of the body AAD.
type VaultFileHeader struct {
	Magic              string       `cbor:"magic"`
	Version            uint8        `cbor:"version"`
	UserSuperPub       []byte       `cbor:"user_super_pub"`
	WrappedPayloadKeys []WrappedKey `cbor:"wrapped_payload_keys"`
	BodyNonce          []byte       `cbor:"body_nonce"`
}

// WrappedKey is one unlock entry: payload_key wrapped under one auth method.
type WrappedKey struct {
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	WrapNonce    []byte `cbor:"wrap_nonce"`
	Wrapped      []byte `cbor:"wrapped"`
}

// WrappedKeyHeader is WrappedKey minus wrapped; used as part of the wrap AAD.
type WrappedKeyHeader struct {
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	WrapNonce    []byte `cbor:"wrap_nonce"`
}

// VaultBody is the plaintext that lives inside VaultFile.Body.
type VaultBody struct {
	// SSHGrants are personal, device-bound authorizations; never scope-shared.
	SSHGrants        []SSHGrant                `cbor:"ssh_grants,omitempty"`
	SuperPriv        []byte                    `cbor:"super_priv"`
	AuthTip          ChainTip                  `cbor:"auth_tip"`
	Scopes           map[string]ScopeVaultData `cbor:"scopes"`
	PinnedIdentities map[string]PinnedIdentity `cbor:"pinned_identities"`

	// PinnedServers maps normalised server URL → PinnedServer record.
	// First-contact pinning ceremony per TRANSLOG.md §6.1: the user
	// fingerprints the server's translog signing pubkey out-of-band
	// before any STHs from that server are accepted. A subsequent
	// /v1/server-info that returns a different pub for the same URL
	// is rejected with "pinned-key-mismatch" (TRANSLOG.md §6.4).
	// omitempty for legacy-vault decoding.
	PinnedServers map[string]PinnedServer `cbor:"pinned_servers,omitempty"`

	// LastSTHUser is the most recently verified STH for the user
	// chain, stored as deterministic CBOR over translog.STH (raw
	// bytes to avoid an import cycle proto ↔ translog). Anchors the
	// next sync's consistency check (TRANSLOG.md §6.2/§6.3).
	// omitempty for legacy decoding.
	LastSTHUser []byte `cbor:"last_sth_user,omitempty"`
}

// PinnedServer is one entry in VaultBody.PinnedServers. The map key is
// the normalised server URL; the struct holds only the bytes the user
// actually agreed to via the safety-number ceremony.
//
// Registered records whether THIS user has already POSTed their
// genesis user event to /users on this server. Set true after the
// first successful (or `super_pub_taken`-409) registration round.
// Used to avoid pointless POSTs on every sync.
type PinnedServer struct {
	ServerPub       []byte `cbor:"server_pub"`
	PinnedAt        uint64 `cbor:"pinned_at"`
	Registered      bool   `cbor:"registered,omitempty"`
	MembershipAfter string `cbor:"membership_after,omitempty"`
}

// ScopeVaultData holds the OEK lineage and the latest accepted chain tip for
// one scope this client is a member of. Label is a local-only convenience
// (never sent to the server / never part of any signed input).
//
// PushFloor (omitempty, defaults to 0) is the lowest seq we still need to
// push. Initial state == 0 means "push everything"; we set it to
// (max accepted seq + 1) only after the server has confirmed and the vault
// has been re-sealed. On any failure the field stays put → next sync
// re-pushes the same suffix → server dedups by event_id. The invariant is
// "PushFloor ≤ true highest pushed seq + 1": never advance speculatively.
//
// Leaving is set by `scope leave` to mark a scope whose `member.change
// op=remove member=self` event has been appended locally but not yet
// pushed to the server. Sync iterates Leaving scopes specifically so
// the leave event reaches the server before we drop the local copy
// (the previous behaviour dropped immediately, losing the leave event
// and causing the server to re-discover us as a member on next pull).
// Once the server returns Denied for a Leaving scope, the normal drop
// path runs.
type ScopeVaultData struct {
	Label    string     `cbor:"label,omitempty"`
	OEKs     []OEKEntry `cbor:"oeks"`
	ChainTip ChainTip   `cbor:"chain_tip"`
	Leaving  bool       `cbor:"leaving,omitempty"`

	// Legacy single-server fields (≤ v0.0.4). New writes go to
	// PerServer[<currentlySyncingServer>]; these survive as the
	// initial-state fallback when PerServer is empty (first sync after
	// upgrading from a vault that knew only one server). Once PerServer
	// has any entry, lookups for an unknown server return defaults —
	// the legacy field is no longer used as a fallback because doing
	// so would feed a new replica stale server-A state.
	PushFloor uint64 `cbor:"push_floor,omitempty"`
	LastSTH   []byte `cbor:"last_sth,omitempty"`

	// PerServer is the v0.0.5+ multi-server state. Key is the canonical
	// server URL (canon.URL.String()); value carries the push floor and
	// last verified STH for that server. Each entry advances
	// independently — server A's STH can never poison a consistency
	// proof against server B's tree.
	PerServer map[string]ScopeServerState `cbor:"per_server,omitempty"`
}

// ScopeServerState is the per-(scope, server) cursor: how far we've
// pushed to this server, and the last STH we verified from it.
// Multi-server clients hold one entry per pinned server; single-server
// clients still hold one entry (after first v0.0.5+ sync).
type ScopeServerState struct {
	PushFloor uint64 `cbor:"push_floor,omitempty"`
	LastSTH   []byte `cbor:"last_sth,omitempty"`
}

// PushFloorFor returns the push floor for server. Precedence:
// PerServer[server] → legacy singular PushFloor (only if PerServer is
// empty, i.e. pre-v0.0.5 state) → 0 (fresh server in a multi-server
// vault).
func (sd ScopeVaultData) PushFloorFor(server string) uint64 {
	if s, ok := sd.PerServer[server]; ok {
		return s.PushFloor
	}
	if len(sd.PerServer) == 0 {
		return sd.PushFloor
	}
	return 0
}

// LastSTHFor returns the last verified STH for server. Same precedence
// as PushFloorFor.
func (sd ScopeVaultData) LastSTHFor(server string) []byte {
	if s, ok := sd.PerServer[server]; ok {
		return s.LastSTH
	}
	if len(sd.PerServer) == 0 {
		return sd.LastSTH
	}
	return nil
}

// SetPushFloorFor sets per-server push floor; lazily initialises
// PerServer.
func (sd *ScopeVaultData) SetPushFloorFor(server string, floor uint64) {
	if sd.PerServer == nil {
		sd.PerServer = map[string]ScopeServerState{}
	}
	s := sd.PerServer[server]
	s.PushFloor = floor
	sd.PerServer[server] = s
}

// SetLastSTHFor sets per-server LastSTH; lazily initialises PerServer.
func (sd *ScopeVaultData) SetLastSTHFor(server string, sth []byte) {
	if sd.PerServer == nil {
		sd.PerServer = map[string]ScopeServerState{}
	}
	s := sd.PerServer[server]
	s.LastSTH = sth
	sd.PerServer[server] = s
}

// Clone returns a deep copy of sd: every slice, map, and byte slice is
// independently allocated, so later in-place mutation of the copy (or of
// the original) leaves the other untouched.
//
// Used by the reconcile rollback snapshot (cli.reconcileAndRepush): the
// transactional restore stores this snapshot back into the vault on any
// error. A shallow struct copy is NOT enough — ScopeVaultData carries an
// OEKs backing array (upsertOEK mutates elements in place), a PerServer
// map (SetPushFloorFor / SetLastSTHFor mutate it in place), and byte
// slices, all of which a plain `x := sd` would alias. Without this the
// "failed reconcile leaves local state untouched" guarantee leaks
// advanced push floors / STHs / OEK contents into the restored snapshot.
func (sd ScopeVaultData) Clone() ScopeVaultData {
	out := sd // scalars: Label, Leaving, PushFloor, ChainTip.Seq
	if sd.OEKs != nil {
		out.OEKs = make([]OEKEntry, len(sd.OEKs))
		for i, e := range sd.OEKs {
			out.OEKs[i] = OEKEntry{Version: e.Version, Key: append([]byte(nil), e.Key...)}
		}
	}
	out.ChainTip.Hash = append([]byte(nil), sd.ChainTip.Hash...)
	out.LastSTH = append([]byte(nil), sd.LastSTH...)
	if sd.PerServer != nil {
		out.PerServer = make(map[string]ScopeServerState, len(sd.PerServer))
		for k, v := range sd.PerServer {
			out.PerServer[k] = ScopeServerState{
				PushFloor: v.PushFloor,
				LastSTH:   append([]byte(nil), v.LastSTH...),
			}
		}
	}
	return out
}

// OEKEntry is one (version, key) pair.
type OEKEntry struct {
	Version uint64 `cbor:"version"`
	Key     []byte `cbor:"key"`
}

// ChainTip is the latest seq+hash this client has accepted on a chain.
type ChainTip struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}

// PinnedIdentity is a peer the user has imported via identity card.
type PinnedIdentity struct {
	SuperPub []byte `cbor:"super_pub"`
	Label    string `cbor:"label"`
}

// ---- Recovery export (PROTOCOL.md §6.3) ----

// RecoveryFile is the offline-stored identity backup. Version 1 contains only
// super_priv. Version 2 additionally carries an encrypted bootstrap snapshot
// so the exported authentication methods keep working on a restored device.
type RecoveryFile struct {
	Magic              string       `cbor:"magic"`
	Version            uint8        `cbor:"version"`
	UserSuperPub       []byte       `cbor:"user_super_pub"`
	Salt               []byte       `cbor:"salt"`
	Argon2Params       Argon2Params `cbor:"argon2_params"`
	Nonce              []byte       `cbor:"nonce"`
	EncryptedSuperPriv []byte       `cbor:"encrypted_super_priv"`
	PayloadNonce       []byte       `cbor:"payload_nonce,omitempty"`
	EncryptedPayload   []byte       `cbor:"encrypted_payload,omitempty"`
}

// RecoveryPayloadV2 is encrypted as one unit under K_recovery. Both embedded
// files remain encrypted/signed in their native formats as defence in depth.
type RecoveryPayloadV2 struct {
	UserChain []byte `cbor:"user_chain"`
	Vault     []byte `cbor:"vault"`
}

// Argon2Params are the cost parameters used for passphrase-derived keys.
type Argon2Params struct {
	M uint32 `cbor:"m"` // memory in KiB
	T uint32 `cbor:"t"` // iterations
	P uint8  `cbor:"p"` // parallelism
}

// SSHGrant binds a local exception to exact host configuration and SSH keys.
// It contains no private key material. It is owned by the agent, not ReSeal callers.
type SSHGrant struct {
	ID        string   `cbor:"id" json:"id"`
	DeviceID  string   `cbor:"device_id" json:"deviceId"`
	ScopeID   string   `cbor:"scope_id" json:"scopeId"`
	Name      string   `cbor:"name" json:"name"`
	HostID    string   `cbor:"host_id" json:"-"`
	KeyID     string   `cbor:"key_id" json:"-"`
	HostJSON  []byte   `cbor:"host_json" json:"-"`
	KeyPublic []byte   `cbor:"key_public" json:"-"`
	HostKeys  [][]byte `cbor:"host_keys" json:"-"`
}
