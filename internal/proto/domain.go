// Package proto defines fd0's wire format: CBOR schemas, domain separators,
// and hashing helpers shared by client, agent, and server.
//
// Every value used as input to Ed25519 signing or AEAD AAD is prefixed with
// one of the domain separators below. A signature or ciphertext valid under
// one domain MUST be invalid under any other (PROTOCOL.md §1.1).
//
// THREAT: T13 (cross-protocol signature reuse),
//
//	T14 (cross-context AEAD ciphertext reuse).
package proto

// Domain separators. See PROTOCOL.md §1.1.
const (
	DomainEvent              = "fd0-event-v1"                // scope event signatures
	DomainUserEvent          = "fd0-user-event-v1"           // user identity event signatures
	DomainCard               = "fd0-card-v1"                 // identity card signatures
	DomainHTTP               = "fd0-http-request-v1"         // per-request HTTP auth
	DomainEncryptedSuperPriv = "fd0-encrypted-super-priv-v1" // AAD: auth-method ciphertext
	DomainVaultBody          = "fd0-vault-body-v1"           // AAD: vault body
	DomainVaultWrap          = "fd0-vault-wrap-v1"           // AAD: vault wrapped key
	DomainRecoveryKey        = "fd0-recovery-key-v1"         // AAD: recovery export
	DomainRecoveryBundle     = "fd0-recovery-bundle-v2"      // AAD: recovery bootstrap snapshot
	DomainSafety             = "fd0-safety-v1"               // safety-number derivation prefix

	// Transparency log (TRANSLOG.md §2). One domain per hash position so a
	// leaf hash, an inner-node hash, and the empty-tree sentinel are pairwise
	// distinguishable preimages even at the same byte length.
	DomainTranslogLeaf       = "fd0-translog-leaf-v1"        // SHA-256 prefix for leaves
	DomainTranslogNode       = "fd0-translog-node-v1"        // SHA-256 prefix for inner nodes
	DomainTranslogEmpty      = "fd0-translog-empty-v1"       // SHA-256 input for empty-tree root
	DomainTranslogSTH        = "fd0-translog-sth-v1"         // STH signature input
	DomainTranslogServerInfo = "fd0-translog-server-info-v1" // server-info signature input
	DomainServerFingerprint  = "fd0-server-fingerprint-v1"   // user-facing fingerprint over (URL, pubkey)

	// Witness cosign (TRANSLOG.md §10). A witness cosigns an STH it
	// observed at a specific server, binding the cosign to BOTH the
	// STH bytes AND the server URL the witness fetched it from. This
	// prevents replay across servers (a witness signature for chain
	// X@server1 must not validate as a cosign for chain X@server2).
	DomainWitnessCosign = "fd0-witness-cosign-v1"
)

// Magic strings for on-disk file headers.
const (
	VaultMagic    = "FD0V"
	RecoveryMagic = "FD0K"
)

// Event kinds.
const (
	KindAuthSet      = "auth.set"
	KindMemberChange = "member.change"
	KindSecretSet    = "secret.set"
)

// member.change ops.
const (
	OpAdd    = "add"
	OpRemove = "remove"
	// OpRole changes an existing member's role (docs/SCOPE_ROLES_PLAN.md).
	OpRole = "role"
)

// Scope member roles. A member.change without a role means RoleAdmin.
const (
	RoleAdmin  = "admin"
	RoleWriter = "writer"
	RoleReader = "reader"
)

// AuthMethod types.
const (
	AuthPassphrase = "passphrase"
	AuthYubikey    = "yubikey"
)
