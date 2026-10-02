# fd0 Protocol — Cryptographic Specification (v1)

Wire format and cryptographic constructions. Companion specs: `API.md`, `STORAGE.md`, `TRANSLOG.md`, `THREATS.md`.

Schemas use CDDL. `||` denotes byte concatenation. `cbor(x)` denotes deterministic CBOR (RFC 8949 §4.2.1). `bstr .size N` is an N-byte byte string. AEAD ciphertext layout is `nonce(12) || ct || tag(16)`.

## Contents

1. [Primitives](#1-primitives) — algorithms, domain separators, identifiers.
2. [Identity](#2-identity) — `super_keypair`, `shortId`, identity cards, safety numbers.
3. [User identity event chain](#3-user-identity-event-chain) — `auth.set`, login, credential rotation.
4. [Scope event log](#4-scope-event-log) — `member.change`, `secret.set`, OEK distribution, projection verification.
5. [AEAD bindings](#5-aead-bindings) — site-to-AAD table.
6. [Vault and recovery files](#6-vault-and-recovery-files) — vault file format, unwrap/re-seal, recovery export.
7. [Replay and concurrency](#7-replay-and-concurrency) — CAS, de-duplication, HTTP replay, chain replay, cursor advancement.
8. [Conformance](#8-conformance) — MUST / MUST NOT for implementers.

---

## 1. Primitives

| Algorithm   | Use                                                       |
| ----------- | --------------------------------------------------------- |
| Ed25519     | Signatures                                                |
| X25519      | Sealed-box recipients (derived from Ed25519, §1.2)        |
| AES-256-GCM | AEAD                                                      |
| Argon2id    | Passphrase KDF                                            |
| SHA-256     | Hashing                                                   |
| BLAKE2b-256 | Internal libsodium constructions                          |

### 1.1 Domain separators

Every Ed25519 signature is over `domain || cbor(object)`. Every AEAD AAD includes a domain string. A ciphertext or signature valid under one domain MUST be invalid under any other.

| Domain                         | Use                                          |
| ------------------------------ | -------------------------------------------- |
| `fd0-event-v1`                 | Scope event signatures (§4)                  |
| `fd0-user-event-v1`            | User identity event signatures (§3)          |
| `fd0-card-v1`                  | Identity card signatures (§2.3)              |
| `fd0-http-request-v1`          | Per-request HTTP auth (`API.md` §1)          |
| `fd0-encrypted-super-priv-v1`  | AAD for the auth-method ciphertext           |
| `fd0-vault-body-v1`            | AAD for vault body                           |
| `fd0-vault-wrap-v1`            | AAD for vault wrapped payload key            |
| `fd0-recovery-key-v1`          | AAD for recovery export (§6.3)               |
| `fd0-safety-v1`                | Prefix for safety-number derivation          |

### 1.2 Ed25519 → X25519 conversion

```
x25519_pub  = crypto_sign_ed25519_pk_to_curve25519(ed25519_pub)
x25519_priv = crypto_sign_ed25519_sk_to_curve25519(ed25519_priv)
```

No alternative derivation is permitted.

### 1.3 Identifiers

| Kind            | Form                                                      | Source                          |
| --------------- | --------------------------------------------------------- | ------------------------------- |
| `shortId`       | 8 chars Crockford-base32                                  | server-assigned at registration |
| Event ID        | `e_` + base32(truncate_128(SHA-256(prefix)))              | content hash                    |
| Scope ID        | `s_` + base32(truncate_128(SHA-256(genesis_event_id)))    | server-derived                  |
| Secret ID       | `s_` + ULID                                               | client-assigned                 |
| Auth method ID  | `am_` + ULID                                              | client-assigned                 |

There is one scope kind. A "personal" scope is a scope with one member.

---

## 2. Identity

### 2.1 super_keypair

Each user has one Ed25519 keypair, generated at registration, never rotated.

- `super_priv` (64 B): held in the vault on each device. Never sent in plaintext.
- `super_pub` (32 B): user's cryptographic identity. Appears in cards, scope auth lists, event author fields, and sealed-box recipients.

If `super_priv` is compromised the user re-onboards with a new identity, or restores from a recovery export (§6.3).

### 2.2 shortId

Server-assigned 8-char Crockford-base32 at registration. Server retries on collision. Treated as semi-private.

### 2.3 Identity card

```
IdentityCard = {
    version    : uint .size 1,             ; = 1
    shortId    : tstr,
    super_pub  : bstr .size 32,
    issued_at  : uint,
    expires_at : uint,                      ; typically issued_at + 86400
    signature  : bstr .size 64,
}

signed_input = "fd0-card-v1" || cbor({version, shortId, super_pub, issued_at, expires_at})
signature    = Ed25519(super_priv, signed_input)
```

Wire form: `fd0://card/<base64url(cbor(IdentityCard))>`.

Importer requirements: decode; verify signature against `super_pub`; check `expires_at > now`; display safety number; on user confirmation, persist `(shortId, super_pub)` as a pinned identity. The card carries no human-readable handle.

### 2.4 Safety number

```
digest = SHA-256("fd0-safety-v1" || cbor({shortId, super_pub}))
take first 24 bytes
encode as 12 groups of 5 decimal digits (16 bits per group, zero-padded)
display as 3 lines of 4 groups
```

Compared out of band during first-trust verification.

Worked example:

```
shortId   = "jg379se4"
super_pub = ba921a98 c96c8274 52f61ae4 75ddbbe4
            e5938bd4 b560faa0 b141adb8 730a8b20

display:
  40010 36850 12295 00838
  20844 20977 47468 34175
  07128 20851 42294 58206
```

Two devices comparing these 12 groups over a trusted channel verify
the identity binding without exchanging the raw public key.

---

## 3. User identity event chain

Per-user append-only signed chain. One event kind: `auth.set`. Each event is a signed snapshot of the active auth methods. The first event (seq=0, prev_hash=nil) bootstraps the user; the server assigns a `shortId` on accept.

### 3.1 Common envelope

```
UserEvent = {
    kind           : "auth.set",
    seq            : uint,                  ; 0 at registration, monotonic
    prev_hash      : bstr .size 32 / nil,   ; nil iff seq=0
    user_super_pub : bstr .size 32,
    payload        : { active: [+ AuthMethod] },
    signature      : bstr .size 64,
}

AuthMethod = {
    method_id            : tstr,                ; "am_…", ULID
    method_type          : "passphrase" / "yubikey",
    public_params        : bstr,                ; method-specific; see below
    encrypted_super_priv : bstr,                ; AEAD ciphertext
}

YubikeyPublicParams = {                         ; cbor-encoded into AuthMethod.public_params
                                                ; when method_type = "yubikey"
    x25519_pub      : bstr .size 32,            ; the YubiKey slot's pubkey
    sealed_k_unlock : bstr,                     ; libsodium crypto_box_seal of K_unlock
                                                ; to x25519_pub (≥ 80 B for a 32-B K_unlock)
    slot            : uint .size 1,             ; PIV slot id (v1 = 0x9d Key Management only)
    pin_policy      : "never" / "once",         ; optional; absent = legacy optional PIN prompt
    touch_policy    : "always" / "cached" / "never", ; optional; recorded enrollment policy
}

signed_input   = "fd0-user-event-v1" || cbor(UserEvent without signature)
signature      = Ed25519(super_priv, signed_input)
prev_hash[N+1] = SHA-256(cbor(UserEvent[N] without signature))

K_unlock derivation:
    passphrase     : Argon2id(passphrase, salt = public_params[0:16], params = public_params[16:])
    yubikey        : K_unlock = crypto_box_seal_open(YubikeyPublicParams.sealed_k_unlock,
                                                      on-card_x25519_priv,
                                                      YubikeyPublicParams.x25519_pub)
                     The sealed_k_unlock is opened on-card via X25519 ECDH against the
                     slot's private key; nothing leaves the card. Raw 32-byte K_unlock
                     is recovered host-side and consumed exactly like a passphrase-
                     derived K_unlock.

encrypted_super_priv = AEAD(
    key   = K_unlock,
    nonce = random(12),
    plain = super_priv,
    aad   = "fd0-encrypted-super-priv-v1" || user_super_pub || method_id,
)
```

Server validation:
- Signature verifies under `user_super_pub`.
- `payload.active` is non-empty; all `method_id` values are unique within the event.
- At seq=0: `prev_hash == nil`; the server assigns and returns a `shortId`.
- At seq>0: `prev_hash` matches user-chain tip.

### 3.2 Login

```
1. Fetch latest auth.set event (API: GET /users/<shortId>/events?latest=true).
2. Verify signature.
3. For each AuthMethod m in payload.active matching the supplied credential type:
     compute K_unlock from credential and m.public_params
     attempt AEAD-decrypt of m.encrypted_super_priv with AAD bound to m.method_id
4. Check Ed25519_pub(super_priv) == user_super_pub. Else reject.
```

Login does not modify the chain.

### 3.3 Credential rotation

A credential change posts a new `auth.set` with the resulting active set. Removing a method requires that the new active set is non-empty.

If `super_priv` is held only by a method suspected to be compromised, the user adds a new method first, then posts a follow-up event removing the old one. Both events are signed with `super_priv` accessed via any active method at signing time.

If `super_priv` is lost without a recovery export (§6.3), the identity is unrecoverable.

---

## 4. Scope event log

Per-scope append-only signed chain. One scope, one OEK lineage. Two event kinds: `member.change` and `secret.set`.

The first event of a scope is a `member.change` with `op = "add"`, `prev_hash = nil`, and one `KeyDelivery` to the creator. The server derives `scope_id` from the event ID.

Each `secret.set` event is the snapshot for one `secret_id`. Clients maintain a per-scope `secret_id → latest event` index in memory; reads are O(1) lookups.

### 4.1 Common envelope

```
ScopeEvent = {
    signed_prefix : SignedPrefix,
    signature     : Signature,
}

SignedPrefix = {
    kind           : "member.change" / "secret.set",
    scope          : tstr / nil,                ; nil iff genesis
    prev_hash      : bstr .size 32 / nil,       ; nil iff genesis
    author         : bstr .size 32,             ; super_pub of signer
    seq            : uint,
    oek_version    : uint,
    key_deliveries : [* KeyDelivery],           ; non-empty for member.change; empty for secret.set
    payload        : <kind-specific>,
}

KeyDelivery = { recipient_pubkey: bstr .size 32, sealed: bstr }
Signature   = { signer_pubkey: bstr .size 32, signature: bstr .size 64 }

signed_input    = "fd0-event-v1" || cbor(SignedPrefix)
event_signature = Ed25519(super_priv, signed_input)

event_id   = "e_" || base32(truncate_128(SHA-256(cbor(SignedPrefix))))
prev_hash[N+1] = SHA-256(cbor(SignedPrefix[N]))

invariants:
  - author == signature.signer_pubkey
  - signature verifies
  - prev_hash matches scope tip (nil only for genesis)
  - author ∈ current scope.auth_list
```

`KeyDelivery.sealed = crypto_box_seal(OEK_v(oek_version), X25519_from(recipient_pubkey))`.

### 4.2 `member.change`

```
payload = {
    op             : "add" / "remove" / "role",
    member         : bstr .size 32,             ; super_pub
    enc_projection : bstr,                      ; AEAD under OEK_v(oek_version); absent for op=role
    ? role         : "admin" / "writer" / "reader", ; add (optional) and role (required); absent = admin
}

Body (plaintext) = { secrets : [* SecretRecord] }   ; current projection at this seq

server validates:
  - op = "add" / "remove": oek_version == prior_oek_version_max + 1   (=1 at genesis)
  - op = "add" never grows auth_list beyond 1000 members
  - key_deliveries count ≤ 131072; existing over-limit scopes may only shrink
  - op = "add":    member ∉ auth_list;
                   { kd.recipient_pubkey } == auth_list ∪ {member}
  - op = "remove": member ∈ auth_list;
                   { kd.recipient_pubkey } == auth_list ∖ {member}
                   (removing the last member is allowed; the scope becomes a tombstone
                    and accepts no further events)
  - body size ≤ 1 MB

roles (server validator and client replay apply the same rules, against the
roles before the event):
  - members without an explicit role are admins; legacy events carry no role
  - secret.set: author is writer or admin
  - member.change (any op): author is admin; the genesis author is admin
  - op = "role": member ∈ auth_list, role differs from the current one,
                 oek_version == oek_version_max, key_deliveries == [], no enc_projection
  - after the event a non-empty auth_list keeps at least one admin

server effect:
  - genesis (seq=0, op=add, member=author): assigns scope_id, auth_list = [author],
                                              oek_version_max = 1
  - op = "add":    auth_list ∪= {member}, oek_version_max += 1
  - op = "remove": auth_list ∖= {member}, oek_version_max += 1
  - op = "role":   roles[member] = role (auth_list and oek_version_max unchanged)
```

### 4.3 `secret.set`

```
payload = {
    enc_body : bstr,                            ; AEAD under OEK_v(oek_version)
}

Body (plaintext) = {
    id     : tstr,                              ; "s_…", ULID, stable
    record : SecretRecord / nil,                ; nil = tombstone
}

SecretRecord = {
    name           : tstr,
    type           : tstr,                      ; "<domain>.<entity>", e.g. "ssh.host"
    schema_version : uint,
    payload        : any,
    tags           : { * tstr => tstr },
}

server validates:
  - oek_version == scope.oek_version_max
    (lower → 409 stale_oek_version; higher → 409 future_oek_version)
  - key_deliveries == []
  - body size ≤ 64 KB
```

The server does not see `id`, `name`, or `payload`.

### 4.4 OEK distribution

OEKs are distributed exclusively via `KeyDelivery` entries on `member.change` events. Server enforces:

- On `op = add` and `op = remove`: `{ kd.recipient_pubkey | kd ∈ key_deliveries }` exactly equals the post-mutation `auth_list`.
- On `op = role`: no key deliveries; the OEK and its version stay unchanged.

Clients install OEKs only after the carrying `member.change` event passes full verification (§4.5).

### 4.5 Projection verification

Existing members verify each `member.change` with `op = add` or `op = remove` on receipt (`op = role` carries no projection; it only updates roles and keeps keys and the secret index):

```
1. Verify signature, prev_hash, author membership.
2. Decrypt enc_projection with the candidate OEK from key_deliveries.
3. For each SecretRecord r in body.secrets:
     local = client's secret_index[scope][r.id] → decrypt → record
     if local exists and local ≠ r: REJECT
     if local does not exist (re-sync race): force a pull, retry
4. For each id in client's secret_index[scope] not present in body.secrets:
     if the entry is not a tombstone: REJECT
5. On accept: install the OEK; replace member_set and secret_index.
   On reject: refuse, surface to user, await corrective member.change from another current member.
```

For `op = "remove"` with `member == self`: skip steps 2–4 (the body is undecryptable). Verify signature, prev_hash, op, target, and that `key_deliveries` excludes self. Then drop the scope locally (`STORAGE.md` §5.4).

A new member receiving `op = "add"` with `member == self` has no prior state to compare against and trusts the inviter's projection.

---

## 5. AEAD bindings

| Site                                | Key                       | AAD                                                    |
| ----------------------------------- | ------------------------- | ------------------------------------------------------ |
| Scope event `enc_body` / `enc_projection` | OEK[oek_version]    | `cbor(SignedPrefix without payload.{enc_body,enc_projection})` |
| Auth-method `encrypted_super_priv`  | K_unlock                  | `"fd0-encrypted-super-priv-v1" \|\| user_super_pub \|\| method_id` |
| Vault body                          | payload_key (random)      | `"fd0-vault-body-v1" \|\| cbor(VaultFile without body)` |
| Vault wrapped payload key           | unlock_key                | `"fd0-vault-wrap-v1" \|\| user_super_pub \|\| cbor(WrappedKey without wrapped)` |
| Recovery export                     | K_recovery (Argon2id)     | `"fd0-recovery-key-v1" \|\| user_super_pub`            |

All AEAD nonces are 12 random bytes from a CSPRNG.

---

## 6. Vault and recovery files

### 6.1 Vault file format

```
VaultFile = {
    magic                : "FD0V",
    version              : uint .size 1,             ; = 1
    user_super_pub       : bstr .size 32,
    wrapped_payload_keys : [+ WrappedKey],
    body_nonce           : bstr .size 12,
    body                 : bstr,                     ; AEAD ciphertext
}

WrappedKey = {
    method_id       : tstr,                          ; matches an active AuthMethod's method_id
    method_type     : "passphrase" / "yubikey",
    public_params   : bstr,                          ; same shape as auth.set public_params
    wrap_nonce      : bstr .size 12,
    wrapped         : bstr,                          ; AEAD ciphertext
}

VaultBody (plaintext, CBOR) = {
    ? ssh_grants : [* SSHGrant],                      ; personal installation approvals
    super_priv : bstr .size 64,
    auth_tip   : { seq: uint, hash: bstr .size 32 },
    scopes : { * tstr => {
        oeks       : [+ { version: uint, key: bstr .size 32 }],
        chain_tip  : { seq: uint, hash: bstr .size 32 },
    } },
    pinned_identities : { * tstr => {
        super_pub : bstr .size 32,
        label     : tstr,
    } },
}
```

`SSHGrant` is an optional local extension (not a scope event). Its fields are
`id`, `device_id`, `scope_id`, `name`, `host_id`, `key_id` (text), `host_json`
(JSON bytes of the approved connection settings without tags/description),
`key_public` (SSH public-key wire bytes), and `host_keys` (an array of SSH public-key
wire bytes). It stores no private keys. Agent-owned grant operations require fresh
credential validation and the digest of the exact reviewed grant for creation.
Ordinary re-sealing preserves the agent's current grant list. See `STORAGE.md`
for installation identity and `THREATS.md` for the SSH authorization boundary.

`auth_tip` and per-scope `chain_tip` record the latest event the client has accepted on each chain. On open, the client compares them to the chain-file heads. Three outcomes:

- Match: trust the chain file as committed state.
- File ahead: replay the suffix from `vault.tip+1` with full verification (§4.5); on success, advance the vault tip and re-seal.
- File behind: local rollback; refuse to operate; require re-sync.

Coordinated rollback of vault and chain files together is acknowledged as out of scope (`THREATS.md`).

`WrappedKey.method_id` MUST refer to a currently-active `AuthMethod` in the latest `auth.set`. On every sync, wraps whose `method_id` is no longer active are pruned and the vault re-sealed.

Typical vault size: ≤ 4 KB for ten scopes.

### 6.2 Vault unwrap and re-seal

Unwrap:

```
1. Read header: magic, version, user_super_pub, wrapped_payload_keys, body_nonce.
2. Find a WrappedKey whose method_type is available on this device.
3. Compute unlock_key (same derivation as K_unlock in §3.1).
4. payload_key = AEAD-decrypt(
       key   = unlock_key,
       nonce = wrap_nonce,
       ct    = wrapped,
       aad   = "fd0-vault-wrap-v1" || user_super_pub || cbor(WrappedKey without wrapped),
   )
5. content = AEAD-decrypt(
       key   = payload_key,
       nonce = body_nonce,
       ct    = body,
       aad   = "fd0-vault-body-v1" || cbor(VaultFile without body),
   )
```

Re-seal:

```
1. payload_key = random(32);  body_nonce = random(12)
2. body = AEAD(payload_key, body_nonce, cbor(content), aad = "fd0-vault-body-v1" || ...)
3. For each authorized WrappedKey w:
     wrap_nonce_w = random(12)
     wrapped_w    = AEAD(unlock_key_w, wrap_nonce_w, payload_key,
                          aad = "fd0-vault-wrap-v1" || user_super_pub || cbor(w without wrapped))
4. Write VaultFile to vault.enc.tmp; fsync; rename to vault.enc; fsync parent dir.
5. Zeroize payload_key and content from memory.
```

A fresh `payload_key` is generated on every path that re-wraps for every auth method: `init`, `recovery import`, and any `auth add`/`auth rm` path that rebuilds every wrap. Routine body-only re-saves keep the cached `payload_key` stable. Rotating it per-save would require every auth method's `K_unlock`, which the agent does not hold for non-active methods.

Forward-secrecy bound: an attacker who recovers BOTH an old vault snapshot AND a K_unlock for any active wrap can decrypt all subsequent body snapshots until the next credential rotation. Closing this gap without per-save user interaction (e.g. via a per-body DEK chain) is reserved for v2.

If a crash leaves the vault behind the latest chain event, the next open self-heals: `replay_chain` (`STORAGE.md` §4) verifies each event in full before installing any new OEK.

### 6.3 Recovery export

A user-initiated offline backup encrypted under a separate recovery passphrase. Version 2 preserves the signed user authentication chain and encrypted vault bootstrap in addition to `super_priv`; version 1 remains importable for compatibility.

```
RecoveryFileV1 = {
    magic                : "FD0K",
    version              : uint .size 1,                 ; = 1
    user_super_pub       : bstr .size 32,
    salt                 : bstr .size 16,
    argon2_params        : { m: uint, t: uint, p: uint },
    nonce                : bstr .size 12,
    encrypted_super_priv : bstr,                         ; AEAD ciphertext
}

K_recovery = Argon2id(passphrase, salt, argon2_params)

encrypted_super_priv = AEAD(
    key   = K_recovery,
    nonce = nonce,
    plain = super_priv,                                  ; 64 B
    aad   = "fd0-recovery-key-v1" || user_super_pub,
)
```

Version 2 retains the v1 fields and adds:

```
RecoveryFileV2 = RecoveryFileV1(version = 2) + {
    payload_nonce     : bstr .size 12,
    encrypted_payload : bstr,
}

RecoveryPayloadV2 = {
    user_chain : bstr,  ; byte-identical signed user.cbor
    vault      : bstr,  ; byte-identical encrypted vault.enc
}

encrypted_payload = AEAD(
    key   = K_recovery,
    nonce = payload_nonce,
    plain = cbor(RecoveryPayloadV2),
    aad   = "fd0-recovery-bundle-v2" || user_super_pub || nonce || encrypted_super_priv,
)
```

Restore v2: authenticate and decrypt both ciphertexts; verify `Ed25519_pub(super_priv) == user_super_pub`; replay the complete user chain; require its active methods to match the vault's wrapped payload keys; then install the two native files with no-overwrite commits, removing the first if the second commit fails. The methods present at export therefore remain usable, including YubiKey methods. An auth method added after the export is not present; Desktop records the exported auth tip and asks for a fresh export after the auth chain changes.

Restore v1: decrypt and verify `super_priv`, then bootstrap a fresh vault with one new local passphrase method as before.

The recovery file is never sent to the server. Export freshness is local Desktop metadata, not server or protocol state.

---

## 7. Replay and concurrency

### 7.1 Optimistic CAS

A scope-event push is rejected with `409 divergence` if `prev_hash ≠ scope.tip_hash`. The response includes the current tip. The client pulls, applies, re-encrypts the body under the new OEK if `oek_version_max` changed, updates `prev_hash`, re-signs, and retries. Auto-retry up to N (default 3) before surfacing.

Sync work is paged and aggregate-bounded. One request carries at most 64 push
items and 256 pull scopes. A pull response carries at most 1024 events and
48 MiB of encoded event bytes. Membership and public witness chain discovery
use ordered cursors; clients continue until the server omits the next cursor.
Clients may reduce push batch size after a rate-limit response.

### 7.2 Stored-event de-duplication

`event_id` is content-derived. Server enforces `UNIQUE(event_id)`; duplicates rejected with `409 dup`.

### 7.3 HTTP request replay

Per-request `(pk, nonce, ts)` window of 300 s; nonces cached for 600 s. The signed input includes the canonical query string. See `API.md` §1.

### 7.4 Identity-chain replay

The user identity chain is hash-linked. A device with a local copy detects any server attempt to omit or reorder events. First-fetch on a brand-new device trusts the server's response; the user-ceremony mitigation is out-of-band cross-device chain-tip comparison.

### 7.5 Cursor advancement

A client MUST only advance its `cursor: {seq, hash}` for a chain after verifying contiguous events from the prior cursor. Gapped or metadata-only responses MUST NOT advance the cursor.

---

## 8. Conformance

Implementations MUST:

- Use the exact domain separators in §1.1.
- Use libsodium-compatible primitives.
- Encode signed and hashed objects with deterministic CBOR (RFC 8949 §4.2.1).
- Verify every signature, AAD binding, and hash-chain link before accepting any event.
- Enforce per-kind constraints in §3 and §4 server-side.

Implementations MUST NOT:

- Mutate or delete events server-side.
- Accept ciphertext under one AAD domain at another site.
- Derive X25519 from Ed25519 by any path other than §1.2.
- Garbage-collect events client-side based on protocol metadata alone. GC is permitted only after the event has been stored, decrypted, and applied to the local index.

Future versions preserve compatibility with v1 events at rest.
