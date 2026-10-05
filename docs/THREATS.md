# fd0 Threat Model (v1)

Companion to `PROTOCOL.md`, `STORAGE.md`, `TRANSLOG.md`, `API.md`.

This document is the canonical inventory of threats fd0 reasons about.
It is **not** an inventory of every protocol property — those live in
`PROTOCOL.md` §1 and `TRANSLOG.md` §1. It is the inventory of
**adversary capabilities**, **trust boundaries**, **specific threats**
under those capabilities, and **the mitigation each threat receives**
(structural / runtime / ceremony / acknowledged-limit / out-of-scope).

Every threat has a stable identifier (`T01`–`T54`). Source code that
implements a mitigation carries a `// THREAT: Txx` annotation
referencing the catalogue below — `grep -rn '// THREAT:' --include='*.go'`
walks the doc-↔-code link in either direction. The
`tools/threat-coverage` linter (run via `make lint`) enforces that
every catalogued non-📋/⛔ threat has at least one Go annotation and
every annotation references a known T-ID.

## Contents

1. [Adversary model](#1-adversary-model) — six attacker classes.
2. [Trust boundaries](#2-trust-boundaries) — six boundaries crossed.
3. [Threats](#3-threats) — T01 to T54, grouped by plane:
   3.1 identity/unlock · 3.2 crypto primitives · 3.3 storage ·
   3.4 wire/replay · 3.5 membership · 3.6 translog/equivocation ·
   3.7 server boundary · 3.8 operational/metadata.
4. [Coverage matrix](#4-coverage-matrix-one-line-per-threat) — one
   line per threat: status, code reference, spec section.
5. [Acknowledged limits](#5-acknowledged-limits-consolidated) —
   what v1 does not promise.
6. [User-ceremony properties](#6-user-ceremony-properties) — hold
   only if the user does the right thing.
7. [Out of scope](#7-out-of-scope-explicit-non-goals) — explicit
   non-goals (distinct from §5 acknowledged limits).
8. [Maintenance](#8-maintenance) — how to keep this doc and the
   code annotations in sync.

**§5 vs §7 boundary.** §5 lists *acknowledged limits*: real threats
in scope of the adversary model where v1's mitigation reduces to a
ceremony, a documented gap, or "best effort". §7 lists *explicit
non-goals*: classes of attack we never intended to defend against
(kernel bugs, supply-chain, TLS PKI). The matrix in §4 marks both as
📋 (acknowledged) and ⛔ (out of scope) respectively.

---

## 1. Adversary model

Six attacker classes. Threats below are tagged with which class(es)
they apply to.

| ID  | Attacker                          | Capabilities                                                                                                                                                  |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | **Hosted-server operator**        | Full read/write on the server's database + code. Can rewrite history, equivocate, omit events, return forged proofs, run any handler. Cannot forge identities (no super_priv). |
| A2  | **Network attacker (active)**     | TLS-MITM during transport, DNS poisoning, ability to drop / reorder / replay packets. Cannot forge TLS certs (assumes a working PKI / cert-pinning).          |
| A3  | **Same-machine local attacker**   | Same UID / process namespace. Can read mlock'd memory in some configs, can plant symlinks in the home dir, can race fs operations. Stops at root / kernel-bug. |
| A4  | **Compromised member**            | Holds a valid `super_priv` that is currently in a scope's MemberSet. Can produce signed events, can withhold OEKs, can author projection-poisoned events.   |
| A5  | **Witness operator (malicious)**  | Runs an `fd0-witness` instance the user has pinned. Can refuse to cosign, return forged STHs, equivocate on what they observed. Cannot forge the server's signature. |
| A6  | **Coerced / lost-credential**     | A user who lost a credential (passphrase, hardware token) or who is being coerced. Includes "device theft" scenarios.                                         |

Each attacker is strictly weaker than its predecessor for the guarantees fd0 enforces — except A4 (members are by definition trusted event authors) and A5 (witnesses are passive observers, not protocol participants).

---

## 2. Trust boundaries

| ID    | Boundary                          | Crosses                                                                                |
| ----- | --------------------------------- | -------------------------------------------------------------------------------------- |
| TB1   | **User → Vault**                  | Passphrase / hardware-token credential becomes K_unlock then payload key.            |
| TB2   | **Agent → CLI process**           | super_priv stays mlocked in agent. CLI requests `Sign` over IPC; never sees raw priv. |
| TB3   | **Client ↔ Server (HTTP)**        | Signed requests + sealed bodies cross network. Server is A1; cannot decrypt.         |
| TB4   | **Server → Translog → Witness**   | Server publishes signed STHs; witnesses cosign. Witness is A5; sees only STHs.       |
| TB5   | **Filesystem → Process memory**   | Vault file + chain files on disk. Same-UID adversary (A3) crosses here.              |
| TB6   | **Member → Member (in-scope)**    | One member trusts other members for projection contents on join. Members are A4.     |

---

## 3. Threats

Status legend:

- 🟢 **Structural**: impossible at the type level (e.g. T15, T25 — unconstructable types) OR impossible unless a primitive breaks (e.g. T20 — would require forging Ed25519). A runtime guard that is "hard to forget" is 🛡️, not 🟢.
- 🛡️ **Runtime**: explicit guard or check at runtime, surfaces a controlled error. Failure mode is a missing check — forgettable on refactor, lint-protectable. Examples: nonce DB UNIQUE insert (T22), validator branches (T26, T30), `O_NOFOLLOW` (T18).
- 🤝 **Ceremony**: depends on user behaviour, e.g. comparing safety numbers or choosing a strong passphrase.
- 📋 **Acknowledged**: outside what v1 promises; documented as a non-goal.
- ⛔ **Out of scope**: explicitly not addressed (kernel bugs, etc.).

### 3.1 Identity / unlock plane (TB1, TB2, TB5)

#### T01 — Server fabricates `auth.set` events to install a malicious credential
- **Adversary**: A1.
- **Threat**: server returns a forged user chain that contains an
  `auth.set` whose `EncryptedSuperPriv` is an attacker-known wrap.
- **Mitigation** 🟢: every `auth.set` carries an Ed25519 signature by
  the user's `super_priv`. The server doesn't hold `super_priv`, so
  cannot produce a valid signature. **Code**: `chain/user.go`
  `ReplayUser` ⇒ `crypto.VerifyBytes` of every event.
- **Spec ref**: `PROTOCOL.md` §3.

#### T02 — Stolen vault file → offline brute-force passphrase
- **Adversary**: A3, A1 (if user pulled from a server that holds
  cipher-vault for backup — current v1 does not, but a future "vault
  sync" feature would expose this).
- **Mitigation** 🤝 + 🛡️: K_unlock is Argon2id with M=64 MiB / T=3 / P=1
  (`crypto.DefaultArgon2`). User-ceremony: strong passphrase (CLI
  shows a strength estimate but does not enforce a minimum).
- **Code**: `vault/resolver.go` PassphraseResolver, `crypto.DeriveKey`.
- **Spec ref**: `PROTOCOL.md` §6.1.
#### T03 — Coerced unlock
- **Adversary**: A6.
- **Mitigation** 📋: out of cryptographic scope. Threat is
  acknowledged in the original `THREATS.md` §3.

#### T04 — Server rolls back the user chain to expose a revoked credential
- **Adversary**: A1.
- **Threat**: user removes a compromised `AuthMethod`, server still
  serves an older `auth.set` that contains it; a fresh device fetches
  `?latest=true` and unlocks with the revoked credential.
- **Mitigation** 🛡️ + 🤝: vault binds `AuthTip(seq, hash)` (`PROTOCOL.md`
  §6.1). On every open, `chain.CompareUserTip` rejects when the file's
  tip lags the vault. **First-fetch case** (fresh device, no vault
  yet) is acknowledged: cross-device tip comparison out of band is
  the user-ceremony fallback.
- **Code**: `chain/tipbind.go` `CompareUserTip`,
  `cli/session.go` open path.

#### T05 — Single-file local rollback (vault OR chain replaced alone)
- **Adversary**: A3.
- **Mitigation** 🟢: vault `AuthTip` and `ScopeVaultData.ChainTip` bind
  the chain file's expected tip. A chain file alone (without the
  matching vault update) fails `CompareScopeTip`.
- **Code**: `chain/tipbind.go`. **Spec**: `PROTOCOL.md` §6.1.

#### T06 — Coordinated local rollback (vault + chain replaced together)
- **Adversary**: A3.
- **Mitigation** 📋: not covered. The vault-↔-chain hash binding
  catches one-of-the-two; replacing both in lockstep is a clean
  rollback. Operational mitigation: filesystem permissions
  (0700 home), full-disk encryption.
- **Spec ref**: this document, §5.

#### T07 — Same-UID malware reads agent process memory
- **Adversary**: A3 (with same-UID exec).
- **Mitigation** 🛡️: `mlock` on super_priv buffer (memguard);
  zeroization (`crypto.Wipe` with `runtime.KeepAlive` safeguard);
  agent runs as a separate process so CLI memory never holds the
  raw priv. Lifecycle deadlines are checked before every IPC
  operation. Status and rejected requests cannot extend idle time;
  max-lifetime cannot be extended by activity.
- **Code**: `internal/agent/server.go` mlocked buffers,
  `internal/crypto/wipe.go`, `internal/crypto/keys.go`
  `Ed25519Priv.Wipe`.
- **Spec ref**: `PROTOCOL.md` §1.1, §6.

#### T08 — Recovery-file theft
- **Adversary**: A3 + offline brute-force.
- **Mitigation** 🤝: `RecoveryFile` key material is AEAD-sealed under
  K_recovery (Argon2id over a separate recovery passphrase). Version 2 seals
  the signed user chain and already-encrypted vault as a second domain-bound
  AEAD payload. Strength of protection reduces to the user's recovery
  passphrase choice; the bundle is never sent to the server.
- **Spec ref**: `PROTOCOL.md` §6.3.

### 3.2 Cryptographic primitives plane

#### T09 — `ed25519.Sign` panics on wrong-size priv
- **Adversary**: A4 / data-corruption.
- **Mitigation** 🟢: `crypto.Ed25519Priv` is opaque; only
  `ParseEd25519Priv` (validates length AND seed/public-half
  consistency) and `GenerateIdentity` (correct by construction)
  produce a non-zero value. `crypto.Sign` rejects zero-value via
  `errSignBadKey`. Untyped byte boundaries use `crypto.SignBytes`
  with explicit length-gate.
- **Code**: `crypto/keys.go`, `crypto/crypto.go` Sign / SignBytes.
- **Tests**: typed key constructors and byte-boundary signing tests.

#### T10 — `ed25519.Verify` accepts wrong-size pub silently
- **Adversary**: A1, A4.
- **Mitigation** 🟢: `crypto.Verify(Ed25519Pub, ...)` requires the
  typed wrapper; zero-value fails closed. `crypto.VerifyBytes`
  parses-or-false at byte boundaries.
- **Code**: `crypto/crypto.go`.

#### T11 — Forged "valid-length" priv with mismatched seed/public half
- **Adversary**: A1 + corrupted/forged recovery file delivered to user.
- **Threat**: a 64-byte slice whose seed[:32] doesn't derive to
  public[32:] would wrap "successfully" in earlier C-3 design but
  produce signatures that fail every `Verify(.Public(), ...)` —
  silent signing failure.
- **Mitigation** 🟢: `ParseEd25519Priv` re-derives public half via
  `ed25519.NewKeyFromSeed`, constant-time-compares against the
  input's public half, rejects on mismatch. The temporary derived
  copy is wiped via `defer Wipe(derived)`.
- **Code**: `crypto/keys.go` ParseEd25519Priv.

#### T12 — Heap leak of priv bytes after Wipe
- **Adversary**: A3 (post-process-exit forensic).
- **Mitigation** 🛡️: `crypto.Wipe` carries `runtime.KeepAlive`; typed
  `Ed25519Priv.Wipe` delegates to it. Key generation takes ownership
  of `ed25519.GenerateKey`'s slices directly, avoiding a duplicate
  private-key copy. Recovery import calls `defer signerPriv.Wipe()`
  after the one-shot signer use.
- **Code**: `crypto/wipe.go`, `crypto/keys.go`,
  `cli/init.go`, `cli/recovery.go`.

#### T13 — Cross-protocol signature reuse
- **Adversary**: A1.
- **Threat**: a signature produced for one purpose (event
  authorship) is replayed in a different context (HTTP request
  auth, server-info self-sig, witness cosign).
- **Mitigation** 🟢: every signature input has a domain separator.
  See `internal/proto/domain.go` for the canonical list — the
  doc deliberately doesn't repeat the literals to avoid drift.
  Domain pairwise disjunction (no two are equal AND none is a
  prefix of another) is asserted by two tests:
  `proto.TestDomainSeparatorsDisjoint` in
  `internal/proto/proto_test.go` (basic equality + prefix check)
  and `proto.TestAdvDomainPrefixesDisjoint` in
  `internal/proto/adversarial_test.go` (harder property checks).
- **Code**: `internal/proto/domain.go`.

#### T14 — Cross-context AEAD ciphertext reuse
- **Adversary**: A1.
- **Mitigation** 🟢: every AEAD site has a distinct AAD domain prefix.
  Wrapping `super_priv` (`fd0-vault-wrap-v1`), vault body
  (`fd0-vault-body-v1`), scope event body (`fd0-event-v1`),
  scope projection (also `fd0-event-v1` with the prefix-of-prefix
  trick — see chain.encryptProjection AAD construction), recovery
  blob (`fd0-recovery-key-v1`).
- **Code**: `chain/build.go` encryptProjection, BodyAAD;
  `vault/vault.go` bodyAAD, `vault/resolver.go` EncryptSuperPriv.

### 3.3 Storage plane (TB5)

#### T15 — Path traversal via attacker-supplied scope_id
- **Adversary**: A1, A3 (corrupted local index).
- **Threat**: `s.Paths.ScopeChain(sid)` joins `sid + ".cbor"` into
  the chain dir; a hostile `sid = "../../etc/passwd"` would escape.
- **Mitigation** 🟢: `proto.ScopeID` is an opaque struct;
  `ParseScopeID` validates against `s_[a-z2-7]{26}` shape; direct
  cast is impossible. `fdhome.ScopeChain` re-validates as
  defence-in-depth.
- **Code**: `proto/scopeid.go`, `fdhome/fdhome.go`.

#### T16 — Silent truncate-rollback failure
- **Adversary**: A1 (server returns events that fail to replay).
- **Threat**: the older `_ = os.Truncate(path, preSize)` pattern
  swallowed errors; a half-extended chain file could survive a
  "rolled back" return.
- **Mitigation** 🟢: `chain.AppendTx.Cleanup` returns the truncate
  error; `defer tx.Cleanup()` makes rollback uniform across every
  early-return path. 200 random property-test seeds enforce
  invariants I1 (final size ∈ {preSize, preSize + Σ committed})
  and I2 (Cleanup is idempotent).
- **Code**: `chain/tx.go`, `chain/tx_test.go`, used in `cli/sync.go`.
- **Tests**: append transaction property tests cover rollback
  invariants.

#### T17 — Partial AppendRaw mid-batch leaves fsynced events
- **Adversary**: A1.
- **Mitigation** 🟢: AppendTx pattern — defer Cleanup truncates back
  to preSize on any error. Every event is fsynced, but the file
  size invariant guarantees readers see either pre-batch or
  post-commit, never partial.
- **Code**: `chain/tx.go`.

#### T18 — Symlink-redirect attack on chain file
- **Adversary**: A3.
- **Mitigation** 🛡️: `O_NOFOLLOW` on every chain-file open
  (`appendBytes` and `chain.WriteAll`). Same flag on vault file
  open and tmp-file rename. Defence-in-depth on top of
  "trusted home dir, mode 0700".
- **Code**: `chain/file.go` appendBytes, `vault/vault.go` Save.

#### T19 — Omitted events in local scope history
- **Adversary**: A3.
- **Mitigation** 🟢: v1 replay requires a contiguous sequence and
  `prev_hash` chain. A retained real final event cannot hide an omitted
  current secret. Sync also cross-checks the local final event against the
  vault-bound tip. `fd0 sync` repairs files created by older compacting
  clients from the pinned server's transparency-verified full history,
  preserving local-only writes transactionally.
- **Code**: `chain.ValidateScopeContinuity`, `chain.ReplayScope`,
  `cli.repairNonContiguousScopes`; regression and isolated integration
  tests cover rejection and repair.

#### T20 — Bit-flipping of on-disk chain
- **Adversary**: A3.
- **Mitigation** 🟢: every event is signature-bound to its
  prev_hash; any byte flip in CBOR breaks the signature. Adversarial
  test `TestAdvReplayRejectsBitFlipInGenesisSig` exercises this.
- **Code**: `chain/scope.go` ReplayScope verify path; test in
  `chain/adversarial_test.go`.

### 3.4 Wire / replay plane (TB3)

#### T21 — Cross-server signature replay
- **Adversary**: A1 (operator of server-A) + user registered on
  server-B with the same identity.
- **Threat**: signed `/sync` request from server-A's HTTP log is
  replayed against server-B's `/sync`.
- **Mitigation** 🟢: `proto.HTTPSignedInput` includes the
  destination `server_pub`. Different `server_pub` ⇒ different
  signed input ⇒ replay verify-fails.
- **Code**: `proto/httpsig.go`, `cli/sync.go` `signedPOST`,
  `server/auth.go` verify path.
- **Test**: `proto/proto_test.go` `TestHTTPSignedInputServerPubBinding`.

#### T22 — Per-request HTTP replay (within a single server)
- **Adversary**: A2 (network).
- **Mitigation** 🛡️: per-request `(pk, nonce, ts)` tuple stored in
  `nonces` table with UNIQUE constraint. `ts` window enforced
  (currently ±300s).
- **Code**: `server/auth.go` verifyAuthHeader, `server/store/store.go`
  CheckAndInsertNonce.

#### T23 — Stored-event replay
- **Adversary**: A1.
- **Mitigation** 🟢: events are content-addressed via
  `event_id = "e_" + base32(SHA-256(prefix)[:16])` and the server
  has a UNIQUE constraint on event_id; same event_id submitted
  twice is rejected (or returns the first-write `dup` result for
  idempotent retry).
- **Code**: `proto/ids.go` EventID, `server/store/store.go` Append.

#### T24 — URL drift between sync ↔ witness ↔ pin lookup
- **Adversary**: A1 (presents subtly different URLs to different layers).
- **Threat**: `https://server` vs `https://server/` vs
  `HTTPS://Server` keying into different vault entries.
- **Mitigation** 🟢: `canon.URL` opaque newtype; only
  `canon.ParseURL` (lowercase scheme/host, strip trailing slash,
  drop query+fragment) produces a value. All API surfaces
  consume the typed value.
- **Code**: `canon/url.go`, all `cli/sync*.go` + `cli/witness_check.go`.

#### T25 — Verify result discarded; encode unverified STH
- **Adversary**: A1 (returns a forged STH the verify rejects but
  the persistence path re-extracts).
- **Threat**: a refactor splits `Verify(...)` and `Encode(...)`
  into unrelated functions; the encode runs against the raw
  `r.STH` while `verifiedSTH` from Verify is discarded.
- **Mitigation** 🟢: `cli.VerifiedSTH` is opaque + sealed (a
  composite literal `cli.VerifiedSTH{}` from any other package
  fails the seal sentinel runtime check). `EncodeSTH` only
  accepts `VerifiedSTH`. Byte slices are deep-copied on
  construction so post-verify mutation can't poison.
- **Code**: `cli/verified_sth.go`, `cli/translog.go` EncodeSTH.

### 3.5 Membership plane (TB6)

#### T26 — Forged member.change (unsigned author)
- **Adversary**: A1.
- **Mitigation** 🛡️: `validate.ScopeEvent` enforces `Author ==
  ev.Signature.SignerPubkey` AND signature verifies under that pub.
- **Code**: `server/validate/validate.go`, `chain/scope.go` replay.

#### T27 — Foreign-author event splice (non-member writes a secret)
- **Adversary**: A4 (a non-member splicing a signed event into a
  victim's local chain) or A1.
- **Mitigation** 🛡️: `chain.ReplayScope` enforces "author ∈
  current MemberSet" before applying. Adversarial test
  `TestAdvReplayRejectsForeignAuthor` pins this.
- **Code**: `chain/scope.go` per-event member check.

#### T28 — Insider key-delivery omission (recipient-bricking)
- **Adversary**: A4.
- **Threat**: a current member posts a `member.change` and
  delivers an unusable sealed-box to one recipient (corrupt
  ciphertext, garbage OEK, or an OEK that decrypts but is not
  the active key).
- **Mitigation** 📋: mitigated for the scope, NOT for the victim. The server validates the recipient set (every post-mutation member receives one delivery) but cannot validate sealed-box contents (the OEK inside).
  - The victim's `chain.ReplayScope` errors at the poisoned `member.change` and cannot advance past it. A later `member.change op="remove"` of the bad author does not rescue the victim — replay is stuck before reaching it.
  - The victim is bricked for that scope until out-of-band recovery: another current member captures the post-remove chain prefix and physically re-delivers the recovered OEK, or re-bootstraps via re-discovery plus a fresh `member.change op=add` carrying a clean OEK.
  - Other members (who got valid OEKs) continue normally; the scope is not lost.
- **Recovery limit**: a recovery subcommand is non-trivial — re-fetching from `cursor=0` still re-replays the poisoned event. The honest recovery path is either:
  - **Replay-skip**: an operator-authorised flag (e.g. `fd0 scope skip-key-delivery <scope> <seq>`) that lets `ReplayScope` skip our own key_delivery on a specific seq while still verifying signatures and projection content for that event. The next `member.change` addressed to us re-establishes OEK access. Preferred — no protocol change.
  - **Re-admit checkpoint**: after a fresh `member.change op="add"` of the victim by another member, the victim resumes from that checkpoint with a clean OEK and treats the bricked prefix as cryptographically inaccessible.
  Neither path restores events authored during the bricked era.

#### T29 — Insider projection-poisoning
- **Adversary**: A4.
- **Mitigation** 🟢 for existing members + 📋 for new joiners:
  existing members run "projection-content integrity check" on
  every member.change — the projection MUST equal their local
  `secret_index`. Adversarial test
  `TestMalMemberCannotInjectExtraSecretInProjection`. New members
  have no prior local state and trust the inviter (T34).
- **Code**: `chain/scope.go` applyMemberChange projection check.

#### T30 — No-op membership change as a poison vehicle
- **Adversary**: A4.
- **Threat**: a `member.change op="add"` for an already-member
  could be used to rotate the OEK without justification, possibly
  delivering a poisoned projection.
- **Mitigation** 🛡️: server-side and client-side reject
  `op="add"` on existing members and `op="remove"` on
  non-members; no-op member.changes are explicitly disallowed.
- **Code**: `server/validate/validate.go`, `chain/scope.go`.

#### T31 — OEK ring stale after failed local push
- **Adversary**: A4 (race) or A1.
- **Threat**: a failed local `member.change` push leaves a stale
  OEK at version v in the vault. When the authoritative
  server-chain replay later returns a different bytewise key at
  the same version, the stale entry must be overwritten —
  otherwise subsequent secret.sets get encrypted under the wrong
  key and peers silently fail to decrypt them.
- **Mitigation** 🟢: `cli.upsertOEK` *replaces* on version
  collision instead of appending. Documented invariant: vault.OEKs
  is authoritative for the most recent replay.
- **Code**: `cli/sync_internal.go` upsertOEK.

#### T32 — Server hides a `member.change op="remove"` of self
- **Adversary**: A1.
- **Mitigation** 📋: future events under the new OEK become
  unreadable (forward-secrecy on member churn), but the local
  subscription remains stale until manually pruned.

#### T33 — First-fetch projection trust on join
- **Adversary**: A4.
- **Mitigation** 🤝: a fresh member receiving an admit event has
  no prior local state to verify projection content against.
  Inviter trust is inherent.

#### T34 — Server can withhold scope discovery
- **Adversary**: A1.
- **Mitigation** 📋: `/sync?discover_memberships=true` runs
  server-side; a malicious server can return a stale or filtered
  list. A user who suspects withholding needs an out-of-band check
  with another authorized member or a server-side audit; there is no
  client command that can force discovery if the server hides the
  membership.

### 3.6 Translog / equivocation plane (TB4)

#### T35 — Server equivocation between two clients (different consistent histories)
- **Adversary**: A1.
- **Mitigation** 🛡️ + 🤝: STH cosign by ≥`min_cosigns` independent
  witnesses (configurable; recommended 2-of-3 or 3-of-3). The
  witness archive is keyed by `(server_url, chain_id,
  tree_size, root_hash)` — divergent roots at the same
  tree_size are intentionally **stored side-by-side** as
  evidence. The client's `CrossCheckSTH` queries witnesses for
  cosign at the server-supplied tree_size; if the witness has
  multi-roots at that size, the witness HTTP layer returns 409
  (`ErrEquivocationAtSize` ⇒ `errWitnessEquivocation` ⇒
  `ErrWitnessEquivocation`).
- **Chain-level cross-check (closed by C5)**: client now
  consults `GET /v1/equivocation/{server_b64}/{chain_id}` on
  every pinned witness BEFORE accepting any cosign. The
  endpoint returns true iff the witness has EVER archived
  multi-roots at any tree_size for the chain. Closes the
  historical-equivocation gap.
- **Witness identity binding**: a fresh production witness requires
  an explicit server public key obtained out of band. It checks the
  persisted pin before any network request and refuses first contact
  without an explicit pin. Self-signed first-contact TOFU is disabled
  by default and exposed only as an unsafe development option, so an
  attacker controlling the first connection cannot create an
  apparently independent witness for its own server identity.
- **Code**: `cli/witness_check.go` CrossCheckSTH +
  fetchEquivocationProbe, `witness/store.go` Insert +
  DetectEquivocationAt + DetectChainEquivocation,
  `witness/http.go` handleEquivocation,
  `witness.Witness.EnsurePins`.
- **Spec**: `TRANSLOG.md` §6.

#### T36 — Server returns wrong consistency proof (forks history)
- **Adversary**: A1.
- **Mitigation** 🟢: every `/sync` response that advances LastSTH
  carries a consistency proof from priorSTH → newSTH. Client
  verifies before persisting. Wrong proof ⇒ verify fails ⇒ no
  state advance.
- **Code**: `translog/proof.go` VerifyConsistency,
  `cli/translog.go` VerifyTranslogResponse.

#### T37 — Server returns inclusion proof for the wrong leaf
- **Adversary**: A1.
- **Threat**: server claims our seq=5 push landed but embedded a
  different event at that seq.
- **Mitigation** 🟢: `cli.leafHashAtSeq` reads the local chain
  file by seq and computes the expected leaf hash from local
  bytes. Inclusion proof must verify against THAT leaf, not
  whatever the server claims at seq=5.
- **Code**: `cli/sync_internal.go` leafHashAtSeq, `cli/sync.go`
  push-verify path, `cli/sync_reconcile.go` rebuilt-push path.

#### T38 — Witness collusion with server
- **Adversary**: A1 + A5(coordinated).
- **Mitigation** 📋 partially: N-of-M cosign threshold
  (`min_cosigns`) makes single-witness collusion ineffective.
  All-witness collusion is a config attack (the user pinned the
  wrong witnesses); mitigation is pin-diversity ceremony.

#### T39 — Bad-cosign / forged witness response
- **Adversary**: A5.
- **Mitigation** 🟢: every witness's pub is pinned in the user's
  config. `cli.fetchWitnessedSTH` verifies the cosign signature
  under the pinned pub. A wrong-pub or wrong-sig response is a
  miss; the threshold check still has to be satisfied by other
  honest witnesses. Adversarial test suite
  `tests/integration_witness_malicious.sh` (8 scenarios:
  fork-cosign, wrong-chain-id, wrong-server-url, size-drift,
  garbage-cbor, always-409, always-500, wrong-witness-pub).
- **Code**: `cli/witness_check.go`,
  `cmd/fd0-test-bad-witness/main.go`.

#### T40 — Witness archive holds same-size divergent roots → 409 on lookup
- **Adversary**: A1 (caught red-handed).
- **Mitigation** 🟢: the witness schema's UNIQUE key includes
  `root_hash`, so divergent same-size STHs are stored as
  separate rows by design — that IS the equivocation evidence,
  not a thing the witness suppresses. The client's `LookupAt`
  query returns HTTP 409 when ≥2 rows exist at the same
  (server_url, chain_id, tree_size). Client treats 409 as
  immediate evidence of equivocation and refuses to advance
  LastSTH.
- **Code**: `witness/store.go` Insert (intentional row-per-
  divergent-root) + LookupAt (multi-row → 409 caller-side),
  `cli/witness_check.go` errWitnessEquivocation handler.

#### T41 — First-fetch checkpoint rollback (no prior STH anchor)
- **Adversary**: A1.
- **Mitigation** 🛡️ + 🤝: client now consults
  `GET /v1/witness/highest/{server}/{chain}` on every pinned
  witness BEFORE accepting a cosign at the server-supplied
  tree_size N. If any witness has previously archived
  tree_size > N for this chain, refuse the cosign — server is
  rolling the client back. Closes the rollback-to-older-witnessed
  STH gap.
- **Residual user-ceremony**: still depends on at least one
  witness having seen the chain BEFORE the rollback. A
  truly-first-contact client (no witness has ever seen the
  chain either) falls back on cross-device out-of-band tip
  comparison.
- **Code**: `cli/witness_check.go` CrossCheckSTH +
  fetchHighestProbe, `witness/store.go` HighestTreeSize,
  `witness/http.go` handleHighest.
- **Spec**: `TRANSLOG.md` §6.1, §6.4.

#### T42 — STH for a different chain_id served as ours
- **Adversary**: A1, A5.
- **Mitigation** 🟢: the STH's signed prefix includes
  `chain_id`. `cli.VerifyTranslogResponse` requires
  `expectedChainID == sth.Head.ChainID` AND the witness cosign
  binding is also chain-id-keyed.

#### T43 — Equivocation across servers (split-brain by URL)
- **Adversary**: A1.
- **Mitigation** 🟢 (T24 also covers this): the STH cosign embeds
  the *canonical server URL*. Witnesses index their archive by
  `(server_url, chain_id, tree_size)`. Trying to present
  "server-A's chain at server-B's URL" is a wrong-server-url
  cosign that the client rejects.
- **Code**: `translog/witness.go` SignWitnessedSTH binds URL,
  `cli/witness_check.go` verify path.

### 3.7 Server boundary (TB3, server-internal)

#### T44 — Authenticate as someone else
- **Adversary**: A1, A2.
- **Mitigation** 🟢: every authenticated request carries an
  Ed25519 signature over `(server_pub, method, path, query, ts,
  nonce, body_hash)`. Server verifies under the claimed `pk` from
  the Authorization header. No pk → no auth → 401.
- **Code**: `server/auth.go` verifyAuthHeader.

#### T45 — User-registration replay (bind a stranger's identity)
- **Adversary**: A1, A2.
- **Mitigation** 🟢: `POST /users` requires the genesis user
  event itself (signature-bound to the user's super_priv).
  Server verifies before storing. Re-registration with the same
  pubkey returns 409 `super_pub_taken`.
- **Code**: `server/server.go` handleUsersRegister.

#### T46 — Server-info pubkey forgery
- **Adversary**: A1.
- **Threat**: server returns a forged `/v1/server-info` pinning
  an attacker pubkey.
- **Mitigation** 🟢 + 🤝: `server-info` is self-signed under the
  server's translog priv; client verifies sig before pinning.
  But on FIRST contact the client has nothing to verify against
  (TOFU) — fallback is the safety-number ceremony
  (`cli.ServerFingerprint`) that the user verifies out-of-band.
- **Code**: `server/server.go` ServerInfo handler,
  `translog/witness.go` VerifyServerInfo, `cli/translog.go`
  EnsurePinnedServer + pinningPrompt.

#### T47 — Auto-pin bypass without operator awareness
- **Adversary**: A1 + scripted unattended client.
- **Threat**: a CI script that accepts any pin would never
  detect a MITM during first-contact pinning.
- **Mitigation** 🛡️: `FD0_AUTO_PIN=1` must be explicitly set;
  default is to refuse non-TTY pinning. The fingerprint is
  always printed even when auto-pinning, so a follow-up review
  can detect a wrong pin.
- **Code**: `cli/translog.go` pinningPrompt.

#### T48 — Per-IP brute-force / DoS
- **Adversary**: A2.
- **Mitigation** 🛡️: token-bucket rate limiter, five buckets:
  - `AcquireAuthAttempt` (per-IP) — fires before body read and signature verify; covers every authenticated handler via `verifyHTTPSig`.
  - `AcquireRegister` (per-IP, low cap) — covers `handleRegister` only.
  - `AcquireProof` (per-IP, default 120/min) — covers public translog endpoints `handleSTH`, `handleInclusionProof`, `handleConsistencyProof`. These walk SQL per request and are not cached, so without a cap an attacker could drive non-trivial CPU + IO unauthenticated. The cap is generous: a legitimate client verifying many proofs in one pull stays under it.
  - `AcquireWrite` (per-pubkey, post-auth) — operations rate.
  - `AcquireBytes` (per-pubkey, post-auth) — bytes rate.
- **`handleServerInfo` is intentionally NOT rate-limited**. It returns a cached ~256-byte blob from memory; clients refetch it on every sync for pin-mismatch detection, so even a 5/hour cap would 429 legitimate users behind a NAT.
- **Code**: `server/auth.go`, `server/server.go`, `server/ratelimit/limiter.go`.

#### T49 — Witness archive storage growth
- **Adversary**: A1 (operationally). Not exploitable by an attacker.
- **Status**: 📋 acknowledged operational consideration.
- **Mitigation**: the witness has no inbound ingest endpoint — it polls upstream servers outbound on a schedule (`witness.Witness.poll`). Storage grows by at most one row per *distinct* `(server, chain, tree_size, root_hash)` tuple. In the honest case (server is monogamous), one row per `tree_size` advance. Same-size divergent roots are intentionally preserved as evidence (T35, T40). The poll loop bounds response read size, so a malicious upstream cannot OOM-crash the witness. Operational bound: the operator archives or GCs older STHs.
- **Code**: `witness/witness.go` (poll loop, bounded reads), `witness/store.go` Insert (per-distinct-root storage).

### 3.8 Operational / metadata

#### T50 — `shortId` enumeration → encrypted user chain → offline brute
- **Adversary**: A1 only.
- **Mitigation** 🤝 + 🛡️: `GET /users/{shortId}/events` requires
  authentication + signer-must-equal-chain-owner check
  (`server.handleFetchUser`), so a network attacker (A2) CANNOT
  enumerate `shortId`s and pull encrypted user chains. The
  threat is real ONLY for A1 (server operator with raw DB
  access), where protection reduces to passphrase strength.
  Short_id is by design discoverable — it's what you advertise
  on a card; the mitigation is that the encrypted user chain
  is not network-readable.
- **Code**: `server/server.go` handleFetchUser auth check.
- **Spec**: `PROTOCOL.md` §6.1, `API.md` §2.2.

#### T51 — Card-channel substitution
- **Adversary**: A2.
- **Mitigation** 🤝: safety-number ceremony — user compares the
  fingerprint of the imported card with the source's via an
  authentic out-of-band channel.
- **Code**: `cli/card.go` safety number renderer.

#### T52 — Metadata side channels
- **Adversary**: A1.
- **Mitigation** 📋: server learns scope membership graphs,
  online times, event sizes by design. Hiding metadata is not a
  v1 goal.

#### T53 — Server-storage growth is unbounded
- **Adversary**: not malicious — operational consequence.
- **Mitigation** 📋: server retains events forever (translog
  immutability is the property). Operator-bounded by quota /
  GC policy outside fd0.

#### T54 — Coerced or lost-credential recovery
- **Adversary**: A6.
- **Mitigation** 📋: identity rotation requires recovery export
  or full re-onboarding. Forward-secrecy of past data is not
  achievable given that removed members retain past OEKs.

---

## 4. Coverage matrix (one-line per threat)

Status: 🟢 structural · 🛡️ runtime guard · 🤝 user ceremony ·
📋 acknowledged limit · ⛔ out of scope. Full definitions in §3
opening paragraph.

| ID  | Status | Code reference                                   | Spec §          |
| --- | :----: | ------------------------------------------------ | --------------- |
| T01 | 🟢 | `chain/user.go`                                  | PROTOCOL §3     |
| T02 | 🤝🛡️ | `crypto.DeriveKey`                               | PROTOCOL §6.1   |
| T03 | 📋 | —                                                | THREATS §5      |
| T04 | 🛡️🤝 | `chain/tipbind.go`                               | PROTOCOL §6.1   |
| T05 | 🟢 | `chain/tipbind.go`                               | PROTOCOL §6.1   |
| T06 | 📋 | —                                                | —               |
| T07 | 🛡️ | `agent/server.go`, `crypto/wipe.go`              | PROTOCOL §1.1   |
| T08 | 🤝 | `cli/recovery.go`                                | PROTOCOL §6.3   |
| T09 | 🟢 | `crypto/keys.go` Ed25519Priv                     | —               |
| T10 | 🟢 | `crypto/keys.go` Ed25519Pub                      | —               |
| T11 | 🟢 | `crypto/keys.go` ParseEd25519Priv                | —               |
| T12 | 🛡️ | `crypto/wipe.go`, `crypto/keys.go` Wipe          | —               |
| T13 | 🟢 | `proto/domain.go`                                | PROTOCOL §1.1   |
| T14 | 🟢 | `chain/build.go` BodyAAD, `vault/vault.go`       | PROTOCOL §5     |
| T15 | 🟢 | `proto/scopeid.go`, `fdhome/fdhome.go`           | STORAGE §1.3    |
| T16 | 🟢 | `chain/tx.go` AppendTx                           | STORAGE §3      |
| T17 | 🟢 | `chain/tx.go`                                    | STORAGE §3      |
| T18 | 🛡️ | `chain/file.go` O_NOFOLLOW                       | —               |
| T19 | 📋 | —                                                | STORAGE §5.4    |
| T20 | 🟢 | `chain/scope.go` ReplayScope                     | PROTOCOL §4     |
| T21 | 🟢 | `proto/httpsig.go` server_pub binding            | PROTOCOL §7.1   |
| T22 | 🛡️ | `server/auth.go`, store CheckAndInsertNonce      | API §1          |
| T23 | 🟢 | `proto/ids.go` EventID                           | PROTOCOL §1.3   |
| T24 | 🟢 | `canon/url.go`, `cli/sync.go`                    | TRANSLOG §6.1   |
| T25 | 🟢 | `cli/verified_sth.go` (opaque + sealed)          | TRANSLOG §5     |
| T26 | 🛡️ | `server/validate/validate.go`                    | PROTOCOL §4     |
| T27 | 🛡️ | `chain/scope.go` member-set check                | PROTOCOL §4     |
| T28 | 📋 | `chain/scope.go` (replay error path)             | THREATS §5      |
| T29 | 🟢🤝 | `chain/scope.go` projection-content check        | PROTOCOL §4.4   |
| T30 | 🛡️ | `validate/validate.go`, `chain/scope.go`         | PROTOCOL §4.2   |
| T31 | 🟢 | `cli/sync_internal.go` upsertOEK                 | STORAGE §4.3    |
| T32 | 📋 | —                                                | THREATS §5      |
| T33 | 🤝 | —                                                | THREATS §5      |
| T34 | 📋 | —                                                | API §2.4        |
| T35 | 🛡️🤝 | `cli/witness_check.go`, `witness/store.go`        | TRANSLOG §6     |
| T36 | 🟢 | `translog/proof.go`, `cli/translog.go`           | TRANSLOG §5     |
| T37 | 🟢 | `cli/sync_internal.go` leafHashAtSeq             | TRANSLOG §5.4   |
| T38 | 📋 | —                                                | TRANSLOG §6     |
| T39 | 🟢 | `cli/witness_check.go`                           | TRANSLOG §6.3   |
| T40 | 🟢 | `witness/store.go` Insert UNIQUE                 | TRANSLOG §8.2   |
| T41 | 🛡️🤝 | `cli/witness_check.go` fetchHighestProbe       | TRANSLOG §6.1   |
| T42 | 🟢 | `cli/translog.go` VerifyTranslogResponse         | TRANSLOG §3     |
| T43 | 🟢 | `translog/witness.go` SignWitnessedSTH           | TRANSLOG §6.3   |
| T44 | 🟢 | `server/auth.go`                                 | API §1          |
| T45 | 🟢 | `server/server.go` handleUsersRegister           | API §2.1        |
| T46 | 🟢🤝 | `cli/translog.go` EnsurePinnedServer             | TRANSLOG §6.1   |
| T47 | 🛡️ | `cli/translog.go` pinningPrompt                  | TRANSLOG §6.1   |
| T48 | 🛡️ | `server/ratelimit/limiter.go`                    | API §1          |
| T49 | 📋 | `witness/witness.go` (no ingest endpoint exists) | TRANSLOG §8     |
| T50 | 🤝🛡️ | `server/server.go` handleFetchUser auth          | PROTOCOL §6.1   |
| T51 | 🤝 | `cli/card.go`                                    | PROTOCOL §2.3   |
| T52 | 📋 | —                                                | —               |
| T53 | 📋 | —                                                | —               |
| T54 | 📋 | —                                                | PROTOCOL §6.3   |

---

## 5. Acknowledged limits (consolidated)

What v1 explicitly does NOT promise:

- **Coerced user** (T03, T54).
- **Coordinated local rollback** (T06) — vault + chain restored in
  lockstep is indistinguishable from a legitimate older snapshot.
- **Insider key-delivery omission** (T28) — server can't validate
  sealed-box contents.
- **Server hides remove-self** (T32) — local subscription stays stale.
- **Server withholds scope discovery** (T34) — discovery is
  best-effort.
- **First-fetch projection trust on join** (T33) — inviter trust is
  inherent on a fresh device.
- **First-fetch checkpoint rollback** (T41) — no priorSTH to
  consistency-prove against; user-ceremony fallback (T46 + cross-
  device gossip).
- **No forward secrecy for already-fetched data** — removed members
  retain every OEK they had.
- **No per-event forward secrecy** — all events under one OEK era
  share the same key.
- **No post-compromise security** — identity compromise is terminal.
- **Local-machine compromise** (T07) — same-UID malware can read
  process memory; mlock + zeroize mitigate but do not eliminate.
- **Server availability** is not a security property.
- **Metadata side channels** (T52) — membership graph, online time,
  event sizes are visible to the server by design.
- **Server storage growth** (T53) — unbounded, operator-bounded.
---

## 6. User-ceremony properties

These hold ONLY if the user does the right thing. Each is flagged
🤝 in the threat catalogue.

- **Strong passphrase** (T02, T08, T50).
- **Recovery-passphrase strength** (T08, T54).
- **Custody of `shortId`** (T50).
- **Card safety-number verification** (T51).
- **Cross-device chain-tip comparison** (T04, T41).
- **Inviter trust on join** (T33).
- **Storage of recovery exports** (T08).
- **Server-fingerprint verification on first pin** (T46, T47).

---

## 7. Out of scope (explicit non-goals)

- OS-level defense in depth.
- Hardware-token compromise scenarios beyond "key extraction is hard".
- Side channels in the underlying primitives (timing on
  AES / Ed25519 / Argon2id stdlib implementations).
- Supply-chain attacks against fd0 binaries.
- TLS / PKI failures at the transport layer.

---

## 8. Maintenance

When code changes, the THREAT annotation must move with it. To find
all annotations:

```sh
grep -rn '// THREAT: T' --include='*.go'
```

When adding a new security-critical function, add a `// THREAT: TXX`
comment referencing the relevant entry. When adding a new threat,
extend §3 + §4 here, then go annotate the corresponding code site.

A future spec-compliance generator could parse this doc and fail CI
when a Tnn entry has no matching `// THREAT:` annotation in non-test
code.


## SSH grants while the vault is locked

SSH grants are an explicit exception to the default empty SSH identity list while
locked. Saved approvals live in the encrypted local vault and apply to one
installation ID. After restart, the first unlock resolves their current host and
key records. Only the selected private SSH keys survive subsequent vault locks,
in protected memory; identity, payload and scope keys follow the normal lock
lifecycle. `fd0 lock --all` clears active SSH keys too. Existing SSH sessions and
multiplexed connections are outside the agent's authentication boundary.

The supported grant operation always validates freshly supplied credentials
against the canonical vault and active authentication methods. It binds the
approval to a digest of the device, record identities, connection settings,
client public key and already-trusted server host keys. Generic vault re-sealing
cannot modify approvals. This is a workflow boundary, not a defense against
arbitrary same-UID code: existing recovery/export and identity APIs retain their
normal trust model. A terminal or passphrase prompt alone does not prove human
presence. YubiKey touch requirements depend on enrollment policy.

Locked signing requires a verified `session-bind@openssh.com` proof and a matching
`publickey-hostbound-v00@openssh.com` user-authentication payload, including the
session ID, destination host key, username and client key. Unbound or forwarded
connections, arbitrary signing and unsupported clients are refused. Hosts that
share a server host key share that cryptographic identity; hostname and port are
configuration checks, not independent server identities. CA-only trust is not
accepted. ProxyJump hops require separate explicit approvals.

Grant activation reads scope chains without repairing partial tails. Vault
commits revalidate grants, so changed targets, replaced/deleted keys and observed
membership removal stop affected grants. Offline agents cannot observe remote
revocation until synchronization. Local grant revocation does not remove a
public key from a remote server's authorized_keys file.

## Scope roles

Scope members are `admin`, `writer` or `reader` (docs/SCOPE_ROLES_PLAN.md).
Every member still receives the scope's OEKs, so roles restrict what a member
can sign into the chain, not what it can read or disclose. A compromised reader
can read and leak every value in its scopes but cannot sign value or membership
changes. A compromised writer can also alter or delete values and the scope's
name and organization tags, which are ordinary records, and like any member it
can submit events other clients cannot decrypt (T28). Admins are unchanged.

The server validator and client replay share one authorization function, and
replay rejects forbidden events even before the replaying client's own
admission, so a misbehaving server cannot make clients accept them. Clients
also refuse to sign events their own role does not allow. Only admins sign
membership changes: readers and writers leave by hiding the scope locally and
asking an admin to remove them, because the leaving member would otherwise
author the next OEK deliveries and projection for everyone else.

Older clients and servers drop the unknown `role` field when re-encoding a
signed prefix, so signatures fail and they reject role events rather than
ignore roles. An older server started on a database that already holds roles
would forget them; from store generation 2 on, servers refuse databases of a
newer generation, and downgrading after roles are used is unsupported.


## Deploy recipes

A deploy recipe (docs/SERVICES_PLAN.md, phase 3) is a command stored in a
scope that a device runs with selected service values on stdin or in its
environment. Every writer of the scope can create or change recipes, so a
recipe is code from another member. The boundary is the per-device approval:
the agent records it only after fresh authentication in a terminal, binds it
to the device ID, and pins a digest of the scope, the recipe name and every
part of the definition that affects what runs or what it receives (program
and arguments, working directory, field selection with variable names or
Secret keys, input format, targets) plus the device's home directory. Any
change makes `fd0 service deploy` refuse until the device approves again;
value rotations do not. Recipes never run on sync, unlock or rotation,
approval is not available through organization grants, and approval grants
no locked access.

An approved recipe runs as the user with that user's files, SSH agent and
unlocked vault. Approval does not sandbox it and does not cover scripts,
tools or configuration it calls (`kubectl` contexts, SSH aliases): those
remain the operator's trust. fd0 never puts values into arguments, sets its
own `FD0_*` variables last and refuses them as value names, discards command
output unless `--verbose`, and re-checks the approval before every launch so a
revocation or lock stops what has not started. After an interrupt fd0 tries,
within a bounded window, to record the result of the target that was running. Deploy results are ordinary
scope records written by the deploying device and contain no values. They
are reports from a scope writer, not authenticated device attestations, and a
successful command does not prove an application uses a value. Two devices
deploying at the same time can race; one deploying device per target, or a
destination that rejects stale writes, avoids that. An older agent that does
not know recipe approvals drops them when it rewrites the vault; deploys then
refuse until the recipe is approved again.

## Secret grants

A secret grant (docs/SECRET_GRANTS_PLAN.md) keeps one value readable on one
device while the vault is locked, for unattended consumers that run as the
same OS user. While a grant is active, every process of that user can read
the value through the agent socket; that is the documented trade against
keeping the whole vault unlocked or copying the value into a file. Grants
are created only with fresh authentication in a terminal, bound to the
device and pinned to the record ID, field and field type; a deleted,
renamed or retyped value removes the grant, and a recreated one needs a new
grant. Locked reads release exactly one granted value for an exact name and
scope and nothing else. `fd0 lock --all` stops all grants until the next
unlock. Values may briefly exist in ordinary memory while scopes are
replayed; the released copy is held in protected memory.
