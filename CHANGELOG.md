# Changelog

Each component has its own version namespace from `client-v0.0.5`
onwards:

- `client-vX.Y.Z` — `fd0`, `fd0-agent` binaries (goreleaser tarball)
- `server-vX.Y.Z` — `fd0-server` Docker image
- `witness-vX.Y.Z` — `fd0-witness` Docker image
- `website-vX.Y.Z` — `fd0-website` Docker image

Coordinated wire-protocol bumps use `fd0-vX.Y.Z` which tags all four
components at the same commit. Image tags published to ghcr.io drop the
component prefix, so compose files keep pulling `:0.0.5` and `:latest`
as before.

Tags before `client-v0.0.5` used the unified `vX.Y.Z` scheme (one
release shipped all artefacts together) and are retained as-is.

From 0.20.0, the CLI and fd0 Desktop share one version number: every
client release tags `client-vX.Y.Z` and `desktop-vX.Y.Z` on the same
commit, even when only one of them changed. The CLI bundled with Desktop
prints `fd0 X.Y.Z <flavor> (desktop)` because Desktop updates it.
Server, witness and website keep their own numbers.

## client-v0.6.0 — 2026-06-25

Single-primary write model (A1). The client now writes and reads exactly
one primary server per scope, so two independent servers can never
disagree about a scope's history. Multi-push is removed: it could leave
replicas divergent, and any auto-merge would discard a conflicting write.

- **BREAKING (config):** the `[sync].servers = [...]` array is replaced by
  the singular `[sync].server = "https://…"`. A config still using the
  array is a hard error with a migration message. The built-in default is
  a single `https://api.fd0.sh`.
- Removed the cross-replica read-failover (a possibly-stale replica must
  never serve a read) and the `[sync].mode = "primary"` option.
- Redundancy is now a server-side DR backup (`FD0_REPLICATE_FROM`), not a
  second write target — see `docs/REPLICATION.md`.
- The interactive lock waits briefly by default instead of failing fast,
  so a command no longer errors "another fd0 instance holds the lock"
  while the agent's auto-sync is mid-run; divergence output is summarized
  rather than printed once per refused push.

`fd0-website` → `0.0.12` brings the site and docs in line with the model.
Servers are unchanged: `fd0-server` stays on `server-v0.2.0`, and its
DR-backup machinery (shipped in `server-v0.2.0`) is retained.

## fd0-v0.1.0 — 2026-06-08

Coordinated bump of all four components to 0.1.0. Consolidates every
piece of the multi-server work and gives the project a clean
"replicas-are-real" milestone version.

Component versions rolled into this release:

- `fd0-server`  — was `0.0.5`, now `0.1.0`
- `fd0-witness` — was `0.0.5`, now `0.1.0`
- `fd0-website` — was `0.0.6`, now `0.1.0`
- `fd0` / `fd0-agent` — was `0.0.5`, now `0.1.0`

CI / release pipeline:

- arm64 Docker builds now use native `ubuntu-24.04-arm` runners
  instead of qemu emulation. Removes the docker-hub timeout failure
  class observed in earlier releases; arm64 build time roughly halved.

No wire-protocol changes vs `v0.0.5`. The transparency-log signature
inputs, vault on-disk format, and HTTP API are unchanged. Existing
clients on `client-v0.0.5` keep working against servers on
`server-v0.1.0` and vice versa.

## website-v0.0.6 — 2026-06-08

- Architecture diagram: add replica box, headings left-aligned with
  their box, caption centered
- Self-host landing column rewritten around Docker compose
- `/install` redirect added (short curl URL)

## server-v0.0.5, client-v0.0.5 — 2026-06-08

(Originally shipped as `v0.0.5`. Promoted into the scoped scheme.)

- Per-server `PushFloor` and `LastSTH` in `ScopeVaultData.PerServer`.
  Fixes the v0.0.4 bug where the second entry in `[sync].servers`
  silently received zero events.

## fd0-v0.0.4 — 2026-06-07

(Originally shipped as `v0.0.4`. Coordinated wire-protocol bump.)

- `FD0_LABEL` and `FD0_PEERS` on `fd0-server`
- TOFU-pinned peer resolver in SQLite, runs every hour
- `/v1/server-info` embeds signed `label` + `peers` (omitempty)
- Client `[sync].servers = [...]` multi-server array
- Defaults: `https://api.fd0.sh` + `https://api2.fd0.sh`
- Client multi-pushes every event to every configured server
- `docs/TRANSLOG.md` §11 (peer hints trust model)

## v1.0.0 — Initial release

First public release. Wire protocol, on-disk formats, and HTTP API
are frozen at this version. Future versions preserve compatibility
with v1 events at rest (`docs/PROTOCOL.md` §8 conformance).

### Identity, vault, and unlock

- Ed25519 identity (`super_keypair`) with X25519 ECDH derived for
  sealed-box recipients.
- Per-device encrypted vault (AES-256-GCM) holding `super_priv`,
  per-scope OEKs, chain-tip bindings, and pinned identities.
- Argon2id passphrase unlock with parameter validation; non-default
  parameters survive boot via the vault wrap header.
- YubiKey-PIV unlock (build tag `yubikey`, firmware ≥ 5.7, X25519
  slot 9d). `auth add --yubikey [--touch=...] [--force]`,
  `unlock --method=yubikey|passphrase`, `FD0_YUBIKEY_CARD` env
  override for multi-reader systems.
- Recovery export/import (`fd0 recovery`) under a separate
  passphrase, Argon2id-derived.
- Identity cards (`fd0://card/...`) with safety-number ceremony for
  out-of-band verification.

### Multi-member scopes

- Per-scope event chain with `member.change` and `secret.set` event
  kinds.
- Per-member sealed-box OEK delivery; OEK rotates on every
  `member.change`.
- Projection verification on every `member.change`: existing
  members assert the inviter's claimed projection equals their
  local index.
- Tombstones for deleted secrets; per-secret stable IDs (ULID).

### Server + sync

- HTTP API + SQLite. Stateless per-request authentication via
  Ed25519-signed headers (`fd0-http-request-v1` domain) bound to
  the destination server's translog pubkey (T21 cross-server
  replay defence).
- Replay defence: per-request `(pk, nonce)` UNIQUE + 300s window.
- Token-bucket rate limiting (five buckets:
  `AcquireAuthAttempt`, `AcquireRegister`, `AcquireProof`,
  `AcquireWrite`, `AcquireBytes`).
- Optimistic CAS with `409 divergence` retry hint on stale push.
- Membership discovery via `/sync?discover_memberships=true`.

### Transparency log

- Per-chain RFC 6962 Merkle tree, SHA-256 leaves with domain
  separators (`fd0-translog-{leaf,node,empty,sth,server-info}-v1`).
- Ed25519-signed STHs; mandatory on every `/sync` response carrying
  events. Mandatory inclusion proofs per pulled event; optional
  consistency proof against client-supplied `last_sth_size`.
- First-contact pinning via `/v1/server-info` (TOFU + safety-
  number ceremony, opt-in non-TTY via `FD0_AUTO_PIN`).
- Atomic keyfile-↔-DB lifecycle: 5×2 startup matrix; refuses to
  start on mismatch.

### Witness

- `fd0-witness` binary: passive STH archiver, polls upstream
  servers, detects same-size and different-size equivocation.
- Cosign protocol (`WitnessedSTH`, domain
  `fd0-witness-cosign-v1`): the witness cosigns honest STHs and
  withholds on consistency failure (no signing oracle for forks).
- Client cross-check via `[[witness]]` config and
  `[witness_policy] min_cosigns`. A 409 from the witness archive
  (multi-root at size) is a hard equivocation refusal.
- `/v1/witness/highest` and `/v1/witness/equivocation` probes
  catch first-fetch rollback (T41) and historical equivocation
  across the chain (T35).

### Storage

- Append-only CBOR chain files; vault `chain_tip` binds the
  latest accepted seq+hash; single-file rollback is detected on
  open.
- Local compaction drops superseded `secret.set` events. The
  transparency log is unaffected — anchored by STHs, not local
  events.
- Atomic vault rewrites (`vault.enc.tmp + fsync + rename + fsync
  parent`). `O_NOFOLLOW` on every chain-file and vault open
  (T18 symlink-redirect defence).

### Threat model

- 54 catalogued threats (T01–T54) across six attacker classes (A1
  hosted-server operator through A6 coerced/lost-credential) and
  six trust boundaries (TB1–TB6).
- Every non-📋/⛔ threat has at least one `// THREAT: Txx`
  annotation in production code; `tools/threat-coverage`
  (`make lint`) enforces the doc-↔-code link.
- 8 semgrep rules (`tools/semgrep/`) freeze real bug classes
  surfaced during security review.

### Tooling

- `fd0 doctor`: read-only health check; sections for agent, user
  chain, scopes, auth-method consistency, and orphan files.
- `cmd/fd0-yubikey-record`: hardware-day recorder that captures
  golden vectors against a real YubiKey. CI replays them through
  the pure-software path on every push.
- `cmd/fd0-test-{bad-witness,equiv-inject,mitm}`: adversarial
  test harnesses for integration tests.
- Wire-format compat snapshot at `internal/wirecompat/testdata/v1/`
  pins the on-disk format; `TestWireCompatV1Verify` fails on any
  break.

### Testing

- 17 shell integration tests (~5,500 LoC) including a 563-line
  multi-user e2e and a 91-assertion YubiKey e2e with optional
  200-cycle stress phase (`FD0_YUBIKEY_STRESS=N`).
- 4 rounds of brutal adversarial code review (4 P0 + 20 P1 + 16
  P2 findings total; 10 production-bug-class fixes).
- Performance baseline (`docs/BENCH.md`) covering server-side translog,
  client-side chain replay, and vault unlock.

### Out of scope for v1.0 — deferred to v1.x or later

- Full user-chain sync (subsequent `auth.set` events propagated to
  the server). v1 idempotently registers the genesis only.
- STH archive endpoint (`GET /v1/sth/{cid}?at_size={n}`) — current
  STH only.
- Per-scope sensitivity flag (re-prompt before sign/decrypt on
  high-value scopes).
- Per-event forward secrecy (all events under one OEK era share
  the same key).
- User-chain compaction.
- OS keystore backends (macOS Keychain, Linux Secret Service,
  Windows Credential Manager).
