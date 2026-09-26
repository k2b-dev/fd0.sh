# fd0 Storage (v1)

Companion to `PROTOCOL.md`. Server uses SQLite; client uses append-only CBOR files. Both store byte-identical events.

## Contents

1. [Properties](#1-properties)
2. [Server storage (SQLite)](#2-server-storage-sqlite)
3. [Client storage (CBOR files)](#3-client-storage-cbor-files)
4. [Replay](#4-replay)
5. [History retention and scope-leave](#5-history-retention-and-scope-leave)
6. [Subscriptions and discovery](#6-subscriptions-and-discovery)
7. [Read and write paths](#7-read-and-write-paths)
8. [Backup and restore](#8-backup-and-restore)
9. [Limits](#9-limits)
10. [Growth (order of magnitude)](#10-growth-order-of-magnitude-small-team)
11. [Conformance](#11-conformance)

---

## 1. Properties

- Server and client store byte-identical protocol-defined CBOR.
- Every `auth.set`, `secret.set`, and `member.change` is a self-contained snapshot.
- Client reads are O(1) lookups against an in-memory index rebuilt at open.
- Decrypted secret material never touches disk; `super_priv` and OEKs live only inside `vault.enc`.
- Clients store events only for their own user chain and current-membership scopes.
- The server stores every event forever.
- The vault binds the latest accepted seq+hash for each chain, so single-file rollback is detected on open.
- Local size grows with the active key set, not chain lifetime or member churn.

---

## 2. Server storage (SQLite)

```sql
CREATE TABLE events (
    chain_id    TEXT    NOT NULL,            -- "user:<shortId>" | "scope:<scope_id>"
    seq         INTEGER NOT NULL,
    event_id    TEXT    NOT NULL UNIQUE,
    prev_hash   BLOB,                         -- nullable iff seq=0
    kind        TEXT    NOT NULL,             -- "auth.set" | "member.change" | "secret.set"
    cbor        BLOB    NOT NULL,
    stored_at   INTEGER NOT NULL,
    PRIMARY KEY (chain_id, seq)
);

CREATE INDEX events_by_chain_seq ON events(chain_id, seq);

CREATE TABLE chains (
    chain_id  TEXT    PRIMARY KEY,
    tip_seq   INTEGER NOT NULL,
    tip_hash  BLOB    NOT NULL,
    metadata  BLOB                            -- CBOR, chain-kind-specific:
                                              --   user:  { super_pub, shortId }
                                              --   scope: { oek_version_max,
                                              --            members: [super_pub] }
);

CREATE TABLE auth_nonces (
    pk    BLOB    NOT NULL,
    nonce BLOB    NOT NULL,
    ts    INTEGER NOT NULL,
    PRIMARY KEY (pk, nonce)
);

CREATE INDEX auth_nonces_by_ts ON auth_nonces(ts);
```

SQLite settings:

```
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

The server stores events forever and MUST NOT delete or mutate accepted events.

---

## 3. Client storage (CBOR files)

Layout under `~/.fd0/` (override with `FD0_HOME`):

```
~/.fd0/
    .lock                        -- exclusive-lock sentinel
    chains/
        user.cbor                -- user identity chain
        <scope_id>.cbor          -- one file per joined scope
    vault.enc                    -- encrypted material
    config.toml                  -- non-secret config
    recovery/                    -- optional, user-managed exports (see `PROTOCOL.md` §6.3)
```

In-memory state (member set, secret_index, OEK selection per event) is rebuilt at process start by the replay function in §4.

### 3.1 Chain files

Each chain file is a concatenation of raw deterministic-CBOR events:

```
chain_file = cbor(event_0) || cbor(event_1) || cbor(event_2) || …
```

Filenames:

- `chains/user.cbor`: one per device.
- `chains/<scope_id>.cbor`: `<scope_id>` matches the events' `scope` field. Replay (§4) recomputes the genesis-derived `scope_id` and rejects mismatched filenames.

Append rules:

- `O_WRONLY | O_APPEND`.
- `write_all` then `fsync` before reporting success.

Crash recovery on open:

- Decode events sequentially. On partial decode, `truncate` at the start offset of the failing event.
- Tail-truncation is safe only under the single-writer lock (§3.4); without the lock, a partial event from one writer followed by a complete event from another would truncate incorrectly.

### 3.2 `vault.enc`

Format: `PROTOCOL.md` §6.1. Atomic rewrite via `vault.enc.tmp + fsync + rename + fsync(parent)`.

The vault binds `auth_tip` and per-scope `chain_tip` to the chain files. Mismatch is detected on open (`PROTOCOL.md` §6).

`WrappedKey.method_id` ties each unlock entry to a currently-active `AuthMethod`. Inactive wraps are pruned on every sync.

The optional encrypted `ssh_grants` field stores personal SSH approvals keyed by
installation ID. It contains host/key identities and constraints, never extra
private key copies. It is not a scope record and is not synchronized with scope
members. The agent preserves this field across ordinary `ReSeal` calls, including
calls from clients that omit it. Only its dedicated grant operation can create
or remove approvals through the supported API.

### 3.3 `config.toml`

Plain TOML, no secrets. `device_id` is a random 32-byte identifier encoded as
64 lowercase hexadecimal characters, created once per fd0 home. CLI and Desktop
share it. Copying the entire home copies the ID; it is not a hardware binding.
Its initialization serializes through `config.toml.lock` and atomically replaces
the config while preserving unrelated settings.

Example:

```toml
short_id = "jg379se4"

[sync]
server    = "https://fd0.example.com"
interval  = "1h"
on_unlock = true

[clipboard]
clear_after_seconds = 30
```

`user_super_pub` lives in the vault and in every event of the user chain; it is not duplicated in `config.toml`.

### 3.4 Concurrency

One advisory exclusive lock at `~/.fd0/.lock` (`flock(LOCK_EX)`) covers append, verified history repair, tail-truncation on open, vault re-seal, scope unlink, and config writes. v1 assumes one fd0 process per `FD0_HOME`.

---

## 4. Replay

Every chain-processing path (open, sync, and recovery) uses the same `replay_chain(file, vault) → (state, vault_delta, errors)` function.

```
replay_chain(chain_file, vault):
    state = empty
    vault_delta = empty
    file_offset = 0
    while not at end of chain_file:
        try decode one CBOR event at file_offset
        on partial decode (CBOR error):
            truncate chain_file at file_offset
            break
        on success: event, next_offset

        verify_event_envelope(event)   -- §4.1; on failure return ERROR

        case event.kind:
            "auth.set"      : apply_auth_set(state, event, vault, vault_delta)
            "member.change" : apply_member_change(state, event, vault, vault_delta)
            "secret.set"    : apply_secret_set(state, event, vault)

        file_offset = next_offset

    case (file_tip vs vault_tip):
        match     : return state, vault_delta
        file ahead: advance vault tip in vault_delta; return
        file behind: return ERROR (rollback)
```

### 4.1 Envelope checks

- Decode succeeds and is canonical CBOR.
- `signature` verifies under the embedded signer key.
- For scope events: `scope` field equals the genesis-derived scope_id (computed from the file's first event with `prev_hash == nil`); reject on mismatch.
- `prev_hash` is `nil` only at seq=0; otherwise matches the previous event's signed-prefix hash.
- `seq` is `prior_seq + 1` (or 0 at genesis).

### 4.2 `auth.set` apply

```
verify: payload.active is non-empty; method_ids unique; signature verifies under user_super_pub
state.latest_auth_set = event
vault_delta: prune WrappedKey entries whose method_id ∉ event.payload.active
```

### 4.3 `member.change` apply

```
verify: author ∈ state.member_set (or genesis: prev_hash=nil, op=add, member=author)
verify: oek_version == prior + 1
verify: key_deliveries' recipient set matches post-mutation member set

if event.member == own super_pub and event.op == "add":
    decrypt our key_delivery with super_priv → new OEK
    decrypt enc_projection with new OEK → projection
    state.member_set = post-mutation set
    state.secret_index = projection.secrets keyed by id
    vault_delta: install OEK
elif event.member == own super_pub and event.op == "remove":
    return SCHEDULE_LEAVE
else:
    decrypt our key_delivery with super_priv → candidate OEK
    decrypt enc_projection with candidate OEK → projection
    for each r in projection.secrets:
        if r.id ∉ state.secret_index OR state.secret_index[r.id] ≠ r:
            return ERROR
    for each non-tombstone id in state.secret_index:
        if id not in projection: return ERROR
    state.member_set = post-mutation set
    state.secret_index = projection.secrets
    vault_delta: install OEK; mark prior OEK for removal if no longer needed
```

The OEK is installed only after projection verification.

### 4.4 `secret.set` apply

```
verify: oek_version == state.current_oek_version
verify: key_deliveries == []
decrypt enc_body with OEK[oek_version]
state.secret_index[body.id] = (event_id, body.record)
```

### 4.5 Recovery from inconsistent on-disk state

After replay, the open path performs:

```
1. For every chain file:
     if replay returned SCHEDULE_LEAVE: unlink it.
     if replay returned ERROR: surface to user; do not advance vault.
2. For every scope_id in vault.scopes:
     if no chains/<scope_id>.cbor exists: drop the scope from vault.
3. For every WrappedKey in vault:
     if its method_id ∉ latest auth.set's active set: prune.
4. If vault changed: re-seal.
```

Scope-leave (§5.3) and credential rotation are crash-atomic in effect: any partial completion is reconciled here.

---

## 5. History retention and scope-leave

### 5.1 Full local history

v1 retains every signed event in both user and scope chain files. Replay
requires:

- genesis at `seq = 0`;
- each subsequent event at exactly `previous.seq + 1`;
- each `prev_hash` equal to the hash of the preceding signed prefix.

The vault-bound final tip alone cannot authenticate which intermediate events
remain in a shortened file. A file that retains the real final event but omits
a newer `secret.set` could otherwise replay stale data. `CompactUser` and
`CompactScope` therefore fail explicitly in v1.

Tombstones update the current state but do not erase historical ciphertext.
Rotate any credential whose plaintext may have leaked.

### 5.2 Legacy non-contiguous file repair

Older v1 clients could remove superseded scope events. Current clients never
expose such a file through replay. On `fd0 sync`:

1. Detect a missing sequence, broken `prev_hash` link, empty file, or mismatch
   between the local final event and the vault-bound tip before normal sync.
2. Pull the full server chain from `cursor = 0`, with pagination.
3. Verify the pinned server identity, STH, inclusion proofs, sequence, and tip.
4. Preserve local-only events by event ID before replacing the file.
5. Atomically write and replay the complete server history.
6. Rebuild and push preserved local events in their original order.
7. Persist the verified final STH and vault tip only after successful replay.

The operation snapshots the original chain and scope vault state. Any failure
restores both, so unavailable servers and failed retries do not discard local
writes. A user who is no longer a member follows the normal scope-removal path.

### 5.3 Scope-leave (`member.change op="remove"` of self)

```
1. Verify signature, prev_hash, op, author ∈ prior member_set.
   Skip projection verification (body undecryptable).
2. unlink chains/<scope_id>.cbor
3. Drop the scope's entry from vault.scopes
4. Re-seal vault
```

A crash between any pair of steps is reconciled by §4.5 on next open.

---

## 6. Subscriptions and discovery

A client maintains chain files for its own user chain and for each scope it is a current member of. Other events are neither requested in `/sync` nor stored locally.

### 6.1 New memberships

The client sets `discover_memberships: true` on `/sync` (`API.md` §2.4) periodically and at every login. The response's `memberships` list contains every scope_id where the client's `super_pub` is currently in the auth list.

For each scope_id not yet known locally:

1. Pull from `cursor = {seq: 0, hash: nil}`.
2. `replay_chain` verifies the `member.change op="add"` whose `member == own super_pub`, installs the OEK, populates `secret_index`.
3. Append the events to a new `chains/<scope_id>.cbor`.
4. Before exposing any secret, prompt the user with the inviter's `shortId`. On refusal, unlink and prune.

---

## 7. Read and write paths

### 7.1 Server: accept event

```sql
BEGIN IMMEDIATE;
  SELECT tip_hash FROM chains WHERE chain_id = ?;
  -- if mismatch → 409 divergence; else validate event and:
  INSERT INTO events (chain_id, seq, event_id, prev_hash, kind, cbor, stored_at) VALUES …;
  UPDATE chains SET tip_seq = ?, tip_hash = ?, metadata = ? WHERE chain_id = ?;
COMMIT;
```

### 7.2 Server: serve `/sync` pull

```sql
SELECT cbor FROM events WHERE chain_id = ? AND seq > ? ORDER BY seq LIMIT ?;
```

### 7.3 Client: read a secret

```
1. flock(~/.fd0/.lock)
2. Open vault.enc; prompt for credential; unwrap → super_priv + auth_tip + scopes (in RAM).
3. replay_chain(chains/user.cbor, vault) → state, vault_delta_user
4. replay_chain(chains/<scope_id>.cbor, vault) → state, vault_delta_scope
5. If vault_delta_* is non-empty: re-seal vault.
6. event = state.secret_index[secret_id]; if absent or tombstone → not found.
7. Decrypt event.payload.enc_body with OEK[event.oek_version]; print record.
8. Zeroize. Release lock. Exit.
```

### 7.4 Client: write a secret

Steps 1–5 as in 7.3, then:

```
6. Build new ScopeEvent (kind = secret.set), encrypt body under current OEK, sign.
7. POST /sync; on 409 divergence, refresh tip from response, re-sign, retry.
8. On accept: append to chains/<scope_id>.cbor; fsync.
9. Update vault.scopes[scope_id].chain_tip; re-seal vault.
10. Zeroize as in 7.3.
```

### 7.5 Member-change write path

Steps 1–5 as in 7.3, then:

- Generate new OEK; build `key_deliveries` for the post-mutation auth_list.
- Decrypt the current projection with the prior OEK; re-encrypt under the new OEK.
- Sign and post.
- On accept: append; install the new OEK in the vault; update `chain_tip`; re-seal.
- For `op = remove` of self: §5.3.

---

## 8. Backup and restore

### 8.1 Client

```
cp -r ~/.fd0/  /backup/
```

The vault is encrypted; events are public-equivalent. A torn backup self-heals on next open via §4 + §4.5.

### 8.2 Server

`sqlite3 .backup` for hot backups. `chains` and `auth_nonces` are rebuildable from `events` if corrupted.

### 8.2.1 Server translog signing key

Critical. Loss of the translog signing key forces every client to
re-pin per `TRANSLOG.md` §4.3, dropping equivocation evidence for
STHs signed under the old key.

Backup procedure:

1. The key lives at `<data-dir>/server-translog.key` (or whatever
   `--server-priv-file` points at). 64 bytes raw Ed25519
   (`seed || pub`), mode `0600`.
2. Copy out-of-band (encrypted backup, HSM, paper QR) after first
   boot. The server writes the key once at first start; the same
   pubkey is also persisted in the DB's `translog_server_key` table
   for boot-time consistency check.
3. To restore: place the keyfile back; restart the server. The
   keyfile-↔-DB cross-check verifies the pubkey matches.
4. If only the keyfile is lost but the DB pubkey persists, the
   server refuses to start (matrix row 4 in `TRANSLOG.md` §4.1).
   Recovery requires either restoring the file from backup or
   running the key-rotation ceremony in `TRANSLOG.md` §4.3.

### 8.3 Recovery scenarios

- **Lost client artifacts, identity intact via recovery export:** a v2 export restores `super_priv`, the signed user chain, and the encrypted vault bootstrap, preserving every authentication method present at export; sync refreshes remote scope state. A legacy v1 export restores the identity and creates one new local passphrase method (`PROTOCOL.md` §6.3).
- **Lost client artifacts, no recovery export:** install fd0 on a new device; from a still-trusted device append a fresh `auth.set` including the new method; sync on the new device.
- **Lost vault.enc only:** equivalent to lost device.
- **Lost server DB:** push events from any client back to a fresh server; the server rebuilds `chains`. Replay nonces are fresh by construction.
- **Lost everything everywhere with no recovery export:** identity is unrecoverable.

---

## 9. Limits

"Enforced" — the server rejects requests that exceed the limit.
"Advisory" — documented for operators; not currently enforced in
code. Operators expecting deployments to approach an advisory
limit should add their own checks (or open an issue).

| Constraint                              | Value                   | Enforcement |
| --------------------------------------- | ----------------------- | ----------- |
| `cbor` (full event) per row             | ≤ 8 MB                  | Enforced (via `MaxBody`) |
| `secret.set` body                       | ≤ 64 KB                 | Enforced |
| `member.change` body                    | ≤ 1 MB                  | Enforced |
| Active auth methods per `auth.set`      | ≤ 50                    | Advisory |
| Active members per scope                | ≤ 1 000                 | Advisory |
| Active secrets per scope                | ≤ 10 000                | Advisory |
| Events/sec per `super_pub`              | sustained 10, burst 100 | Enforced (token bucket, `AcquireWrite`) |
| Concurrent connections per `super_pub`  | ≤ 4                     | Advisory |
| Request body bytes                      | ≤ 8 MB                  | Enforced (`FD0_MAX_BODY`) |

---

## 10. Growth (order of magnitude, small team)

- Server, per scope per year: ~15 MB
- Server, per user chain per year: ~50 KB
- Server total (5 users, 3 scopes, 100 years): ~5 GB
- Client, per scope per year: ~15 MB
- Client total depends linearly on retained scope history

---

## 11. Conformance

A client MUST:

- Store events as concatenated deterministic CBOR per §3.1.
- Use `replay_chain` (§4) for every chain-processing path.
- Encrypt the vault per `PROTOCOL.md` §6, including `auth_tip` and per-scope `chain_tip`.
- Verify vault tips against chain-file heads on every open and refuse to operate on rollback.
- Never write decrypted secret material outside `vault.enc`.
- Apply locality rules in §6.
- Retain a contiguous local event history; reject gaps and repair them only through verified full sync.
- Acquire `flock` on `~/.fd0/.lock` for every state-mutating operation.

A server MUST:

- Use the SQLite schema in §2 verbatim or a backend producing identical observable semantics.
- Store events forever; never delete or mutate accepted events.

Implementations MAY apply stricter operator-policy limits and add observability that does not affect the protocol surface.
