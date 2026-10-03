# fd0 protocol — high-level

This reference exists so an agent using the fd0 CLI can reason about what is and is not protected, and what the constraints actually are. For exhaustive cryptographic detail, read `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/TRANSLOG.md`, and `docs/THREATS.md` in the source repository.

## One-sentence summary

The server stores ciphertext and signed events; every secret is sealed client-side under a per-scope key, scope membership is a cryptographic operation (not policy), and every server tree-head is countersigned by an independent witness so a server cannot show different histories to different clients without leaving a publishable proof.

## What the server sees

| Layer | Visible | Not visible |
|---|---|---|
| Wire | TLS-terminated request timing, source IP, request size | Plaintext request body — encrypted at the protocol layer |
| Storage | Ciphertext + signed event headers, chain tips, STH archive | Secret values, secret names, scope memberships, passphrases, OEKs, super_priv |
| Operational | Stop the service, change DNS, sign a new STH | Decrypt anything in the storage column, even with root |

The server's operator can withhold service (denial), trigger replay-by-restore, or fork the log. None of these let the operator read plaintext. All of them are detected by clients or witnesses.

## Identities

Every user holds an ed25519 `super_keypair`. The private half (`super_priv`) lives:

1. **On disk** wrapped under the unlock passphrase (or YubiKey-PIV X25519 key), in `~/.fd0/vault.enc`.
2. **In memory** mlocked inside `fd0-agent` after `fd0 unlock` runs. The agent zeroes it on `fd0 lock`, on the configured idle timeout, or on max-lifetime. Status checks and rejected IPC requests do not extend the idle deadline; only successful protected operations do. Max-lifetime is absolute.
3. **Optionally on a paper QR** or other off-host medium, via `fd0 recovery export`. The export is itself encrypted under a separate recovery passphrase.

`super_priv` is the root of identity. Loss without a recovery export means the user cannot decrypt anything they wrote.

## Scopes and the OEK

A **scope** is a named container of secrets (`work`, `personal`, etc.). Every scope has a current **Object Encryption Key** (OEK) — a symmetric key that encrypts every secret in that scope.

For each scope member, the OEK is wrapped (via X25519 sealed-box) to that member's super_pub. Adding a member is a `member.change op=add` event that wraps the current OEK to their key. Removing a member is a `member.change op=remove` event that generates a NEW OEK and re-wraps it to every remaining member but not the removed one.

The cryptographic consequence: after `remove-member`, any secret written under the new OEK cannot be decrypted by the removed member, even if they intercept the ciphertext from the wire. This is what "cryptographic membership" means.

Members can have a role: `admin` (default; changes values and membership), `writer` (changes values) or `reader` (reads only). The server and every client check the role of each event's author against the signed scope chain, and a scope always keeps at least one admin. A role change is a `member.change op=role` event without key rotation, because it does not change who can read. Roles never limit reading.

Caveat the agent must explain to users: removal does NOT retroactively un-leak secrets the removed member already read. Treat anything they had access to before removal as compromised and rotate the underlying credentials (the actual GitHub token, the actual database password) out-of-band.

## Events and chains

Every state-changing operation is an event. Events are append-only and chained: each event's `prev_hash` covers the previous event in its chain. There are two chain kinds per user:

- **User chain** — `user:<shortId>`. One event kind: `auth.set` (a signed snapshot of the active unlock methods; adding or rotating credentials posts a new one).
- **Scope chain** — `scope:<scope_id>`, one per scope. Two event kinds: `member.change` and `secret.set`. A scope's first event is a `member.change op=add` (that is how the scope is created and its `scope_id` derived); a `secret.set` with a nil record is a tombstone (removal); the OEK is rotated as part of a `member.change op=remove`.

Events are CBOR-encoded, signed by their author's super_priv, and content-addressed by `event_id = SHA256(canonical_cbor)`. The server's `events.event_id UNIQUE` constraint provides idempotent dedup: pushing the same event twice is a no-op.

This is why an idempotent re-push of an event the primary already stored is a no-op — duplicates are handled at the storage layer for free, so a retried sync never double-applies anything.

## Transparency log

Every server maintains an RFC 6962 Merkle tree per chain. Every accepted event becomes a leaf. The server signs a Signed Tree Head (STH) per request that touched the tree. An STH covers `(chain_id, tree_size, root_hash, timestamp)`.

Clients receive an STH on every sync and verify:

1. The STH's signature against the pinned server pubkey.
2. The inclusion proof for every event the response claims to have stored.
3. The consistency proof from the previously-anchored STH to the new one (a server cannot rewrite history without breaking the proof chain).

Independent **witnesses** poll each server's STH and cosign honest tree-heads. Two clients comparing notes — or a third-party observer — detect equivocation: if the server signs two STHs at the same `tree_size` with different roots, both are valid evidence of misbehavior.

This is why clients enforce a "pin matches" rule on every sync. A pin-mismatch is either operator-side key rotation (requires manual ceremony) or attack — both deserve refusal until manually resolved.

## Single primary + DR backup

A client targets **exactly one** server — the primary — via `[sync].server = "..."`. Every write and every read for every scope goes to that one primary, which is the sole ordering authority for the scope. With one authority, two histories can never disagree, so the chains can never fork. The default hosted-fd0.sh client targets the single primary `api.fd0.sh`.

A configuration listing more than one server (the old `[sync].servers = [...]` array) is a **hard error**: fd0 refuses to start and prints a migration message pointing the operator to `[sync].server` plus a server-side DR backup. There is no multi-push and no live read-failover — reading from a possibly-stale second server is exactly the inconsistency this model eliminates. A scope's availability equals its primary's uptime; already-synced secrets stay readable locally because the vault is local.

Semantics:

- **Push / read** — both go to the one primary. A retried sync is idempotent (server-side dedup), never a double-apply.
- **Per-server state** — push floor and last verified STH for the primary are tracked in the vault; the primary's translog is verified against its TOFU pin.

Redundancy comes from a **server-side disaster-recovery backup**, not a second write target. A standby configured with `FD0_REPLICATE_FROM=<primary-url>` pulls the primary's chains into a write-once local archive, verifying each STH under the primary's key before storing it. The backup never serves or re-signs those chains, so it can never become a second authority. The primary authorises the pull by listing the standby in `FD0_PEERS` (a TOFU-pinned peer); removing it there revokes the pull. Promoting a backup to a new primary is a deliberate operator ceremony, not automatic failover. (Hosting this is out of scope for the CLI user — see `docs/REPLICATION.md` and `docs/HOSTING.md`.)

## What this means for an agent using fd0

When you're using fd0 on behalf of the user:

- A failed `fd0 sync` does NOT mean the secret was lost — locally-stored events survive in `~/.fd0/chains/`. Retry sync; do not re-prompt the user for the value.
- A `pinned-key-mismatch` error is a SECURITY EVENT, not a transient. Stop, surface it, and require the user to verify the new fingerprint out of band before re-pinning. The fd0 prompt walks through this.
- A `witness cross-check failed` error is also a security event. The server's STH is not what the witness saw. Stop and refer the user to the operator.
- After `fd0 scope remove-member`, recommend rotating the underlying credentials externally. The cryptographic revocation only applies to FUTURE writes.
- Removing a credential with `fd0 rm` writes a tombstone. v1 retains signed history locally and on the server; tell the user to rotate the underlying credential if it was a real leak.

## Why these guarantees matter

fd0's design treats the server as a hostile-by-default storage broker. The threat model assumes the operator might:

- Be coerced by a legal authority
- Be compromised by an attacker
- Be the attacker

For each, the worst they can do is deny service, fork the log (detectable), or roll the state back (also detectable via STH monotonicity). They cannot read or modify a single byte of plaintext.

This is what an agent must keep in mind when answering "is it safe to put X in fd0?" The answer for any credential that fits in a few KB is yes — even if the operator goes rogue, the secret is mathematically protected.
