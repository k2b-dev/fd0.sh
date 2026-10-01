# Machine identities plan

Status: phase A implemented 2026-10-01 after two peer reviews; phase B needs its own design review.

## Outcome and scope

Let unattended consumers (CI runners, agents, deploy hosts, scheduled jobs) use fd0 with their own identity instead of a person's unlocked vault or plaintext copies of secrets. A machine identity is an ordinary fd0 identity in its own `FD0_HOME`, unlocked without a person present, and a member of only the scopes it needs.

- **Phase A** adds non-interactive unlock and server pinning. No server or protocol change. Every scope member, machine or person, can still change values and membership, so phase A machines must be trusted to administer their scopes.
- **Phase B** adds server- and client-enforced member roles (`reader`, `writer`, `admin`) so a machine can read, or read and write values, without being able to change membership. This is a protocol change and gets its own design and review before implementation.

Not in scope: unattended methods on a person's identity, secret grants (docs/SECRET_GRANTS_PLAN.md), cloud identity federation, hardware-bound machine keys.

## Phase A

### Model

- The identity is created and used like any other, in a dedicated `FD0_HOME` owned by a dedicated service account (separate UID). Separate homes under one UID do not isolate processes.
- Its auth method is the existing passphrase method; the passphrase is a random key read from a file. Vault format, user chain and clients stay unchanged. Unlock runs Argon2 (64 MiB, three passes), which is acceptable for infrequent unlocks.
- The key is provisioned outside fd0, for example `umask 077; head -c 32 /dev/urandom | base64 > fd0.key`, ideally as a systemd credential. fd0 never generates or stores it.

### Commands

```sh
export FD0_HOME=/var/lib/ci/fd0                      # owned by the service account
fd0 init --key-file "$CREDENTIALS_DIRECTORY/fd0.key"
fd0 unlock --key-file "$CREDENTIALS_DIRECTORY/fd0.key"
fd0 sync --pin "12345 67890 …"                       # server safety number, verified out of band
fd0 card export                                      # an admin adds this card to the scopes
fd0 sync                                             # after admission
```

- **Key file contract:** `--key-file PATH` (or `-` for stdin) on `init` and `unlock` only. The file must be a regular file (no symlink, no FIFO) owned by the current user or by root (systemd credentials) and not readable by group or others; size at most 4 KiB, content at least 32 bytes after removing one trailing newline. With `--key-file` there is never a prompt fallback. The value is wiped after use on a best-effort basis; intermediate copies in IPC buffers are not guaranteed to be wiped, as for typed passphrases.
- **Idempotent unlock for jobs:** `fd0 unlock --key-file` succeeds immediately when the agent is unlocked, without reading or checking the key, and unlocks again when an idle or maximum lifetime expired. Consumers run it at the start of every job instead of relying on a long-lived unlocked session.
- **Pinning:** `fd0 sync --pin SAFETY_NUMBER` pins the server on first contact only when the fetched key's safety number matches; it fails on mismatch and also verifies an existing pin. It takes precedence over `FD0_AUTO_PIN`, which remains a test and lab convenience. The agent's background sync never pins on first contact, so unlocking before `sync --pin` is safe.
- **Explicit method IDs:** `--method am_…` is now enforced end to end: the unlock request carries the method ID and the agent refuses a credential that belongs to another method. Without an explicit ID, any passphrase method may unlock, as before.

### Operating model (documentation)

- One identity per machine and purpose. Never copy a machine's `FD0_HOME` to another host.
- Phase A machines are **administrator-equivalent** in their scopes. Use dedicated, disposable scopes that contain only that consumer's credentials, never broad human scopes. Keep an independent copy of those credentials and a tested way to recreate the scope.
- Revocation: remove the machine from its scopes, check the scope's member list for members you did not add, and rotate every value it could read. If membership was tampered with, create a new scope instead of repairing the old one.
- Example: a `fd0-unlock.service` (oneshot, `ExecStart=fd0 unlock --key-file %d/fd0.key`) and consumers that also call `fd0 unlock --key-file` before each run.

### Verification

- Unit tests for the key file contract (owner, mode, regular file, size, minimum length, newline, stdin).
- In-process tests: `init --key-file`, `unlock --key-file` without a TTY and after expiry, refusal without fallback, `sync --pin` match, mismatch and existing-pin verification against a local test server.
- Guarded integration script: machine identity created, admitted by a person, syncs with a pin, reads a service, loses access after removal.

## Phase B (outline, needs design review)

- `member.change` gains a role. The scope creator is `admin`. Only admins may author `member.change`; `writer` and `admin` may author `secret.set`; `reader` authors nothing.
- The server validator and client replay enforce the same rules; a client never accepts an event the rules forbid, even from a misbehaving server.
- Existing scopes keep all current members as `admin`, so nothing changes until an admin assigns a narrower role.
- Open questions for the design: wire format and version gating, interaction with OEK rotation and key deliveries, the last-admin rule, Desktop and CLI surfaces, and how old clients behave in scopes that use roles.
