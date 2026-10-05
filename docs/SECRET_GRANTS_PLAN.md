# Secret grants plan

Status: implemented 2026-10-05 as reviewed (see Review), with two Codex code reviews.

## Outcome and scope

Let a user approve one named plain secret or one text/secret field of a pass item so that it can still be read while the vault is locked. This serves unattended consumers that only need a single credential: a `cld` agent profile reading its OAuth client secret, a backup job reading one token, a deploy script reading one key. Today these consumers either keep the whole vault unlocked for hours or copy the value into a plaintext file, which is what happened with three `cld` agent profiles on the dev VM.

The model mirrors SSH grants: per installation, created with fresh authentication, saved in the encrypted vault, active after one unlock, surviving `fd0 lock`, stopped by `fd0 lock --all`, removed by revocation.

Not in scope: write access, file attachments, TOTP seeds, whole items, bulk grants, a run/inject command, remote or cross-device grants, and any claim of protection against code running as the same OS user.

## Threat model

The fd0 agent answers anyone who can connect to `agent.sock`, which is every process running as the same user. A secret grant therefore deliberately exposes that one value to all local processes of the user for as long as the grant is active. The design must say this plainly in CLI, Desktop and docs.

Compared with what consumers do today, a grant narrows exposure:

| Today | Exposure | With a grant |
| --- | --- | --- |
| Vault kept unlocked | every secret in every scope, for the whole session | one value |
| Plaintext copy in a config file | one value, on disk, in backups, after the vault is locked or the item rotated | one value, in agent memory only, gone after agent restart until the next unlock |

Grants must not weaken anything else: the vault identity, payload and scope keys stay locked; only the released value is held, in protected agent memory, as with SSH grant keys.

## Contract

- **Selection:** scope ID, record name, and for pass items and services one field whose type is `text` or `secret`. Resolve ambiguity before creating; never prefix-match. The grant stores the record ID (see review).
- **Creation:** `fd0 secret grant NAME --scope S [--field PATH] [--ttl DURATION]` while unlocked. Show scope, item, field, type and expiry, then require fresh authentication with the same method chooser as unlock. No `--yes`, no password flag, no organization-MCP tool.
- **Use while locked:** the existing reads work unchanged: `fd0 secret get NAME --scope ID --raw` and `fd0 pass field get NAME PATH --scope ID --raw`. Exact names and scope IDs only. Anything not granted fails with exit code 3, as today.
- **Value lifecycle and identity:** superseded by the review below (stable record IDs, refresh at unlock and on every vault write).
- **Expiry:** every grant has an expiry; default 30 days, renewable with fresh authentication. Expired grants stay listed as expired until revoked.
- **Stop and remove:** `fd0 lock --all` stops all grants until the next unlock. `fd0 secret revoke GRANT_ID` removes one (vault unlocked). Agent or computer restart clears released values until the next unlock.
- **Inspection:** `fd0 secret grants [--json]` lists grant metadata, active state, expiry, release count and last release time. Never values.
- **Storage:** an optional encrypted `secret_grants` vault field next to `ssh_grants`, bound to the installation's `device_id`. Older clients ignore the field.

## Open questions for review

1. **Caller binding.** Option A: no binding, documented honestly (recommended; simple and truthful). Option B: check the caller's executable via `SO_PEERCRED`/proc. It looks stronger but a same-UID process can impersonate it, so it would be security theatre.
2. **Default expiry.** 30 days, or no default and an explicit `--ttl` every time?
3. **File fields.** Leave out for now (recommended) or allow small attachments such as NATS creds?
4. **Desktop.** Same "Allow while locked" section as for SSH hosts, or CLI only in the first version?

## Review 2026-10-03

**Still needed.** Machine identities and services, both shipped since this draft, do not replace it. A machine identity unlocks from a key file on disk, which is the plaintext-copy problem again for a consumer that runs as the user on the user's own device. Evidence from 2026-10-03 on the dev VM: the vault auto-locked twice during one session and each time `cld --profile agent-…` could no longer read its OAuth client secret; an SSH grant kept SSH working, nothing kept that one value.

**Changes to the contract.**

- **Selection includes service fields.** Credentials that programs read now live in services; a grant names a scope ID, a record name and, for pass items and services, one field of type `text` or `secret`. Reads while locked use the existing commands: `secret get --raw`, `pass field get … --raw`, `service get NAME FIELD --raw`.
- **Stable identity.** A grant stores the record ID, kind, field path and field type next to the display name. Deleting, moving or replacing the record, or recreating the field, invalidates the grant until it is approved again; a new record with the same name never inherits it.
- **Value lifecycle.** As with SSH grant keys, the agent refreshes granted values at unlock and after every committed vault write, so a rotation synced while unlocked is served after the next lock. A plain lock then only destroys the normal vault keys. `lock --all`, expiry (checked on every release), revocation and agent shutdown wipe released values. Locked reads go through a narrow agent operation that returns one granted value, not through the full session the CLI uses when unlocked.
- **One grant model.** Store `secret_grants` next to `ssh_grants` (every reseal must preserve both) and reuse the same parts: device binding, fresh authentication, `lock --all`, the method chooser, list/revoke. `fd0 status` reports one active-grants count, and Desktop's lock-screen overview ("Active while locked") lists secret grants by name and expiry, without values, next to SSH hosts.

**Answers to the open questions** (recommendations for Valentin):

1. Caller binding: A, no binding, stated plainly. Same-user processes can impersonate any binding.
2. Expiry: default 30 days, `--ttl` up to 365 days, no "never". Renewing needs fresh authentication; expired grants stay listed until revoked.
3. File fields: still out. Small file fields (NATS creds) can follow once a consumer needs them; the size limit would match service file fields.
4. Desktop: CLI creates and revokes in the first version; Desktop shows active secret grants read-only in the lock-screen overview and in Settings. Creating in Desktop follows the SSH grant section later.

**Implementation steps** (each with tests and a Codex review): 1) vault field, agent refresh and the narrow release operation; 2) CLI `grant`/`grants`/`revoke` for secrets, pass and service fields; 3) locked reads in `secret get`, `pass field get`, `service get`; 4) status count and Desktop read-only list; 5) threat model, docs and skill.

## Verification plan

- Agent tests: grant creation requires fresh authentication; locked reads return only granted values; ungranted reads fail with `ErrAgentLocked`; `lock --all`, revoke, expiry, agent restart and item changes stop release.
- CLI tests: exit codes, `--json` output without values, exact-name enforcement while locked.
- Isolated integration script under the guarded runner: a consumer reads a granted secret after `fd0 lock`, fails after `lock --all`.
- Threat documentation updated in `docs/THREATS.md` and the fd0 skill.

## As built (2026-10-05)

- Commands: `fd0 secret grant NAME --scope S`, `fd0 pass grant ITEM FIELD --scope S`, `fd0 service grant NAME FIELD --scope S`, each with `--ttl` (default 30d, at most 365d) and fresh authentication in a terminal; `fd0 secret grants [--json]` and `fd0 secret revoke ID` cover all three kinds.
- Locked reads use the existing commands with exact names and `--scope` (scope ID, or a label that names exactly one scope): `fd0 secret get NAME --raw`, `fd0 pass field get ITEM FIELD --raw`, `fd0 service get NAME FIELD --raw`. With a matching grant the interactive unlock prompt is skipped.
- The agent refreshes granted values at unlock and after every vault write. A grant whose record or field was deleted, renamed or retyped is removed for good at the next vault write, so a recreated record or field never inherits it. Expiry is checked on every read; `lock --all`, revocation and agent shutdown destroy released values. `fd0 lock` and `fd0 status` report active value grants.
- Desktop lists active value grants on the lock screen next to SSH hosts (name, vault, expiry, never the value). Creating and revoking stays in the CLI.
- Limit: decrypted records are Go strings during replay, so values can still exist in ordinary heap memory briefly; the released copy is held in protected memory and wiped after each response.
