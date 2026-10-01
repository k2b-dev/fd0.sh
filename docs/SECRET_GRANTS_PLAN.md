# Secret grants plan

Status: draft for review, 2026-10-01. Not implemented.

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

- **Selection:** scope ID, record name, and for pass items one field path whose type is `text` or `secret`. Resolve ambiguity before creating; never prefix-match.
- **Creation:** `fd0 secret grant NAME --scope S [--field PATH] [--ttl DURATION]` while unlocked. Show scope, item, field, type and expiry, then require fresh authentication with the same method chooser as unlock. No `--yes`, no password flag, no organization-MCP tool.
- **Use while locked:** the existing reads work unchanged: `fd0 secret get NAME --scope ID --raw` and `fd0 pass field get NAME PATH --scope ID --raw`. Exact names and scope IDs only. Anything not granted fails with exit code 3, as today.
- **Value snapshot:** the agent captures the value at unlock. Changes that arrive later (rotation, sync) take effect at the next unlock. A deleted, moved or retyped field, or loss of scope membership observed locally, disables the grant until it is reviewed again.
- **Expiry:** every grant has an expiry; default 30 days, renewable with fresh authentication. Expired grants stay listed as expired until revoked.
- **Stop and remove:** `fd0 lock --all` stops all grants until the next unlock. `fd0 secret revoke GRANT_ID` removes one (vault unlocked). Agent or computer restart clears released values until the next unlock.
- **Inspection:** `fd0 secret grants [--json]` lists grant metadata, active state, expiry, release count and last release time. Never values.
- **Storage:** an optional encrypted `secret_grants` vault field next to `ssh_grants`, bound to the installation's `device_id`. Older clients ignore the field.

## Open questions for review

1. **Caller binding.** Option A: no binding, documented honestly (recommended; simple and truthful). Option B: check the caller's executable via `SO_PEERCRED`/proc. It looks stronger but a same-UID process can impersonate it, so it would be security theatre.
2. **Default expiry.** 30 days, or no default and an explicit `--ttl` every time?
3. **File fields.** Leave out for now (recommended) or allow small attachments such as NATS creds?
4. **Desktop.** Same "Allow while locked" section as for SSH hosts, or CLI only in the first version?

## Verification plan

- Agent tests: grant creation requires fresh authentication; locked reads return only granted values; ungranted reads fail with `ErrAgentLocked`; `lock --all`, revoke, expiry, agent restart and item changes stop release.
- CLI tests: exit codes, `--json` output without values, exact-name enforcement while locked.
- Isolated integration script under the guarded runner: a consumer reads a granted secret after `fd0 lock`, fails after `lock --all`.
- Threat documentation updated in `docs/THREATS.md` and the fd0 skill.
