---
name: fd0
description: >-
  Use this skill whenever the user — or an agent acting on the user's behalf — needs to store, fetch, share, or organize secrets with the fd0 CLI (`fd0 init`, `fd0 secret set`, `fd0 secret get`, `fd0 sync`, `fd0 scope ...`, `fd0 card ...`), use fd0 as a password manager (`fd0 pass ...`), manage SSH keys, hosts, terminal sessions, or remote files (`fd0 key ...`, `fd0 ssh ...`, `fd0 sftp ...`), or manage Talos Linux / Kubernetes credentials (`fd0 talos ...`, `fd0 kube ...`). Trigger on any of these phrasings even when the user does not name fd0 explicitly — "store a deploy key", "save this API token", "fetch my DB password", "share a credential with bob", "add bob to the work scope", "rotate access", "set up my passphrase", "vault locked", "lock failed", "sync errored", "open my password manager", "store a login", "copy my GitHub password", "fill a login in Chrome", "add a TOTP code", "attach a recovery key file", "generate an ssh key", "share ssh access with the team", "connect to the prod box", "browse files on the prod box", "upload this release to the server", "download a remote log", "store the talosconfig", "share the kubeconfig", "bootstrap a talos cluster". Also trigger when an agent in the middle of another task needs to inject a credential into a script or deploy step — `fd0 secret get NAME` or `fd0 pass field get ITEM FIELD --raw` is the canonical retrieval path. Do NOT trigger for hosting or operating the fd0-server; that is a separate concern documented in this project's docs/HOSTING.md.
---

# fd0 — Zero-knowledge secrets CLI

fd0 stores credentials client-side under a passphrase (or YubiKey), syncs ciphertext-only to a server, and shares scope-by-scope with teammates via cryptographic membership. The server cannot decrypt anything. Every change is a signed event, every server tree-head is countersigned by an independent witness.

Use this skill when the user wants to **manage their own secrets** with fd0. For the protocol model and trust guarantees, read `references/protocol.md`. For installing fd0 itself, read `references/install.md`.

## Decision tree

Map the user's intent to the right command before typing anything:

| User intent | Command |
|---|---|
| First-time setup on a fresh device | `fd0 init` then `fd0 unlock` |
| Store a credential | `fd0 secret set NAME VALUE [--scope LABEL]` |
| Retrieve a credential to stdout | `fd0 secret get NAME [--scope LABEL]` |
| Retrieve to clipboard, auto-clear | `fd0 secret copy NAME [--clear-after=30s]` |
| List secrets | `fd0 secret ls` (`--json` for machines) |
| Forget a credential | `fd0 secret rm NAME` (writes a tombstone; rotate leaked credentials externally) |
| Open the password-manager UI | `fd0 pass` (or `fd0 pass QUERY`) |
| Create a login item | `fd0 pass add NAME --url URL [--scope LABEL]` |
| Add username/password fields | `fd0 pass field set NAME username VALUE`; `fd0 pass field set NAME password --secret --generate` |
| Copy a password-manager field | `fd0 pass copy NAME [FIELD] [--clear-after=30s]` |
| Generate a password without storing | `fd0 pass generate [--length 32]` |
| Install Chrome autofill | Install fd0 from the Chrome Web Store; current fd0 installers register its local host automatically |
| Test Chrome autofill from a source checkout | Follow `browser/README.md`, then register with the built `fd0 browser enable --host PATH` |
| Show a pass item safely | `fd0 pass show NAME` (masked by default; `--reveal` only when explicitly needed) |
| Store a passkey field | `fd0 pass field set NAME passkey VALUE --type passkey` |
| Add or print TOTP | `fd0 pass totp add NAME 'otpauth://...'`; `fd0 pass totp code NAME` |
| Read or write an item's note | `fd0 pass notes NAME`; `fd0 pass notes set NAME [TEXT]`; `fd0 pass notes rm NAME` |
| Attach a small key/recovery file | `fd0 pass file add NAME PATH [FIELD]` (32 KiB max per file) |
| Export an attached file | `fd0 pass file export NAME FIELD --out PATH` |
| Organize related secrets | `fd0 scope create --label LABEL` |
| See your scopes, or who is in one | `fd0 scope ls`; `fd0 scope members [SCOPE]` |
| Rename a scope | `fd0 scope rename SCOPE NEW_LABEL` (label only; the scope id never changes) |
| Share a scope with a person | They run `fd0 card export`, you `fd0 card import URL --label THEIR_NAME --yes`, then `fd0 scope add-member THEIR_NAME --scope LABEL` |
| Revoke access | `fd0 scope remove-member LABEL --scope LABEL` (rotates the per-scope key — they lose access on next sync) |
| See or drop pinned identity cards | `fd0 card ls`; `fd0 card rm LABEL` (dropping a card does not revoke scope access — use `scope remove-member` for that) |
| Pull / push to server | `fd0 sync` |
| Confirm vault state | `fd0 doctor` (read-only check) |
| Check installed client flavor | `fd0 version` (`standard` or `yubikey`) |
| Install fd0 Desktop with its managed CLI and agent | `curl -fsSL https://fd0.sh/install \| sh -s -- --desktop` |
| Update fd0 Desktop, its CLI, and its agent | `fd0 update` (opens the Desktop updater) |
| Install YubiKey-capable client | `curl -fsSL https://fd0.sh/install \| sh -s -- --yubikey` |
| Switch a standalone CLI install to YubiKey flavor | `fd0 update --flavor=yubikey` then `fd0 agent restart` |
| Set this device's default unlock method | `fd0 auth default yubikey` or `fd0 auth default passphrase` |
| End the session | `fd0 lock` |
| Inspect or restart the agent | `fd0 agent status`; `fd0 agent restart`; `fd0 agent stop` |
| Add a second unlock method | `fd0 auth add` (passphrase) or `fd0 auth add --yubikey` |
| Generate an SSH key (ed25519, in-vault) | `fd0 key add NAME [--scope LABEL]` — prints the authorized_keys line |
| Import an existing SSH key | `fd0 key add NAME --import PATH` (encrypted RSA/ECDSA are refused — decrypt first) |
| Show a public key for authorized_keys | `fd0 key show NAME --pub` |
| Add an SSH host | `fd0 ssh add ALIAS [user@]host[:port] [--key NAME \| --with-key] [--jump ALIAS] [--tag T]` |
| Connect to a host | `fd0 ssh ALIAS` (or bare `fd0 ssh` for the fuzzy picker) |
| Browse remote files interactively | `fd0 sftp ALIAS` |
| List or inspect remote files | `fd0 sftp ls ALIAS [PATH] [--json]`; `fd0 sftp tree ALIAS [PATH] --depth N`; `fd0 sftp stat ALIAS PATH` |
| Upload a file or directory | `fd0 sftp cp ALIAS LOCAL remote:PATH [--recursive] [--force]` |
| Download a file or directory | `fd0 sftp cp ALIAS remote:PATH LOCAL [--recursive] [--force]` |
| Manage remote paths | `fd0 sftp mkdir ALIAS PATH`; `fd0 sftp mv ALIAS OLD NEW`; `fd0 sftp rm ALIAS PATH [--recursive --yes]` |
| One-time SSH setup | `fd0 ssh enable` + `export SSH_AUTH_SOCK="$(fd0 ssh sock)"` in your shell rc |
| Tag hosts without a full edit | `fd0 ssh tag ALIAS --add T --remove U` (`ssh edit --tag` replaces the whole list) |
| Store a Talos context | `fd0 talos add NAME --from-config ~/.talos/config` (or per-field `--ca-file/--crt-file/--key-file`) |
| Bootstrap a new Talos cluster (day-0) | `fd0 talos new NAME --endpoint https://IP:6443 [--vault-scope LABEL]` (needs `talosctl`) |
| Render + merge talosconfig | `fd0 talos sync --merge` |
| Onboard a teammate to a Talos cluster | `fd0 talos role-add --from CTX --name NAME --role os:operator` (needs `talosctl`) |
| Store / export the DR secrets.yaml | `fd0 talos secrets import\|export NAME --in\|--out FILE` |
| Store a kubeconfig | `fd0 kube add NAME --from-config ~/.kube/config` (or per-field `--server/--ca-file/...`) |
| Fetch a fresh kubeconfig from Talos | `fd0 talos kubeconfig CTX` (needs `talosctl`) |
| Render + merge kubeconfig | `fd0 kube sync --merge` |
| Merge kube/talos into the standard config on every sync | `fd0 kube enable --merge`; `fd0 talos enable --merge` (`disable` reverses it) |
| Change one field on any item | `fd0 <module> edit NAME --flag VALUE` — only what you pass changes (for `secret`, use `set`) |
| Rename any item | `fd0 <module> rename OLD NEW` |
| Move any item to another scope | `fd0 <module> move NAME --to-scope LABEL` |
| See an item's earlier versions | `fd0 <module> history NAME` (newest first) |
| Undo a bad change | `fd0 <module> history restore NAME SEQ` |

Every command except `fd0 sync` is local. `sync` is the only one that touches the network. The `pass`/`key`/`ssh`/`talos`/`kube` families all store their material as ordinary scope-shared secrets, so sharing a password item, SSH key, host alias, or talosconfig with a teammate is the same `scope add-member` flow.

`add` and `new` refuse an existing name by default. `--force` does not merge — it **replaces the record outright**, so every field the command did not pass goes back to its default. To change one field and leave the rest alone, use `<module> edit` instead. fd0 says so at both points: the duplicate error names the `edit` command, and a forced overwrite warns before it happens.

## One grammar for every module

`secret`, `pass`, `ssh`, `key`, `kube` and `talos` all take the same verbs, so knowing one module means knowing all of them:

```
fd0 <module> add NAME ...        create; refuses an existing name
fd0 <module> edit NAME --flag V  change only the fields you name
fd0 <module> show NAME           human-readable, secrets masked
fd0 <module> list                (aliases: ls)
fd0 <module> rename OLD NEW      rename in place
fd0 <module> move NAME --to-scope L
fd0 <module> rm NAME             tombstone
fd0 <module> history NAME        versions, newest first
fd0 <module> history restore NAME SEQ
```

One exception: **`secret` has no `edit`** — a plain secret is a single value, so `fd0 secret set NAME VALUE` is both the create and the update. Everything else in the list applies to it.

Which flags each `edit` accepts (all also take `--scope`):

| Module | Editable |
|---|---|
| `pass` | `--title`, `--url` (repeat; replaces the list) |
| `ssh` | `--hostname`, `--user`, `--port`, `--key`, `--jump`, `--description`, `--tag` (repeat; replaces), `--opt KEY=VALUE`, `--clear-opts` |
| `key` | `--comment` (key material and type are immutable) |
| `kube` | `--server`, `--namespace`, `--description`, `--tag` (repeat; replaces) |
| `talos` | `--endpoint`, `--node` (both repeat; replace), `--role`, `--description`, `--tag` |

Credentials are deliberately not editable: `kube edit` cannot touch the CA, client cert/key or token, and `talos edit` cannot touch the CA/crt/key. Replace those by re-importing with `add --force`.

To change a pass item's fields rather than its title or URLs, use `pass field set|rm`, `pass notes`, `pass section add`, `pass totp add` and `pass file add`.

`list` takes `--json` on every module, with the same key style throughout (`name`, `scope`, `scopeId`, …) and `[]` rather than `null` when empty. Secret material is never included — `key list --json` carries the fingerprint and the authorized_keys line, never the private half.

Plain secrets are `fd0 secret ...`. The older top-level spellings (`fd0 get`, `fd0 set`, `fd0 rm`, `fd0 ls`, `fd0 copy`) still work and always will, but no longer appear in `--help`; prefer the `secret` form in anything you write down.

Each module owns its own records. `fd0 secret ls` lists plain secrets only (`--all` includes the rest), and the secret commands refuse a name belonging to another module rather than acting on it:

```
$ fd0 secret rm host:prod
✗ "host:prod" is a host, not a plain secret
  use: fd0 ssh rm prod
```

Two properties worth relying on:

- **`edit` is a patch, `add --force` is a replace.** `edit --port 2222` leaves tags, description and key binding alone. Passing an empty value clears that one field (`--jump ""`), which is why "not given" and "set to empty" are different things. An edit that changes nothing writes nothing, so it does not burn a revision.
- **Restore writes forward.** `history restore` adds a new version carrying the old content rather than rewinding the chain, so the history stays append-only and the restore is itself auditable.

Module-specific commands sit alongside these, not instead of them: `pass field/notes/totp/file`, `ssh connect/tag`, `kube sync`, `talos secrets`.

For remote file browsing and transfer, read `references/sftp.md` before
constructing commands. It defines the `remote:` operand, overwrite/delete
confirmations, JSON use, and the boundary between fd0-managed SSH access and
remote authorization.

## Mental model

Three layers, in order of trust:

1. **Identity** — `super_priv` is the root ed25519 key. It lives mlocked inside `fd0-agent` once `fd0 unlock` runs and is wiped from memory on `fd0 lock` or `agent idle-timeout`. Loss of `super_priv` is permanent unless the user exported recovery (see Recovery below).
2. **Scopes** — Named containers (`work`, `personal`, etc). Each scope has an Object Encryption Key (OEK) that encrypts every secret in that scope. Members of a scope hold the OEK wrapped to their own card.
3. **Secrets** — Encrypted under the scope's current OEK. The server only sees ciphertext + signed metadata.

Adding a member wraps the OEK to their card. Removing a member rotates the OEK so future secrets in that scope are unreadable by them. This is **cryptographic** revocation, not policy. They cannot read what comes after `remove-member`, full stop.

## First-time setup

```
fd0 init            # generate identity, set passphrase (TWO entries — confirmation)
fd0 unlock          # decrypts the vault, spawns the agent, holds super_priv mlocked
fd0 sync            # registers identity with the configured server
```

Defaults: client targets the single primary `https://api.fd0.sh` (the hosted instance; `api2.fd0.sh` is a server-side DR backup, not a second client target). Every write and read for every scope goes to that one primary. To self-host, the user edits `~/.fd0/config.toml` before `fd0 sync`:

```toml
[sync]
server = "https://your-server.example"
```

The first sync triggers a TOFU pin: fd0 prints a 12-group fingerprint, the user verifies it out of band, and types `y`. Subsequent syncs short-circuit. **Never bypass this** unattended with `FD0_AUTO_PIN=1` unless the user has explicitly accepted the risk for a scripted context.

## Default unlock method

Use `fd0 auth default METHOD` when a device should prefer one unlock method without a shell alias:

```
fd0 auth ls
fd0 auth default yubikey      # or passphrase, or a method_id from auth ls
fd0 auth default              # show the current device default
fd0 auth default --clear      # return to fd0's built-in selection
```

The setting is local to the current device in `~/.fd0/config.toml` under `[auth].default_method`. It is not synced, does not add or remove auth methods, and does not change vault wraps. `fd0 unlock --method=...` still overrides the local default for that invocation. Without either setting, interactive unlocks ask which enrolled method to use; non-interactive calls keep a deterministic fallback.

## Storing and fetching

```
fd0 scope create --label work
fd0 secret set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx" --scope work
fd0 secret set DB_PASSWORD - --scope work   # `-` (positional, not a flag) reads VALUE from stdin
                                            # — hides the secret from shell history and from `ps`
fd0 secret get DEPLOY_KEY --scope work      # plaintext to stdout
fd0 secret copy DEPLOY_KEY --clear-after=30s # clipboard, auto-cleared
fd0 secret ls                               # names across all scopes
fd0 sync                                     # push the new event(s)
```

Without `--scope`, fd0 looks up the secret across all scopes. If the name exists in exactly one scope it succeeds; if it is ambiguous it errors.

When fetching for a non-interactive context (e.g. CI script substitution, automation), prefer `fd0 secret get NAME --raw` — `--raw` strips trailing newlines that would otherwise pollute environment-variable assignments.

## Password manager

`fd0 pass` is the structured password-manager surface. It stores each item as a typed, scope-shared secret (`fd0.pass.item`) with:

- item title and URL matchers
- fields of type `text`, `secret`, `totp`, `passkey`, `file`, or `section`
- recursive sections by slash path, up to four levels deep
- encrypted per-item metadata, including optional organization tags
- small encrypted file attachments, capped at 32 KiB per file and 60 KiB per item

Bare `fd0 pass` opens the interactive terminal browser. `fd0 pass QUERY` opens the same browser with an initial search. In the browser, secrets are masked by default; use the visible shortcuts for copy/reveal. `q` and `esc` quit/back out.

Common interactive flow:

```
fd0 pass                          # browse all pass items
fd0 pass github                   # browse with initial query
fd0 pass --scope work             # browse one scope
```

Common scriptable flow:

```
fd0 pass add github --url https://github.com --scope work
fd0 pass field set github username valentin@example.com --scope work
fd0 pass field set github password --secret --generate --length 32 --scope work
fd0 pass field set github passkey '{"credential_id":"..."}' --type passkey --scope work
fd0 pass totp add github 'otpauth://totp/GitHub:valentin@example.com?secret=...' --scope work
fd0 pass section add github Recovery --scope work
fd0 pass field set github Recovery/code-1 "1234-5678" --secret --scope work
fd0 pass file add github ~/.ssh/recovery-key.pem SSH/recovery-key.pem --scope work
fd0 sync
```

Read and copy:

```
fd0 pass list --scope work
fd0 pass find github
fd0 pass find --url https://github.com/login
fd0 pass show github                  # masked by default
fd0 pass show github --reveal         # only when the user explicitly asks
fd0 pass copy github                  # copies preferred secret field: password/pass
fd0 pass copy github username
fd0 pass totp code github
fd0 pass field get github username --raw
fd0 pass file export github SSH/recovery-key.pem --out ./recovery-key.pem
```

Use `fd0 pass field set NAME PATH - --secret` for values that should not appear in shell history. A pass item is shared by sharing its scope; there is no separate per-item ACL. For browser/autofill-style lookup, use `fd0 pass find --url URL --json` and then retrieve the needed field explicitly.

### Password tags

Tags organize password items without changing permissions or URL matching.
They are encrypted in the item and sync with it. Desktop accepts free text and
suggests tags already used in the selected vault. Tags ignore capitalization,
allow spaces, and are limited to 32 per item and 64 characters per tag.

```sh
fd0 pass add github --scope work --tag Development --tag "Team A"
fd0 pass tags add github Server --scope work
fd0 pass tags rm github "Team A" --scope work
fd0 pass tags clear github --scope work
fd0 pass tags list --scope work --json
fd0 pass list --scope work --tag Development --tag Server
fd0 pass find github --scope work --tag Development
fd0 pass browse --scope work --tag Development
fd0 pass list --scope work --untagged
```

Repeated filters require **all** tags. Do not combine `--tag` and `--untagged`.
`tags list` returns existing tags and item counts grouped by scope; JSON rows
contain `scopeId`, `scope`, `tag`, and `count`. `pass show` and list/find JSON
include item tags. Default list/find columns are unchanged. Adding an existing
tag or removing an absent tag does not create a new revision. Use explicit
`--scope` when an item name could refer to multiple scopes.

## Browser autofill

The fd0 Chrome extension is published at
`https://chromewebstore.google.com/detail/fd0/kcbjlgbkgoabcdflpnohkknfbegcigel`
for Chrome and Chromium on macOS and Linux. Install fd0 Desktop or the CLI
first; current installers register the matching local Native Messaging host.
For an older install, run `fd0 browser enable` once. Source builds and unpacked
development instructions live in `browser/README.md`.

The extension lists matching item titles and usernames for the concrete HTTPS
frame, reveals a password only after explicit selection, checks origin and
document again, and never submits the form. It also supports password
generation, explicit save/revision-bound update, pasted `otpauth://` setup
links, and TOTP fill after a recent selection. Submitted candidates are held
only in browser session memory for up to 60 seconds. HTTP pages and Firefox are
not supported yet.

Remove only the Native Messaging registration with:

```sh
fd0 browser disable
```

## Sharing a scope

The card-exchange flow has three steps. The two humans must verify safety numbers out of band — fd0 prints them to stderr.

**Alice creates a scope and writes some secrets** (her side):
```
fd0 scope create --label deploy
fd0 secret set GITHUB_TOKEN "ghp_..." --scope deploy
fd0 sync
```

**Both sides exchange cards** (each side runs `card export`, sends the URL to the other side, the other side imports):
```
alice$ fd0 card export                       # prints fd0://card/...  (safety number to stderr)
bob$   fd0 card export                       # same

# Each verifies the OTHER side's safety number out of band (Signal, in person, video call).
# Then pins:
alice$ fd0 card import "fd0://card/..." --label bob   --yes
bob$   fd0 card import "fd0://card/..." --label alice --yes
```

**Alice adds bob to the scope**:
```
alice$ fd0 scope add-member bob --scope deploy
alice$ fd0 sync
```

**Bob discovers the scope on his next sync** — he can now read every secret Alice has stored in `deploy`, including any she sets later, until she removes him.

## Revoking access

```
alice$ fd0 scope remove-member bob --scope deploy
alice$ fd0 sync
```

This generates a new OEK for the `deploy` scope, wrapped to every remaining member but NOT to bob. Any secret Alice writes AFTER this point is unreadable by bob even if he intercepts the ciphertext. Bob's local client drops the scope on his next sync.

Bob still has whatever he downloaded BEFORE the rotation. Treat anything he saw as compromised and rotate the underlying credentials (the actual GitHub token, the actual database password) out-of-band.

## Recovery

`super_priv` is the root of the user's identity. Lose it and they cannot decrypt anything they wrote, even with the passphrase. fd0 ships a recovery export that is encrypted under a separate recovery passphrase:

```
fd0 recovery export ~/fd0-recovery.cbor       # encrypted; ask twice for a new passphrase
# Store ~/fd0-recovery.cbor offline: paper QR, encrypted USB, password manager.
```

To restore on a fresh device:

```
fd0 recovery import ~/fd0-recovery.cbor
fd0 unlock
fd0 sync                                       # auto-discovers every scope the identity is in
```

When the user is about to do anything destructive — `fd0 auth rm`, `fd0 init` over an existing home, switching devices — recommend `fd0 recovery export` first if they have not done it.

## Diagnostics

When something looks off, run **`fd0 doctor`** first. It is read-only and reports:

- Replay of the user chain and every scope chain
- `auth_tip` and per-scope `chain_tip` against the on-disk events
- Auth methods vs vault wraps (no orphans either way)
- fd0/fd0-agent release flavor and YubiKey/PIV capability
- Witness cross-check policy if configured

A `doctor` failure points at a specific check; treat its message as the entry point to the problem rather than guessing.

## YubiKey unlock

YubiKey/PIV unlock is supported by the official `yubikey` client flavor. Do **not** tell normal users to build from the repo unless they are explicitly doing development work.

Check the installed flavor first:

```
fd0 version          # fd0 X.Y.Z standard OR fd0 X.Y.Z yubikey
fd0 doctor           # reports fd0/fd0-agent capability and mismatches
```

Install or switch to the YubiKey flavor:

```
curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
# or, for an existing install:
fd0 update --flavor=yubikey
fd0 agent restart
```

Both `fd0` and `fd0-agent` must be the `yubikey` flavor. If `fd0 doctor` reports a mismatch after update, restart the agent before retrying enrollment or unlock.

After enrolling a YubiKey, suggest `fd0 auth default yubikey` only if the user wants plain `fd0 unlock` on that device to use the YubiKey. Keep passphrase unlock enrolled as recovery unless the user has a tested recovery export and explicitly accepts the risk.

## Security rules

These are not negotiable. The skill is useless and dangerous without them.

1. **Never** echo, log, store-in-variable, or paste-to-clipboard a passphrase. Pipe through stdin (`printf '%s\n' "$pass" | fd0 ...`) only in trusted scripts that the user explicitly authored. Important: fd0 has **no `--stdin` flag** — it reads from stdin automatically when stdin is not a TTY. Do not invent `fd0 unlock --stdin` or similar; the pipe alone is the contract.
2. **Never** set `FD0_AUTO_PIN=1` without the user's explicit consent. The TOFU prompt exists so a MITM cannot silently pin its own key.
3. **Never** dump `~/.fd0/vault.enc` or `~/.fd0/chains/` to a remote location for "debugging" — they contain ciphertext but their existence + size + chain tip is metadata.
4. When `fd0 secret copy` runs, mention the auto-clear time (`--clear-after`) so the user does not assume the clipboard is permanent.
5. Prefer `fd0 pass copy` over `fd0 pass show --reveal` for passwords/TOTP/secrets. Use `--reveal`, `pass field get`, or `pass file export` only when plaintext output is explicitly needed and keep it out of logs.
6. Confirm before `fd0 rm`, `fd0 pass rm`, `fd0 pass field rm`, `fd0 scope leave`, `fd0 auth rm`, and `fd0 recovery import` — each one is destructive or irreversible without a backup.
7. When the user has not run `fd0 recovery export`, prompt them to do it before any operation that could lose `super_priv` (re-init, device migration, `auth rm` of the last method).
8. Treat `fd0 sftp rm`, overwriting transfers (`--force`), and remote renames as remote mutations. Confirm the exact host and path before destructive operations; non-interactive recursive delete additionally requires `--recursive --yes`.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `not unlocked` / `agent not running` | No active agent | `fd0 unlock` |
| `another fd0 instance holds the lock` | The agent's background auto-sync (or another fd0) holds the flock; the client already waits ~5s before failing | Usually transient — just retry. If it persists, make sure no other fd0 is running: `ps aux \| grep fd0-agent`, kill a stale PID, then retry |
| `fd0 SSH agent socket unavailable` / `Connection refused` from `ssh-add -L` | fd0-agent is running but its SSH-agent listener is stale or was started with the wrong socket path | Run `fd0 agent restart`. |
| `standard flavor (YubiKey/PIV disabled)` while enrolling YubiKey | Installed client is the standard release flavor | Run `fd0 update --flavor=yubikey`, then `fd0 agent restart` |
| YubiKey unlock says running agent lacks support | `fd0` was updated but old `fd0-agent` is still running | Run `fd0 agent restart`; then check `fd0 doctor` |
| An update flag “cannot be used with fd0 Desktop” | Desktop updates the signed app, CLI, and agent as one bundle | Run plain `fd0 update`; choose explicit versions or flavors only on standalone CLI installations |
| `429 Too Many Requests` on register | Per-IP rate limit | Retry after the `retry-after` seconds; do not loop |
| `pinned-key-mismatch` on sync | Server's translog key rotated, or MITM | STOP. Verify the new fingerprint out-of-band BEFORE re-pinning. `~/.fd0/config.toml` does not need editing — fd0 walks through the ceremony |
| `witness cross-check failed` | Witness disagrees with server | STOP. Possible equivocation. Open an issue with the server operator |
| `no server configured` | No `[sync].server` set, no `FD0_SERVER` env, defaults disabled somehow | Add `[sync].server = "URL"` or pass `--server URL` |
| Sync says `pushed=0 dup=0` repeatedly | No local events to push | Normal — sync still pulls. Use `fd0 doctor` to confirm local state is sane |

## When to read the reference files

- **`references/protocol.md`** — Before answering questions about what the server can/cannot see, why removing a member actually revokes access, how the transparency log works, or what "ciphertext-only contract" means. Also before discussing trust assumptions for self-hosting vs hosted.
- **`references/install.md`** — When the user wants to install or update fd0 itself, or wants to install this skill in a different setup. Includes `bunx skills add` and manual paths.
- **`references/sftp.md`** — Before browsing, uploading, downloading, renaming, or deleting files on an fd0 SSH host.

## When NOT to use this skill

- The user is operating the **fd0 server** (`fd0-server`, `fd0-witness`) — refer them to `docs/HOSTING.md` instead.
- The user is asking about the **fd0 source code** or wire protocol internals — refer to `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/TRANSLOG.md`.
- The user wants a different secrets manager (Bitwarden, 1Password, Vault) — do not pitch fd0; just help with what they asked.
