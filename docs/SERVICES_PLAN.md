# Services plan

Status: phase 1 implemented 2026-10-01, phase 2 implemented 2026-10-02, phase 3 (deploy recipes) implemented 2026-10-04.

## Outcome and scope

Add a `service` item kind next to `pass`, `ssh`, `key`, `kube` and `talos`. A service holds the credentials and related settings that software consumes (database passwords, API tokens, TSIG keys, NATS creds) and records where they are used and when they changed. fd0 stays on the admin device. It renders values for the operator's pipelines and, in a later phase, pushes them to approved consumers. Nothing is installed on servers or clusters.

The boundary to existing kinds: `pass` is for logins people use (URLs, TOTP, autofill); `service` is for values programs read; plain `secret` stays for single standalone values. Existing records are not converted by fd0; an agent moves them once with the normal commands, piping values so they never appear in its output.

Not in scope: an import or migration command, an in-cluster operator, dynamic or server-generated credentials, rotation against third-party systems, reloading consumers, and storing values anywhere but the vault and their consumers.

## Model

One typed record `service:NAME` in a scope, payload `fd0.service`, encrypted like every other item. No server or protocol change: name, type and payload are inside the encrypted body.

```text
service pg-1                      tags: postgres
  fields
    postgres-password      secret  env POSTGRES_PASSWORD        changed 2026-08-12
    replication-password   secret  env PG_REPLICATION_PASSWORD  changed 2026-08-12
    runtime.creds          file                                 changed 2026-09-03
    host                   text    env PGHOST
  consumers (phase 3)
    pg-1-db-1  /etc/pg-1/credentials.env  systemd-env  managed
    k8s-1      org-kolb-antik-cloud/cloud-runtime  postgres-password -> DATABASE_PASSWORD  managed
    rsql-1-tls (k8s Secret renewed in-cluster)                                             bootstrap
    Cloud admin setting assistant.rsql_api_token                                           manual
```

- **Fields:** one list, types `secret`, `text`, `file`, reusing the pass field types and validators. The type is set at creation and kept on every update. Optional env name (validated `[A-Z_][A-Z0-9_]*`) and note.
- **Change stamp and revision:** each field carries `changedAt` and a field revision, set by fd0 on every value change. History restore writes a new revision with a new stamp, so a restored old value is visible as a change.
- **Tags:** the existing scope-level organization tags, not payload data.
- **Size:** checked on the client against the server's 64 KB limit for an encrypted record, so a service never commits locally and then fails on push.

## Phase 1: service records and pipes

```sh
fd0 service add|list|show|edit|rename|move|rm|history NAME ...
fd0 service set NAME FIELD - [--type secret|text|file] [--env NAME]   # value only from stdin
fd0 service set NAME --env-file -                                     # KEY=VALUE lines -> secret fields
fd0 service get NAME FIELD --raw
fd0 service env NAME --format systemd-env|docker-env|sh [--fields a,b]
fd0 service k8s-secret NAME --namespace NS --name SECRET [--fields a=KEY,...]
```

- Secret values are never accepted as arguments. Stdin is read, bounded, before the vault lock; empty input is rejected.
- `env` has explicit dialects because systemd, Docker and shell parse differently. Each dialect escapes or rejects values it cannot represent safely.
- `k8s-secret` prints an Opaque Secret with the label `fd0.sh/service=NAME` for `kubectl apply --server-side --field-manager=fd0-NAME -f -`. The operator chooses the cluster and the access path (tunnel, context); fd0 does not run kubectl in this phase.
- Rendering commands refuse to write to a terminal. This prevents accidental exposure only; any process that can run these commands with an unlocked vault can read the values. Agents are value-free only when they use a restricted organization grant.
- Desktop: read-only list and detail view.

Implementation notes from the code review: a new kind must be wired into every per-kind switch, not just the `itemKinds` registry (organization listing and tags, rename retitle, move, history and rm dispatch in `cmd/fd0/main.go`, `TestEditHintCoversEveryKind`, and in the Desktop bridge `moveItemKind`, inventory summaries and detail fields, plus `ItemKind`/rail kinds in the renderer).

Compatibility: clients before this release do not know the `service:` prefix and would treat services as plain secrets (list, print the payload, delete). The release that introduces services first ships the prefix guard; documentation tells shared-scope users to update before services are created in that scope.

## Phase 2: `fd0 run`

`fd0 run --service NAME [--field F ...] -- COMMAND ...` replaces fd0 with the command (exec), adding the selected env-named fields to its environment, so the exit status and signals are the command's own. The usual caveat applies: the environment is readable by the same user and inherited by child processes.

## Phase 3: deploy recipes (implemented 2026-10-04)

Phase 3 is convenience on top of phase 2: everything could be done with `fd0 run` and pipes, but the commands then live in READMEs and shell history. A recipe saves such a command next to its service, so every device and member can repeat it, and each device decides once whether it runs it. fd0 stays a general utility: where values go, with which rights and tools, and what happens before or after, is the recipe author's command, not fd0 logic. An earlier draft with built-in SFTP and Kubernetes consumers was dropped after review because it grew special happy paths.

**Model.**

- A recipe is its own record `recipe:SERVICE/NAME` in the service's scope, separate from the service so editing a recipe never competes with rotating a value. Payload: schema version, service name, command (argv; program is an absolute path or `~/…`), optional working directory, explicit field selection `FIELD[=NAME]`, input mode, optional target list, description. Unknown fields and newer versions are refused, never partly run.
- Input is exactly one of: `env` (environment variables, like `fd0 run`) or stdin in an existing format (`systemd-env`, `docker-env`, `sh`, `file` for one field, `k8s-secret:NAMESPACE/SECRET`). fd0 never puts values into argv. A recipe with targets runs once per target with `$FD0_TARGET`; `$FD0_SERVICE` and `$FD0_RECIPE` are always set.
- Before-steps, after-steps and checks are part of the command (for example an inline `/bin/sh -c '…'`), so they are covered by the approval instead of being a pipeline engine in fd0.

**Approval.** `fd0 recipe approve` shows the definition and needs fresh authentication in a terminal. The agent stores the approval in the device's vault (`recipe_approvals`, bound to the device ID, preserved across every vault write like SSH grants). It pins a digest of scope, name, version, service, command, working directory, fields, input and targets; the description is not pinned. Any change requires a new approval; value rotations do not. Approving means: this device may run exactly this command as the current OS user with the selected values. It does not sandbox the command, does not cover local scripts or tool configuration the command uses, and grants no locked access. Recipes never run on sync, unlock or rotation, and organization grants cannot approve or run them.

**Deploy.** `fd0 service deploy SERVICE[/NAME] [--target T] [-v]` syncs first and stops if that fails, freezes the service values, releases the vault lock, then runs the selected approved recipes in name order and each target in list order, without a terminal, and stops at the first failure. Command output is discarded unless `--verbose`, because it can contain values. fd0 reports "command succeeded", not that a value is active.

**Results.** Each device writes one record per recipe target, `deploy:SERVICE/NAME/TARGET/DEVICE`, with status, exit code, time, host name, the recipe digest and the delivered service event, then syncs. Only that device writes its records, so results from several devices never conflict. Readers can approve and deploy but cannot publish results. `fd0 recipe show` lists the latest result per target and device. Results never contain values.

**Operating lesson (2026-10-05).** In the first real recipe, a tunnel helper ran `ssh` before `kubectl` read the value; `ssh` consumed stdin and an empty Secret was written to one target before the run stopped. Recipes that start other programs first must read the value up front and refuse an empty one; the skill and website say so. A later improvement could deliver stdin input on a separate file descriptor instead.

**Limits.** Two devices deploying different revisions at the same moment can still race; the destination or one deploying device per target must serialize. fd0 cannot know whether a command used the values safely. Clients before 0.21 do not know recipes: they hide them from `service` commands but can list or delete them as plain secrets, so update every device of a scope before adding recipes there. Desktop hides recipes and results in this version.

## Verification plan

- Unit tests: field types and env names, change stamps and restore, size limit, env dialect escaping, Secret manifest labels.
- In-process vault tests for every command, including stdin-before-lock, empty stdin, refusal of positional secrets, terminal refusal, and the full kind wiring (`TestEditHintCoversEveryKind`).
- Compatibility test: an older client's plain secret commands cannot reach a service once the guard ships.
- Phase 3: `internal/recipe` unit tests (validation, digest, rendering), an in-process CLI and agent test (approval, deploy per target, rotation, re-approval, failure stop, env input, revocation, guards) and the guarded integration `tests/integration_recipes.sh` (two identities, synced results, reader deploy, re-approval). No test touches production or the installed client.
