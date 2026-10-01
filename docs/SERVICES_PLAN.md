# Services plan

Status: draft for review, 2026-10-01. Revised after code, security and use-case reviews. Not implemented.

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

`fd0 run --service NAME [--fields a,b] -- COMMAND ...` starts the command with the selected fields as environment variables and returns its exit status. The usual caveat applies: the environment is readable by the same user and inherited by child processes.

## Phase 3: approved consumers, deploy and check

Only after phase 1 has proven itself. Deploying means the admin's SSH and cluster credentials write values onto systems, so targets must be trusted, not just listed.

- **Consumers** reference fd0 host and kube records by record ID. Modes:
  - `managed`: deploy and check.
  - `bootstrap`: create when missing, never overwrite, not checked (values renewed elsewhere, e.g. in-cluster certificate renewal).
  - `manual`: documentation only (settings set through an application API or another tool). `show` lists them in the rotation checklist.
  - Embedded uses (a credential inside a larger, validated config such as `named.conf` or `patroni.yml`) stay with their own tooling, which reads the value via `get --raw` or a rendered template on stdout.
- **Approval:** a consumer is used only after a per-device approval with fresh authentication, like SSH grants. The approval pins the target record IDs, the SSH host-key fingerprints or the kube server URL and CA hash, the destination path, owner and mode. `deploy` refuses new or changed targets and shows the difference. This stops a scope member or an agent from redirecting a deploy.
- **Hosts:** destination paths must fall under a prefix allowed on the host record, are absolute without `..`, and are passed as arguments, not shell text. One SSH subprocess per host (not `exec`), fd0's own SSH config with `ControlPath=none`, no TTY. Content goes over stdin into a temporary file created with umask 077 next to the destination and is moved into place with the approved owner and mode; failure removes it in the same session. Requires `sudo -n` for exactly that operation; sudo I/O logging on the target would record the value and must be off for it.
- **Kubernetes:** `kubectl apply --server-side --field-manager=fd0-NAME`, kubeconfig for the one approved cluster passed through a file descriptor, never `--force-conflicts`. fd0 refuses to take over Secrets it does not label, non-Opaque types and protected namespaces. A tunnel endpoint may replace the server URL only with the same pinned CA.
- **Order and partial failure:** consumers deploy in their listed order and stop at the first failure; `show` lists which consumers have the current field revision. A device that is not synced to the latest revision refuses to deploy, so an old value cannot overwrite a newer rotation.
- **Check:** reads the delivered bytes back into fd0's memory over the same SSH channel or the Kubernetes API and compares them in constant time. Results are `ok`, `drift` or `missing`; no hashes or values are printed. This means values travel back to the admin device, which already holds them.

## Verification plan

- Unit tests: field types and env names, change stamps and restore, size limit, env dialect escaping, Secret manifest labels.
- In-process vault tests for every command, including stdin-before-lock, empty stdin, refusal of positional secrets, terminal refusal, and the full kind wiring (`TestEditHintCoversEveryKind`).
- Compatibility test: an older client's plain secret commands cannot reach a service once the guard ships.
- Phase 3: guarded integration tests against a local SSH test server and a Kubernetes API test double, covering approval pinning, path allowlist, takeover refusal, ordered stop on failure and drift detection. No test touches production or the installed client.
