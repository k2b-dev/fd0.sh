# Services plan

Status: phase 1 implemented 2026-10-01, phase 2 implemented 2026-10-02; phase 3 planned (draft for review, 2026-10-03), not implemented.

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

## Phase 3: approved consumers, deploy and check

Only after phase 1 has proven itself. Deploying means the admin's SSH and cluster credentials write values onto systems, so targets must be trusted, not just listed.

- **Consumers** reference fd0 host and kube records by record ID. Modes:
  - `managed`: deploy and check.
  - `bootstrap`: create when missing, never overwrite, not checked (values renewed elsewhere, e.g. in-cluster certificate renewal).
  - `manual`: documentation only (settings set through an application API or another tool). `show` lists them in the rotation checklist.
  - Embedded uses (a credential inside a larger, validated config such as `named.conf` or `patroni.yml`) stay with their own tooling, which reads the value via `get --raw` or a rendered template on stdout.
- **Approval:** a consumer is used only after a per-device approval with fresh authentication, like SSH grants. The approval pins the target record IDs, the SSH host-key fingerprints or the kube server URL and CA hash, the destination path, owner and mode. `deploy` refuses new or changed targets and shows the difference. This stops a scope member or an agent from redirecting a deploy.
- **Hosts:** see the implementation plan below (SFTP, atomic rename, no sudo in the first cut).
- **Kubernetes:** see the implementation plan below (verified TLS, ID-based ownership, conditional writes).
- **Order and partial failure:** consumers deploy in their listed order and stop at the first failure; `show` lists which consumers have the current field revision. A device that is not synced to the latest revision refuses to deploy, so an old value cannot overwrite a newer rotation.
- **Check:** reads the delivered bytes back into fd0's memory over the same SSH channel or the Kubernetes API and compares them in constant time. Results are `ok`, `drift` or `missing`; no hashes or values are printed. This means values travel back to the admin device, which already holds them.

### Phase 3 implementation plan (draft 2026-10-03, revised after design review)

**Smallest useful cut.** `managed` consumers of two kinds, `host-file` and `k8s-secret`, with `approve`, `deploy` and `check`. Not in the first cut: `bootstrap`, `manual`, reload commands, sudo, tunnel overrides, templates for embedded configs, machine-side pulls (those use `fd0 run` or machine identities).

**Compatibility first.** Clients up to 0.20 drop unknown service fields when they save, so they would silently erase consumers. Step 0 ships before any consumer exists: a service payload version, preservation of unknown fields on every save and restore, and refusal to save a payload from a newer version. Consumers are only accepted in scopes after the documentation tells writers to update.

**Model.** Consumers are part of the service payload, so every scope member sees where a value is used:

```
consumer = {
  id      : "c_…",                        ; stable, generated
  kind    : "host-file" / "k8s-secret",
  mode    : "managed",
  mapping : [FIELD=OUTPUT_KEY, …],         ; explicit, never a default
  ; host-file
  host    : host record ID, path, mode (e.g. "0600"),
            format : "systemd-env" / "docker-env" / "sh" / "file",   ; file = exactly one file field
  ; k8s-secret
  kube    : kube record ID (its context), namespace, secret name,
}
```

Host records gain an optional `deploy_prefixes` list. A destination must lie under one of them, compared by path components after resolving the existing parent directories without following symlinks. Approvals and deploy results are device-local vault fields next to `ssh_grants`, not synced.

**Approval pins the resolved destination, not just IDs.** `fd0 service approve NAME` shows and pins, per consumer: scope, service record and consumer IDs; the mapping and format; for hosts the resolved connection (hostname, port, user, jump hosts, client key identity) and the server keys from the trusted `known_hosts` (never `ssh-keyscan` alone); for clusters the server URL, the CA bundle hash and the TLS settings. Value rotations need no new approval; any change to these pinned parts makes `deploy` and `check` refuse and print the difference. The connection is built from the approved specification, not re-resolved from records.

**Deploy.**

- Freshness: `deploy` syncs all involved scopes against the primary immediately before it prepares, and records which signed service event it delivers. This narrows but cannot remove the race between two devices deploying different revisions at the same moment; the docs say so, and the approver should be one device per service.
- Hosts: delivery over SFTP with fd0's own SSH configuration (no remote shell), into an exclusively created temporary file in the destination directory, then an atomic rename. The SSH user must own or be allowed to write the destination directory; there is no sudo in the first cut. Owner and group are those of the SSH user; only the mode is set.
- Kubernetes: HTTPS with certificate and hostname verification is required; a kubeconfig with `insecure-skip-tls-verify` or HTTP cannot be approved. fd0 owns the whole Secret, identified by annotations with scope, record and consumer IDs and the field manager `fd0-<consumer id>`. A missing Secret is created with create-only semantics; an existing one is updated only if its annotations match and with its observed `resourceVersion`, otherwise deploy fails. Type must be Opaque. Only the selected kube record's own config is used, never a merged user config.
- Output: structured, bounded results per consumer. fd0 never forwards raw `kubectl`, API or SSH output, because error bodies can echo values. `--dry-run` is local: approved targets, mapping, the service event to deliver; nothing is sent.

**Check** reads only the mapped outputs back over the approved connection and compares them in constant time: `ok`, `drift`, `missing`, or a distinct transport, authorization or validation error. Target-side logging is the operator's responsibility; the docs name Kubernetes audit logging of Secret bodies and SSH session logging as things to review.

**Roles.** Consumers are edited by writers and admins like values. `approve`, `deploy` and `check` need only read access in fd0; the remote permissions come from the referenced SSH and kube credentials, which may themselves be shared in the scope. Approval stops a scope member from redirecting this device's deploys; it is not protection against code running as the same OS user.

**Implementation steps** (each with tests and a Codex review): 0) payload version and unknown-field preservation, shipped in a release first; 1) consumer model, CLI editing, `show`; 2) approvals with fresh authentication; 3) `host-file` deploy and check against a local SSH test server; 4) `k8s-secret` deploy and check against a Kubernetes API test double; 5) docs, skill and a read-only Desktop list.

**Open questions for Valentin.**

1. Reload after deploy (for example `systemctl restart app`): leave out of the first cut and print the next step? Recommended: yes.
2. Device-local deploy results (recommended) or a synced rollout state per consumer, which means every deploy writes an event?
3. Is "the SSH user writes the destination directory, no sudo" workable for your hosts, or do you need a narrowly defined privileged step soon?

## Verification plan

- Unit tests: field types and env names, change stamps and restore, size limit, env dialect escaping, Secret manifest labels.
- In-process vault tests for every command, including stdin-before-lock, empty stdin, refusal of positional secrets, terminal refusal, and the full kind wiring (`TestEditHintCoversEveryKind`).
- Compatibility test: an older client's plain secret commands cannot reach a service once the guard ships.
- Phase 3: guarded integration tests against a local SSH test server and a Kubernetes API test double, covering approval pinning, path allowlist, takeover refusal, ordered stop on failure and drift detection. No test touches production or the installed client.
