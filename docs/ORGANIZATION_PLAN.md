# Organizing fd0 without exposing secret values

Status: released as CLI 0.16.0 and Desktop 0.6.0 on 2026-09-10. The production installation and user vault were not changed.

## Accepted outcome

Cross-type free-text tags, comfortable CLI operations, safe resumable cross-scope moves, and a metadata-only tool connection for an AI agent. The user reviews concrete changes once; changes must reject stale input. The repository fd0 skill must explain real commands, permissions, failure recovery, and limitations. There is no automatic 1Password importer.

## Implementation decisions

- Passwords, SSH hosts, Kubernetes and Talos retain their native tags. Infrastructure tag matching remains case-sensitive and host tags cannot contain commas because they are exported as CSV comments.
- Plain secrets and SSH keys use string fields `item.tags.<secret ID>` containing JSON arrays in the existing encrypted `_meta` scope record. Existing writers merge unknown metadata fields. Normal old content edits therefore preserve the extra tags. Historical old move/rename commands do not transfer these supplemental tags; use the new version for organization operations. Test this boundary and document it explicitly.
- Normal writes preserve SecretRecord schema version and unknown record tags. Move/rename/restore copy appropriate metadata instead of resetting it.
- The shared organization inventory is an explicit allowlist: ID, name/title, type, scope, tags, revision, reference names. It never reuses the Desktop inventory's subtitle/searchText or item detail (which may contain values).
- A dedicated stdio tool server is the restricted interface. The user starts it with explicit source/destination scope permissions and TTL. The model gets only those tools, with no general shell, file, browser, ordinary fd0 socket or other credential-bearing access. This is a deployment prerequisite, not something a CLI output flag can enforce. Test the full exposed operation surface against canary secrets.
- User approval is outside the model's tool surface. A proposal is immutable, bound to the session and exact revisions. A local trusted command shows and approves its digest. The model may execute only that approved proposal. Session expiry, revocation, or a different unlock epoch invalidates it. Unknown operations and errors fail closed with no raw domain error details.
- Scope moves reuse encrypted records and histories. Copy and verify all destinations before removing any source; synchronized scopes require verified primary acknowledgment. Journal contains only references/revisions/progress, no secret payload. Interrupted moves are resumable; conflicts or changed inputs preserve the source. Validate host/key/proxy relationships, including grouped moves.

## Delivered

- Shared metadata inventory and tags for all six types, native infrastructure tag compatibility, and preservation of record metadata on content edits, rename, restore and move.
- `item list`, tag commands, rename, move and batch preview/apply/resume with explicit IDs and revision checks. Password titles can also be changed through reviewed organization proposals.
- Durable grouped moves, destination acknowledgment for synchronized scopes, source tombstones/history, dependency validation, destination/source drift rejection and resumable offline failures.
- Scoped expiring MCP sessions with five allowlisted tools, independent digest approval, revocation on lock/unlock or expiry, saved progress and scope membership/label checks.
- Desktop tag entry, suggestions, filters and editing for all types; selection and review for bulk tags/moves; retries after partial creation and stale-tag protection.
- Repository skill, direct organization reference, README links and an isolated integration test wired into CI.

## Verification

The repository Go suites and simulator suite were exercised. Final affected-package tests and focused race checks cover metadata preservation, native tag semantics, approval, revocation, scope drift, batch preflight, move resume and recreated sources. Desktop type checking and all 95 component/unit tests passed, with focused reruns after the final UI changes. The earlier reveal timing/teardown failure passed on the complete rerun without a product-code workaround.

The isolated integration test runs real CLI, agent, server, Desktop bridge and MCP processes. It checks offline source retention, acknowledged destination writes, resumption, CLI saved previews, independent MCP approval, secret canaries on both output pipes, literal Desktop secret values, tag preservation on rename and stale-tag rejection. Its wrapper verifies that the production binary and agent state remain unchanged.

The skill passes the skill validator. Harper findings were reviewed; product names and technical terminology were retained. Local verification did not package or launch Electron or open the real vault.

## Release verification

Implementation commit `776cea1733e0275c871662dcd65a1deb5b110c24` passed the complete [main CI](https://github.com/k2b-dev/fd0.sh/actions/runs/34498683872), including both operating systems and the isolated organization integration test. Both release workflows succeeded: [CLI](https://github.com/k2b-dev/fd0.sh/actions/runs/34499898577) and [Desktop](https://github.com/k2b-dev/fd0.sh/actions/runs/34499898115).

The published CLI checksum signature and all eight archives were verified. The downloaded macOS ARM64 binary reports version 0.16.0 and exposes the organization commands. The published Desktop manifest signature and all 23 covered files were verified; all four updater manifests have the correct version, artifact sizes, and SHA512 hashes. The release manifest points to the implementation commit. CI verified macOS signing and notarization for both architectures and Linux packages on clean systems.

Releases: [CLI 0.16.0](https://github.com/k2b-dev/fd0.sh/releases/tag/v0.16.0) and [Desktop 0.6.0](https://github.com/k2b-dev/fd0.sh/releases/tag/desktop-v0.6.0). The local production installation was not updated.

## Operational boundaries

The MCP interface does not sandbox other tools: the organizing model must have only its restricted tools. Older clients preserve supplemental tags on ordinary content edits but do not transfer them on old rename/move commands. Source history is retained; a move does not revoke old members' prior knowledge. Batches are resumable, not rollback transactions. Content transfer from 1Password remains in the user's trusted client.
