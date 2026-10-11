# Working on fd0

fd0 is an end-to-end encrypted secret store: a Go CLI and agent (`cmd/`, `internal/`), a sync server and witness, fd0 Desktop (`desktop/`, Electron), a Chrome extension (`browser/`) and the website with the public docs (`website/`). Design notes and feature plans live in `docs/`; a plan gets an "As built" section once it ships.

## Ground rules

- Never let tests or checks reach the hosted service or the fd0 installed on the machine you work on. Use freshly built binaries, an isolated `FD0_HOME` and a local test server. Do not stop, restart, lock or sync a running fd0-agent that is not your own test agent.
- fd0 stays a general tool. Build features as general building blocks that cover many cases; site-specific topology and procedures belong in the repositories that use fd0.
- Agents never approve recipes, create SSH or secret grants, or enter credentials for a person. Those steps need the person in their own terminal with fresh authentication.
- Never print, log or commit secret values, including in tests and reviews.
- Changes to the security model update `docs/THREATS.md`; user-visible behavior updates the skill (`skills/fd0/`) and the website docs (`website/src/pages/Docs.tsx`).

## Checks

```sh
go vet ./... && go test ./...
bash tests/run_isolated_integration.sh                       # all integration scripts
bash tests/run_isolated_integration.sh tests/integration_X.sh  # one script
(cd desktop && bun test && bun run typecheck)
(cd browser && bun test)
(cd website && bun run build)
```

The isolated runner builds test binaries whose default server is unreachable, so a missing setting can never register anything on the hosted service. Integration scripts that need a terminal (approvals, grants) drive one with Python's `pty`. For Desktop end-to-end tests set `PLAYWRIGHT_BROWSERS_PATH` to a directory outside your home.

## UI

Reuse the existing Desktop design system. Keep it plain and quiet: no glow effects, no colored status dots, no labels that repeat what the layout already says. Cover light and dark, focus, disabled, loading, empty and error states.

## Versions, releases, commits

- Version namespaces and the shared CLI/Desktop number are described at the top of `CHANGELOG.md`. Pushing a tag starts the release: `client-v*` (`release.yml`), `desktop-v*` (`release-desktop.yml`), `server-v*`, `witness-v*`, `website-v*` (`release-docker.yml`).
- Tag, release or deploy only on explicit request. Record releases and deployments as Dex tasks (`.dex/tasks.jsonl`).
- GitHub Issues are the work list; Dex tracks larger pieces of work.
- Conventional Commits named after the outcome. Normal author metadata only: no AI, model or tool attribution, no `Co-authored-by`.
- Edit the fd0 skill in `skills/fd0/`. `.agents/skills` and `.claude/skills` are installed copies.
