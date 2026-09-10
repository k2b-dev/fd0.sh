# fd0 Desktop

fd0 Desktop is the Electron and SolidJS client for the existing fd0 agent. It presents passwords, general secrets, SSH access and remote files, kubeconfigs, and Talos contexts without moving private-key ownership into the renderer.

## Architecture

```text
Solid renderer
    | typed, allowlisted IPC
sandboxed preload
    | ipcMain handlers and native dialogs
Electron main process
    | newline-delimited JSON over private stdio
fd0-desktop-bridge
    | existing internal/cli and domain packages
fd0-agent

Files renderer
    | typed file-operation IPC + native local file dialogs
Electron main process
    | bounded NDJSON with progress and cancellation
fd0-sftp-bridge
    | system OpenSSH using fd0's rendered host configuration
remote SFTP subsystem
```

The agent remains the long-lived key holder. The renderer has no Node.js access, network access, filesystem access, or direct agent socket access. Secret clipboard writes, attachment export, recovery files, and external links cross native main-process handlers.

## Renderer layout

```text
src/renderer/src/
  App.tsx          shell: startup states, routing, overlays, shortcuts
  lib/             store.ts (all vault state and actions), errors, items, format
  ui/              tokens.css and the primitives every surface is built from
  features/        one file per surface (rail, titlebar, list, detail, panels)
  components/      the password editor, add-item, sharing, generator
```

`ui/tokens.css` is the single source for colour, spacing, type, radius, elevation,
z-index, and motion. Component stylesheets must not contain literal hex values,
off-scale spacing, or ad-hoc z-index numbers.

Two rules are load-bearing:

- **Popovers and menus render through `ui/Popover.tsx`**, which portals to `<body>`
  with `position: fixed`. An in-flow popover is clipped by any ancestor with
  `overflow: auto`, regardless of z-index — the modal body and the password
  editor are both scroll containers.
- **Escape ordering goes through `ui/overlayStack.ts`**, not z-index. Modals and
  popovers both listen on `document` in the capture phase, where listener order
  is registration order rather than visual order.

## Develop

Prerequisites: Go from `go.mod`, Bun 1.3.14 or newer, and macOS PC/SC support. Linux also needs the PC/SC development package.

```sh
cd desktop
bun install --frozen-lockfile
bun run dev
```

For a persistent local command, link the repository-owned launcher once:

```sh
mkdir -p ~/.local/bin
ln -s "$PWD/bin/fd0-desktop-dev" ~/.local/bin/fd0-desktop-dev
fd0-desktop-dev
```

The development app uses a separate fd0 instance:

- fd0 home: `~/Library/Application Support/fd0 Desktop Dev` on macOS
- Electron data: `~/Library/Application Support/fd0 Desktop Dev UI` on macOS
- SSH socket: `/tmp/fd0-desktop-dev-ssh-$UID.sock`
- passphrase: `fd0-desktop-dev`
- automatic sync: disabled in the agent process

Both development directories carry exact isolation markers. `bun run dev:reset` refuses to remove either directory when its marker is missing or changed. It never resolves or edits `~/.fd0`.

Set `FD0_DESKTOP_FLAVOR=standard` to build without YubiKey support. Desktop builds include YubiKey support by default.

## Verify

For focused cross-type tag, organization, navigation and reveal checks without Electron or an fd0 agent:

```sh
bun test tests/tags.test.ts tests/password-tags.test.ts tests/item-navigation.test.ts tests/item-reveal.test.ts --timeout 30000
```

These component tests use Chromium with synthetic inventory and a mocked bridge. They require Playwright's Chromium browser to be installed. Set `FD0_TAGS_SCREENSHOTS` to a temporary output directory to capture the narrow tag editor in both themes.

Broader development checks:

```sh
bun run typecheck
bun run test:e2e
bun run package
```

The Electron test launches real temporary fd0 agents and vaults. It covers renderer sandboxing, inventory views, password editing, duplicate protection, general-secret and SSH-host editing, file export, recovery export and restore, lock/unlock, native shortcuts, and responsive layout.

`bun run package` creates an unpacked app under `desktop/dist`. On macOS, local packages receive an ad-hoc signature after Electron fuses are applied so they can be launched without a Developer ID. It does not launch the app. A packaged app uses system mode and defaults to `~/.fd0`; use a temporary `FD0_HOME` and `FD0_SSH_SOCK` for packaged smoke tests.

## Security invariants

- Development and tests require `FD0_DESKTOP_MODE=isolated`, a non-production `FD0_HOME`, an exact marker, a dedicated `FD0_SSH_SOCK`, and `FD0_AGENT_SYNC_DISABLED=1`.
- They also require `FD0_SSH_CONFIG_PATH`. `FD0_HOME` isolates the vault but not what fd0 writes out of it: every mutating `fd0 ssh` command re-renders `~/.ssh/fd0.conf`, so without this an isolated run still overwrites the developer's real ssh_config.
- Packaged builds use `FD0_DESKTOP_MODE=system` and bundled `fd0`, `fd0-agent`, desktop bridge, and SFTP bridge binaries.
- IPC channels and bridge methods are explicit allowlists with strict decoding and 1 MiB frame limits.
- Remote transfers retain strict OpenSSH host verification, reject recursive symlinks, write through temporary destinations, and require explicit overwrite or delete actions.
- Renderer navigation, new windows, permissions, and network connections are denied.
- Copied secrets clear after 30 seconds when the clipboard still contains the copied value.
- Electron production fuses disable RunAsNode, Node options, and inspector arguments and require the embedded ASAR.
- macOS releases require Developer ID signing, hardened runtime, and notarization. The release workflow fails when signing credentials are absent.
- Startup failures stay inside a recovery screen with retry, service repair, redacted diagnostics, and log access. They never trigger a vault reset.
- Diagnostic logs rotate at 512 KiB with three backups and redact credential assignments, bearer tokens, and user-home prefixes.

## Linux runtime

AppImage builds use electron-builder AppImage toolset `1.0.3`, whose static
runtime does not require FUSE2. YubiKey builds link `fd0-agent` to
`libpcsclite.so.1`; the AppImage bundles that library and its license so
passphrase users do not need PC/SC packages. DEB and RPM keep native
`libpcsclite1` or `pcsc-lite-libs` dependencies so their package managers own
updates and removal.

The Linux release job records the complete `ldd` closure for `fd0-agent` on
x64 and arm64 and fails on any unresolved library. Clean-machine jobs run the
AppImage on native runners plus Ubuntu, Debian, and Rocky Linux containers
without host Cosign or PC/SC, then install and remove DEB and RPM packages.
YubiKey use still requires a compatible card, the PC/SC daemon, and device
access; standard vault access does not.

## Release

Push `desktop-vX.Y.Z`. `.github/workflows/release-desktop.yml` verifies the repository, builds YubiKey-enabled macOS and Linux artifacts, signs and notarizes macOS bundles, publishes an SPDX SBOM and GitHub provenance, signs the checksum manifest with Sigstore, verifies it with fd0's embedded verifier, and publishes one GitHub release from draft state only after every artifact is present.

Required GitHub secrets:

- `MACOS_CERTIFICATE`: base64 PKCS#12 Developer ID Application certificate
- `MACOS_CERTIFICATE_PASSWORD`
- `APPLE_API_KEY_P8`: base64 App Store Connect API key
- `APPLE_API_KEY_ID`
- `APPLE_API_ISSUER`

The updater first reads the cached stable feed at `fd0.sh` and falls back to a
fully paginated GitHub lookup. Drafts and prereleases do not enter the stable
channel. macOS uses architecture-specific update metadata; Linux uses AppImage
metadata and an embedded Sigstore verifier pinned to the exact release workflow
and tag. Before installing an update, Desktop stops the running agent so the
bundled app, CLI, and agent cannot drift across versions.

For installer-managed command paths, `fd0 update` opens Desktop, selects
**Support**, and starts this same updater. It never creates a second terminal
download or replacement path for the signed bundle.

`scripts/install-desktop.sh` verifies SHA-256 for every install and always
authenticates the manifest. If Cosign is absent, it downloads the pinned Cosign
3.0.6 binary and checks its hard-coded platform SHA-256 before use. On macOS it
also verifies the app signature and Gatekeeper assessment before replacement.
The installer creates marked `fd0` and `fd0-agent` wrappers in
`~/.local/bin` or `/usr/local/bin`; any pre-existing standalone commands are
preserved and restored on uninstall. Linux commands relay into the installed
AppImage, while macOS commands resolve into the stable app bundle path.
`--uninstall` removes only owned files and never removes `~/.fd0`.

A DMG copied directly to `/Applications` or a directly launched AppImage is a
GUI-only installation: the app starts and supervises its bundled agent, but it
does not claim shell command paths. Use the install script when the same signed
bundle should also own `fd0` and `fd0-agent` commands. DEB and RPM package
ownership remains with the system package manager.
