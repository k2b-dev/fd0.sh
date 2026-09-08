# fd0 — zero-knowledge secrets manager

**One encrypted vault for passwords, SSH keys, Kubernetes and Talos
credentials, and the secrets in between.**

[Website](https://fd0.sh) ·
[Documentation](https://fd0.sh/docs) ·
[Download fd0 Desktop](https://fd0.sh/download) ·
[Self-host fd0](https://fd0.sh/docs/server)

fd0 encrypts every secret on your device before it is synced. The server stores
ciphertext and signed events, not plaintext values or secret names. Use the
hosted service at fd0.sh or run the same server on your own infrastructure.

fd0 Desktop and the CLI use the same vault and local agent. Choose the window,
the terminal, or both.

## What belongs in fd0

- **Logins:** usernames, passwords, TOTP, passkeys stored as data, recovery
  codes, notes, and small file attachments.
- **SSH:** encrypted private keys, a host inventory, terminal sessions, and
  two-way SFTP transfers. The same records work with `ssh`, Git, `scp`,
  `rsync`, fd0 Desktop, and `fd0 sftp`.
- **Clusters:** Kubernetes kubeconfigs and Talos contexts shared by scope
  instead of copied between machines.
- **Secrets:** API keys, deploy tokens, connection strings, licence keys, and
  other opaque values.

Every record type uses the same scopes, version history, sync, and recovery
model.

## Why fd0

- **The server cannot decrypt.** Secret values and names are sealed locally.
  Decrypted identity and SSH key material stays in the local agent's memory.
- **Sharing is cryptographic.** Each scope has its own key. Adding a member
  wraps that key to their identity; removing a member rotates it.
- **Forks are detectable.** The server signs transparency-log tree heads.
  Configured witnesses can expose divergent histories.
- **Hosted and self-hosted use the same protocol.** The hosted
  `api.fd0.sh` primary is the default; changing `[sync].server` points the
  client at your own deployment.
- **No telemetry.** The desktop app and CLI do not send usage analytics.

Read the [product overview](https://fd0.sh/#how) for the trust model or the
[technical specification](https://fd0.sh/spec) for protocol details.

## Install or update

fd0 supports macOS and Linux on x64 and arm64.

```sh
curl -fsSL https://fd0.sh/install | sh
```

The installer asks whether you want:

1. **fd0 Desktop** with its version-matched CLI, agent, and YubiKey support.
2. **CLI and agent only**, with optional YubiKey support.

Run the same command to update. An existing product and CLI flavor remain
selected by default, and the installer asks before changing anything.

For scripted installs, make the choice explicit:

```sh
# Desktop, CLI, and agent
curl -fsSL https://fd0.sh/install | sh -s -- --desktop --yes

# Standard CLI and agent
curl -fsSL https://fd0.sh/install | sh -s -- --flavor=standard --yes

# CLI and agent with YubiKey PIV support
curl -fsSL https://fd0.sh/install | sh -s -- --yubikey --yes
```

The CLI-only path requires
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) on
`PATH`. The Desktop installer bootstraps a pinned, checksum-verified Cosign
binary when needed. Both paths authenticate the release manifest before
installing an artifact.

Prefer a direct package? [Download the signed macOS DMG or Linux
package](https://fd0.sh/download).

## Create your first vault

```sh
fd0 init
fd0 unlock
fd0 secret set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxx"
fd0 sync
fd0 secret get DEPLOY_KEY
```

The hosted fd0.sh service is already configured. To use your own server, follow
the [self-hosting guide](https://fd0.sh/docs/server).

## Use fd0 with your coding agent

Install the fd0 skill to give your coding agent instructions for managing
passwords, SSH keys, scopes, and other credentials. Run either command:

```sh
npx skills add k2b-dev/fd0.sh
# Or with Bun:
bunx skills add k2b-dev/fd0.sh
```

Select your agents in the installer. Installation is project-local by default;
add `--global` to use the skill across projects. The skill contains instructions;
fd0 itself and an initialized vault are still required. Normal vault access and
unlock requirements apply. See the [agent skill setup](https://fd0.sh/docs/install#agent-skill).

## Learn fd0

- [Install Desktop, CLI, and agent](https://fd0.sh/docs/install)
- [Use fd0 Desktop](https://fd0.sh/docs/desktop)
- [Store passwords and login items](https://fd0.sh/docs/pass)
- [Use SSH keys and host aliases](https://fd0.sh/docs/ssh)
- [Store Talos and Kubernetes credentials](https://fd0.sh/docs/talos)
- [Share scopes and sync devices](https://fd0.sh/docs/sync)
- [Recover a vault](https://fd0.sh/docs/recovery)
- [Browse the CLI reference](https://fd0.sh/docs/cli)

User documentation lives on [fd0.sh](https://fd0.sh/docs). The files under
[`docs/`](./docs) are engineering references for the protocol, API, storage,
threat model, transparency log, replication, and production hosting.

## Develop fd0

The repository contains the Go client, agent, server, and witness; the
Electron/Solid desktop app; the fd0.sh website; deployment assets; and
integration tests.

```sh
make test          # Go test suite
make integration   # isolated multi-user and installer tests
make lint          # vet, optional linters, and threat coverage
make all           # build and run all checks
```

Build the website with `cd website && bun install && bun run build`. Desktop
development commands and isolation requirements live in
[`desktop/README.md`](./desktop/README.md). Install the official
[fd0 Chrome extension](https://chromewebstore.google.com/detail/fd0/kcbjlgbkgoabcdflpnohkknfbegcigel)
for autofill, password generation, save/update, and TOTP. Development and
Native Messaging details live in [`browser/README.md`](./browser/README.md).

Compatibility and security-sensitive changes should start with
[`docs/PROTOCOL.md`](./docs/PROTOCOL.md),
[`docs/THREATS.md`](./docs/THREATS.md), and
[`docs/CRYPTO_AUDIT.md`](./docs/CRYPTO_AUDIT.md).

See [CHANGELOG.md](./CHANGELOG.md) and
[GitHub Releases](https://github.com/k2b-dev/fd0.sh/releases) for published
versions.

## Security

Report vulnerabilities privately to **mail@valentin-kolb.com** with subject
prefix `fd0-security:`. Include the affected version, code path, and a
reproducer when possible. Use GitHub Issues for non-security bugs.

## License

Apache-2.0. See [LICENSE](./LICENSE).
