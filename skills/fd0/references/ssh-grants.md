# Keep selected SSH hosts available while fd0 is locked

Use a saved SSH grant when the user explicitly wants a host accessible after
locking the vault. The grant applies only to this fd0 installation. Its selection
survives restarts, but the user must unlock fd0 once after a computer or agent
restart before the keys become available again.

## Agent workflow

1. Inspect host metadata and the user's requested scope. The host needs an
   explicit SSH user and an fd0 key. Resolve ambiguous names before proceeding.
2. The vault must be unlocked to prepare the preview. Give the user the exact
   command to run in their own terminal:

   ```sh
   fd0 ssh grant build-server --scope work
   ```

3. The user reviews the SSH user, server, and key fingerprints, then authenticates
   again using the same method chooser as unlock (passphrase or YubiKey). An already unlocked vault is
   insufficient. Never ask them to send credentials in chat, capture their input,
   or run this authorization command on their behalf. There is no `--yes`,
   password flag or organization-MCP tool for creating grants.
4. Use `fd0 ssh grants --json` to check the saved selection and active state.
   This returns grant metadata, not private keys. It does not authorize connecting
   to or changing the remote host; normal task authorization still applies.

The host must already have a verified entry in `~/.ssh/known_hosts`. If missing,
ask the user to connect and verify the server fingerprint through a trusted
source first. Never use `ssh-keyscan` alone as proof of identity or disable host
verification to get a grant accepted. `--known-hosts PATH` selects a different
trusted file. `--method passphrase` or `--method yubikey` selects authentication.

In Desktop, open the host's **SSH while locked** section, review the grant, and
choose **Authenticate and allow**. The lock screen lists active grants and can
open their SSH sessions.

## Locking and removal

```sh
fd0 lock                 # lock the vault; approved SSH access stays available
fd0 ssh build-server     # exact active alias works while the vault is locked
fd0 ssh grants --json    # saved grants when unlocked; active grants when locked
fd0 lock --all           # stop all grants until the next vault unlock
fd0 ssh revoke GRANT_ID  # permanently remove the grant; unlock first
```

Use a scope ID rather than a scope label for `--scope` while locked. Prefix
matching, the host picker and tag filtering require an unlocked vault.
`lock --all` and revocation prevent new authentication; neither disconnects
existing SSH sessions or multiplexed connections.

## Boundaries

- A grant binds the SSH user, verified server host keys, selected client key,
  host record and connection settings. Key replacement, host changes or locally
  observed membership removal disable the old grant. Review and create a new
  grant if its destination changed. Tag and description edits preserve it.
- Clients and servers must support OpenSSH session binding and host-bound public
  key authentication. Unsupported clients fail while locked; they can still use
  the ordinary unlocked workflow. Forwarded agents, generic signing, and
  certificate-authority-only host trust are not supported for locked grants.
- ProxyJump uses separate local authentication for each hop. Each hop that needs
  an fd0 key must have its own explicit grant; approval never expands to it
  automatically. Native `ssh`, `scp`, Git-over-SSH and CLI SFTP can use grants
  through compatible OpenSSH clients. Desktop file browsing still requires the
  unlocked inventory.
- Selected private keys remain in protected agent memory, without keeping the
  vault's identity, payload, or scope keys unlocked. No private key file is
  exported. Remote revocation is only observed when fd0 next synchronizes;
  removing local access cannot revoke keys already installed on a server.
- Selection lives in an optional encrypted `ssh_grants` vault field. A random
  `device_id` in local `config.toml` identifies the installation. It is not a
  hardware identity or authentication credential. Copying the entire fd0 home
  also copies this ID; newly initialized installations receive a new one.
- Fresh authentication is enforced by the fd0 agent for the supported grant
  operation. It is not a sandbox against arbitrary code running as the same OS
  user, nor cryptographic proof that a human issued the command. YubiKey presence
  requirements follow the enrolled key's policy.
