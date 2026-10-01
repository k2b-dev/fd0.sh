# Remote files over SFTP

Use `fd0 sftp` for file operations on hosts already stored with `fd0 ssh`.
It reuses the rendered OpenSSH configuration, assigned fd0 key, jump host,
agent socket, and strict host-key verification. It does not create a second
credential model and it never bypasses an unverified host key.

## Command grammar

```sh
fd0 sftp HOST
fd0 sftp ls HOST [REMOTE_PATH] [--json]
fd0 sftp tree HOST [REMOTE_PATH] [--depth N]
fd0 sftp stat HOST REMOTE_PATH [--json]
fd0 sftp cp HOST SOURCE DESTINATION [--recursive] [--force]
fd0 sftp mkdir HOST REMOTE_PATH [--parents]
fd0 sftp mv HOST OLD_REMOTE_PATH NEW_REMOTE_PATH [--force]
fd0 sftp rm HOST REMOTE_PATH [--recursive] --yes
```

`fd0 sftp HOST` opens the system's native interactive `sftp` client. Prefer
the explicit subcommands for scripts and agent work. SFTP accepts exact host
aliases only. An alias that exists in several scopes is refused, even with
`--scope`, because the SSH config can only hold one host per alias; rename one.

## Copy operands

Exactly one side of `cp` must start with `remote:`:

```sh
# Upload
fd0 sftp cp prod ./release.tar remote:/tmp/release.tar

# Download
fd0 sftp cp prod remote:/var/log/app.log ./app.log

# Directory transfer
fd0 sftp cp prod ./dist remote:/srv/app/dist --recursive
```

Do not use shell-style `HOST:/path`; the host is already the first command
argument. The explicit `remote:` marker prevents local and remote paths from
being confused.

Existing destinations are refused unless the user explicitly approves
`--force`. Directory transfers require `--recursive`. Recursive operations do
not follow remote symlinks. fd0 refuses to replace an existing directory tree
even with `--force`; choose a new destination or remove the old tree as a
separate, explicitly confirmed operation.

Interactive transfers report progress on stderr so stdout remains usable by
scripts. Ctrl-C or SIGTERM cancels the operation; fd0 removes only its
temporary partial artifact and leaves an existing destination untouched.
Uploaded files and staging directories are owner-only until complete, then
take the source mode. Desktop exposes the same
progress and cancellation in its transfer queue.

## Machine-readable reads

Use `--json` for directory listings and metadata. Do not parse the aligned
human output.

```sh
fd0 sftp ls prod /srv/releases --json
fd0 sftp stat prod /srv/releases/current --json
```

Tree output is intentionally bounded: default depth 3, maximum depth 32, and a
maximum of 10,000 entries.

## Destructive operations

Before `rm`, `mv --force`, or `cp --force`, confirm the exact host and remote
path. Non-interactive deletion requires `--yes`; deleting a directory requires
both `--recursive` and `--yes`.

SFTP authorization comes from the remote operating-system account. fd0 can
select and serve the configured SSH key, but it cannot grant permissions the
remote account does not have.

If host verification fails, open the host interactively, verify its fingerprint
through a trusted channel, and accept it only after it matches. Never disable
`StrictHostKeyChecking`.

## Desktop

For a graphical workflow, open an SSH host in fd0 Desktop and choose **Browse
files**. The dedicated Files window supports navigation, drag-and-drop upload,
download, new folders, rename, delete, progress, and cancellation. Native file
dialogs keep local destination selection outside the web renderer.
