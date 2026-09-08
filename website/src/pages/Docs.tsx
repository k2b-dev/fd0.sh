/**
 * /docs/* - user-facing fd0 documentation.
 *
 * The repository docs are the protocol and operator source of truth. These
 * pages explain how to use fd0 on fd0.sh or against a self-hosted primary.
 */

import { setPageSeo, ssr } from "../../config";
import { Shell } from "../lib/shell";
import {
  C,
  FONT_MONO,
  DocsLayout,
  Shot,
  DESKTOP_RELEASE_URL,
} from "../lib/chrome";

const H2 = (p: { children: any; id?: string }) => (
  <h2 id={p.id} class="text-xl md:text-[1.45rem] font-medium mt-12 mb-4">
    {p.children}
  </h2>
);

const P = (p: { children: any }) => (
  <p class="text-[15px] leading-relaxed mb-4" style={`color:${C.dim};`}>
    {p.children}
  </p>
);

const Code = (p: { children: any }) => (
  <span class="fd0-mono" style={`color:${C.acc};font-family:${FONT_MONO};`}>
    {p.children}
  </span>
);

const Box = (p: { children: any }) => (
  <div
    class="p-4 text-[13px] leading-[1.6] mb-5 overflow-x-auto"
    style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
  >
    <Shell>{p.children}</Shell>
  </div>
);

const Note = (p: { children: any }) => (
  <div
    class="p-4 text-[13.5px] leading-relaxed mb-5"
    style={`background:${C.bgRaised};border-left:2px solid ${C.acc};color:${C.dim};`}
  >
    {p.children}
  </div>
);

const Link = (p: { href: string; children: any }) => (
  <a href={p.href} style={`color:${C.acc};`}>
    {p.children}
  </a>
);

const Cmd = (p: { signature: string; body: any; example?: string }) => (
  <div
    class="p-4 mb-3"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <div
      class="text-[14px] font-medium mb-2 fd0-mono"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.signature}
    </div>
    <p class="text-sm leading-relaxed mb-3" style={`color:${C.dim};`}>
      {p.body}
    </p>
    {p.example ? (
      <div
        class="p-3 text-[12.5px] leading-[1.55] overflow-x-auto"
        style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
      >
        <Shell>{p.example}</Shell>
      </div>
    ) : null}
  </div>
);

/**
 * Primary download call to action. Used at the top of the Desktop page and
 * in the install flow — the two places a reader who came for the app looks
 * first.
 */
const DownloadCta = (p: { note: any }) => (
  <div
    class="p-5 mb-6 flex flex-col gap-3"
    style={`background:${C.bgRaised};border:1px solid ${C.acc}55;`}
  >
    <a
      href={DESKTOP_RELEASE_URL}
      class="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium self-start"
      style={`background:${C.acc};color:#0a0a0a;border:1px solid ${C.acc};`}
    >
      Download fd0 Desktop →
    </a>
    <div class="text-[13px] leading-relaxed" style={`color:${C.dim};`}>
      {p.note}
    </div>
  </div>
);

const TileGrid = (p: { children: any }) => (
  <div class="grid sm:grid-cols-2 gap-4 mt-8">{p.children}</div>
);

const Tile = (p: { href: string; title: string; body: string }) => (
  <a
    href={p.href}
    class="block p-4 transition-colors"
    style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
  >
    <div class="font-medium mb-1" style={`color:${C.acc};`}>
      {p.title}
    </div>
    <div class="text-sm leading-relaxed" style={`color:${C.dim};`}>
      {p.body}
    </div>
  </a>
);

const OverviewBody = () => (
  <>
    <P>
      fd0.sh carries the user documentation. These pages cover the normal
      paths: install, unlock, store secrets, share scopes, sync, SSH, Talos,
      Kube, recovery, and basic self-hosting. The repository holds the
      technical specs.
    </P>

    <TileGrid>
      <Tile href="/docs/install" title="Start here" body="Install the client, create a vault, store the first secret, and sync." />
      <Tile href="/docs/install#agent-skill" title="Agent skill" body="Teach your coding agent to use fd0 for passwords, SSH keys, and other credentials." />
      <Tile href="/docs/desktop" title="Desktop app" body="Download fd0 Desktop for macOS or Linux and see what the app holds." />
      <Tile href="/docs/concepts" title="Concepts" body="The small vocabulary used by every fd0 command." />
      <Tile href="/docs/cli" title="Daily use" body="One grammar for every module, plus scopes, sharing, and health checks." />
      <Tile href="/docs/pass" title="Passwords" body="Login items, TOTP, passkeys, attachments, and the interactive browser." />
      <Tile href="/docs/browser" title="Browser extension" body="Install fd0 for Chrome and fill HTTPS logins without submitting the form." />
      <Tile href="/docs/ssh" title="SSH and files" body="Scope-shared SSH hosts, terminal sessions, and two-way SFTP transfers." />
      <Tile href="/docs/talos" title="Talos and Kube" body="Store, render, merge, and share Talos and Kubernetes configs." />
      <Tile href="/docs/sync" title="Sync" body="What sync sends, what it verifies, and how automatic refresh works." />
      <Tile href="/docs/server" title="Self-host" body="Run a primary, add a DR backup, and know where the full runbook lives." />
      <Tile href="/docs/troubleshooting" title="Troubleshooting" body="Locked vaults, stale SSH sockets, missing hosts, and config refresh." />
    </TileGrid>

    <H2>The normal path</H2>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh
$ fd0 init
$ fd0 unlock
$ fd0 scope create --label work
$ fd0 secret set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxx" --scope work
$ fd0 sync
$ fd0 secret get DEPLOY_KEY --scope work`}</Box>
    <P>
      Prefer a window? <Link href="/docs/desktop">fd0 Desktop</Link> covers the
      same vault on macOS and Linux, and the installer can put the app, the
      CLI, and the agent on the machine in one step.
    </P>

    <H2>Where details live</H2>
    <P>
      Use these pages when you want to operate fd0. Use{" "}
      <Link href="/spec">/spec</Link> or the GitHub files when you need exact
      wire formats, storage invariants, threat IDs, or benchmark baselines.
    </P>
  </>
);

const ConceptsBody = () => {
  const rows = [
    {
      term: "identity",
      text: (
        <>
          Your long-term Ed25519 keypair. The public key appears in cards and
          event authorship. The private key stays encrypted locally and is held
          only by the agent after unlock.
        </>
      ),
    },
    {
      term: "vault",
      text: (
        <>
          The encrypted local file at <Code>~/.fd0/vault.enc</Code>. It stores
          your identity key, pinned cards, per-scope keys, and accepted chain
          tips.
        </>
      ),
    },
    {
      term: "agent",
      text: (
        <>
          The local daemon started by <Code>fd0 unlock</Code>. It signs,
          decrypts, and serves SSH agent requests without exposing private
          bytes to normal CLI commands.
        </>
      ),
    },
    {
      term: "scope",
      text: (
        <>
          A group of secrets with its own encryption key. Adding or removing a
          member rotates that key.
        </>
      ),
    },
    {
      term: "card",
      text: (
        <>
          A signed <Code>fd0://card/...</Code> identity record. Import a card
          only after checking its safety number out of band.
        </>
      ),
    },
    {
      term: "sync",
      text: (
        <>
          The event exchange with one configured primary. The server stores
          ciphertext and signed events; it does not receive plaintext secrets.
        </>
      ),
    },
    {
      term: "witness",
      text: (
        <>
          An independent observer for transparency-log heads. Witnesses help
          clients detect server equivocation.
        </>
      ),
    },
  ];

  return (
    <>
      <P>
        fd0 has a small model: local identity, encrypted vault, scope keys,
        signed events, one primary server, and optional witnesses. Once those
        terms are clear, the commands are direct.
      </P>

      {rows.map((row) => (
        <div
          class="grid sm:grid-cols-[9rem_1fr] gap-x-6 gap-y-2 py-4"
          style={`border-top:1px solid ${C.border};`}
        >
          <div class="text-sm font-medium" style={`color:${C.acc};font-family:${FONT_MONO};`}>
            {row.term}
          </div>
          <div class="text-[15px] leading-relaxed" style={`color:${C.dim};`}>
            {row.text}
          </div>
        </div>
      ))}
    </>
  );
};

const InstallBody = () => (
  <>
    <P>
      Install fd0 on each machine that should hold secrets. The hosted service
      at fd0.sh is the default backend; self-hosted clients use the same
      binaries with a different <Code>[sync].server</Code>.
    </P>
    <P>
      There are two ways in, and they are not exclusive. Take{" "}
      <Link href="/docs/desktop">fd0 Desktop</Link> if you want the app — the
      installer can hand it the <Code>fd0</Code> and <Code>fd0-agent</Code>{" "}
      commands too. Take the CLI alone on servers and machines where a window
      would never open.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh`}</Box>
    <P>
      The installer asks whether to install Desktop or the CLI. For a CLI
      install, it also asks whether to include YubiKey support. Run the same
      command again to update: your current product and flavor are selected by
      default, and nothing changes until you confirm.
    </P>

    <H2 id="desktop">Install fd0 Desktop</H2>
    <DownloadCta
      note={
        <>
          Signed DMGs for macOS and AppImage, DEB, and RPM builds for Linux, on
          x64 and arm64. Downloading the DMG or AppImage directly installs the
          app and its bundled agent; it does not claim the{" "}
          <Code>fd0</Code> command. Use the script below when it should.
        </>
      }
    />
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh -s -- --desktop`}</Box>
    <P>
      This installs one versioned bundle containing fd0 Desktop, the CLI, and
      the agent. The <Code>fd0</Code> and <Code>fd0-agent</Code> commands point
      into that bundle, so an app update updates all three together. Desktop
      manages passwords, general secrets, SSH hosts and keys, kubeconfigs, and
      Talos contexts through the same local agent.
    </P>
    <P>
      The desktop installer verifies SHA-256 for every install and always
      authenticates the release manifest. If Cosign is missing it downloads a
      pinned Cosign 3.0.6 binary and checks its hard-coded hash first, so you
      do not install release tooling by hand. On macOS it also verifies the app
      signature and the Gatekeeper assessment before replacing anything.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install-desktop | sh -s -- --system
$ curl -fsSL https://fd0.sh/install-desktop | sh -s -- --version=desktop-v1.2.3
$ curl -fsSL https://fd0.sh/install-desktop | sh -s -- --uninstall`}</Box>
    <P>
      <Code>--system</Code> installs for every user —{" "}
      <Code>/Applications</Code> on macOS, <Code>/usr/local/bin</Code> on
      Linux — instead of the per-user default.{" "}
      <Code>--version=desktop-vX.Y.Z</Code> pins a release, and going backwards
      also needs <Code>--allow-downgrade</Code>. <Code>--uninstall</Code>{" "}
      removes the app and its managed command wrappers and restores any
      standalone <Code>fd0</Code> commands it displaced. It does not remove{" "}
      <Code>~/.fd0</Code> or your vault data. Add <Code>-y</Code> to skip the
      confirmation prompt.
    </P>

    <H2>Install the CLI</H2>
    <Box>{`$ brew install cosign   # macOS or Linuxbrew
$ cosign version`}</Box>
    <P>
      The CLI-only installer requires <Link href="https://docs.sigstore.dev/cosign/system_config/installation/">Cosign</Link>{" "}
      to authenticate release manifests. Install it first.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh -s -- --flavor=standard
$ fd0 version
fd0 <version> standard`}</Box>
    <P>
      The installer picks Linux or macOS, amd64 or arm64, verifies SHA-256,
      authenticates the manifest against the exact fd0 release workflow and
      tag with Cosign, and writes <Code>fd0</Code> plus{" "}
      <Code>fd0-agent</Code> to <Code>~/.local/bin</Code>. It doubles as the
      upgrade path: it detects an existing install, prints{" "}
      <Code>current → new</Code>, and asks before touching anything.
    </P>
    <P>
      <Code>--system</Code> installs into <Code>/usr/local/bin</Code> and{" "}
      <Code>--prefix=DIR</Code> installs anywhere else.{" "}
      <Code>--version=vX.Y.Z</Code> pins a release (with{" "}
      <Code>--allow-downgrade</Code> to move backwards),{" "}
      <Code>--flavor=auto|standard|yubikey</Code> chooses the build,{" "}
      <Code>--yubikey</Code> is the shortcut for the PIV one, and{" "}
      <Code>-y</Code> skips prompts and keeps the non-interactive default on
      the CLI unless a product or flavor is selected explicitly.{" "}
      <Code>FD0_VERSION</Code> and <Code>FD0_FLAVOR</Code> provide the same
      version and flavor choices from the environment.
    </P>
    <H2>Install the YubiKey flavor</H2>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
$ fd0 version
fd0 <version> yubikey`}</Box>
    <P>
      The YubiKey flavor includes PIV support in both <Code>fd0</Code> and{" "}
      <Code>fd0-agent</Code>. Use it on machines that should enroll or unlock
      with a YubiKey.
    </P>
    <H2>Update the client</H2>
    <Box>{`$ fd0 update --check
$ fd0 update
$ fd0 update --flavor=yubikey`}</Box>
    <P>
      <Code>fd0 update</Code> updates <Code>fd0</Code> and{" "}
      <Code>fd0-agent</Code> from the latest client release. It verifies the
      archive checksum and requires Cosign authentication. It keeps the installed
      flavor by default: <Code>standard</Code> stays standard,{" "}
      <Code>yubikey</Code> stays yubikey. Use <Code>--flavor</Code> only to
      switch deliberately. If the agent is running, restart it after the update
      with <Code>fd0 agent restart</Code>.
    </P>
    <P>
      Automatic update resolution never downgrades. Installing an explicitly
      selected older release requires <Code>--allow-downgrade</Code> in
      addition to the version.
    </P>
    <Note>
      In a Desktop-managed installation, plain <Code>fd0 update</Code> opens
      Desktop under Support and starts the app updater. Desktop-specific
      version, flavor, prefix, and downgrade flags are rejected because the
      app, CLI, and agent update as one signed bundle.
    </Note>
    <Note>
      Windows is not supported yet. The binaries cross-compile, but the agent
      socket path has not been validated on Windows.
    </Note>

    <H2 id="agent-skill">Use fd0 with your coding agent</H2>
    <P>
      Install the fd0 skill to give your coding agent instructions for storing
      passwords, managing SSH keys, sharing scopes, and working with Kubernetes
      and Talos credentials. You can then ask it to “store this login in fd0”
      or “list my SSH hosts.”
    </P>
    <P>Run either command, depending on whether you use npm or Bun:</P>
    <Box>{`$ npx skills add k2b-dev/fd0.sh
# Or with Bun:
$ bunx skills add k2b-dev/fd0.sh`}</Box>
    <P>
      Select the agents you use in the installer. The Skills CLI supports
      Claude Code, Codex, Cursor, and other coding agents. Installation is
      project-local by default; add <Code>--global</Code> to make the skill
      available across projects. Start a new agent session after installation.
    </P>
    <Note>
      The skill contains instructions, not credentials. Install fd0 itself
      using the steps above and initialize your vault below. When your agent
      uses fd0, the same vault access and unlock requirements apply as when
      you run the CLI yourself.
    </Note>

    <H2>Create a vault</H2>
    <Box>{`$ fd0 init
$ fd0 unlock
$ fd0 scope create --label work
$ fd0 secret set API_TOKEN "secret-value" --scope work
$ fd0 sync`}</Box>
    <P>
      <Code>fd0 init</Code> creates your identity and seals the vault under a
      passphrase. <Code>fd0 unlock</Code> starts the agent.{" "}
      <Code>fd0 sync</Code> publishes encrypted events to the configured
      primary and pulls changes from other devices.
    </P>

    <H2>Configure another backend</H2>
    <Box>{`$ mkdir -p ~/.fd0
$ cat >~/.fd0/config.toml <<'EOF'
[sync]
server = "https://fd0.example.com"
interval = "1h"
on_unlock = true
EOF`}</Box>

  </>
);

const DesktopBody = () => (
  <>
    <P>
      fd0 Desktop is the app for the same vault the CLI uses. It runs on macOS
      and Linux, keeps every item type in one searchable list, and reaches the
      vault through the local agent rather than around it.
    </P>

    <DownloadCta
      note={
        <>
          Signed DMGs for macOS and AppImage, DEB, and RPM builds for Linux, on
          x64 and arm64. macOS releases are Developer ID signed and notarized;
          every release ships a Cosign-signed checksum manifest.
        </>
      }
    />
    <P>
      To let the app own the <Code>fd0</Code> and <Code>fd0-agent</Code>{" "}
      commands as well, install it with the script instead. Full flags are on{" "}
      <Link href="/docs/install#desktop">the install page</Link>.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh -s -- --desktop`}</Box>

    <H2>What the app holds</H2>
    <P>
      Everything <Code>fd0</Code> stores, in the same scopes, on the same
      chains:
    </P>
    <div class="mb-6">
      {[
        [
          "Passwords",
          "Login items with typed fields — text, secret, TOTP with a live countdown, passkeys stored as data, and file attachments. Sections group fields inside one item.",
        ],
        [
          "General secrets",
          "The plain name-and-value records behind fd0 secret set, editable in the same detail pane.",
        ],
        [
          "SSH keys and hosts",
          "Host, user, port, notes, and the key each host authenticates with. The agent serves those keys over the standard ssh-agent protocol.",
        ],
        [
          "Kubeconfigs and Talos contexts",
          "Cluster credentials alongside everything else, rendered to disk by the same sync that pulls them.",
        ],
        [
          "Sharing",
          "Move an item into a shared scope and the scope's members get it on their next sync. Removing a member rotates the scope key.",
        ],
        [
          "History",
          "Each item keeps its earlier versions and can be restored to one of them.",
        ],
      ].map(([term, text]) => (
        <div
          class="grid sm:grid-cols-[11rem_1fr] gap-x-6 gap-y-1 py-3"
          style={`border-top:1px solid ${C.border};`}
        >
          <div class="text-sm font-medium" style={`color:${C.acc};`}>
            {term}
          </div>
          <div class="text-[15px] leading-relaxed" style={`color:${C.dim};`}>
            {text}
          </div>
        </div>
      ))}
    </div>

    <H2>Organize passwords with tags</H2>
    <P>
      Open a password for editing and use <strong>Tags</strong> to add labels
      such as Work or Shopping. Type a label and press Enter, or choose a
      suggestion from the selected vault. Tags can contain spaces. Use the
      remove button on a tag to remove it, then save your changes.
    </P>
    <P>
      Click a tag in an item's details, or open <strong>Tags</strong> above
      the password list. Multiple selected tags match items that have all of
      them. Combine tags with a vault, favorites, or search, and use{" "}
      <strong>Without tags</strong> to find items you have not organized yet.
      Remove active filter chips to widen the list again.
    </P>
    <P>
      Tags are encrypted and sync with the password. They do not change who
      can access it. You can use up to 32 tags per item, with 64 characters per
      tag; capitalization does not create a separate tag.
    </P>

    <H2>The app, screen by screen</H2>
    <div class="grid gap-5 mb-6">
    </div>

    <H2>How it reaches your secrets</H2>
    <P>
      The window you see has no Node.js, no filesystem access, no network
      access, and no direct connection to the agent socket. It talks to the
      Electron main process over a typed, allowlisted channel, which talks to a
      versioned Go bridge, which talks to <Code>fd0-agent</Code> — the same
      long-lived key holder the CLI uses. Clipboard writes, attachment exports,
      recovery files, and external links all cross a native handler.
    </P>
    <Note>
      A packaged app defaults to <Code>~/.fd0</Code>, so the app and the CLI
      share one vault on the machine. Startup failures land in a recovery
      screen with retry, service repair, and redacted diagnostics — they never
      reset a vault.
    </Note>

    <H2>Update and remove</H2>
    <P>
      Desktop updates itself from Support inside the app. In a Desktop-managed
      installation <Code>fd0 update</Code> opens that view and starts the same
      updater instead of writing into the signed bundle. Before installing an
      update, Desktop stops the running agent so the app, CLI, and agent cannot
      drift apart.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install-desktop | sh -s -- --uninstall`}</Box>
    <P>
      Uninstalling removes the app and the command wrappers it owns and
      restores any standalone <Code>fd0</Code> commands it displaced. Your
      vault in <Code>~/.fd0</Code> is left alone. DEB and RPM installs are
      removed by the system package manager instead.
    </P>
  </>
);

const PassBody = () => (
  <>
    <P>
      <Code>fd0 pass</Code> is the password manager. An item is a title, a set
      of URLs, an optional note, and typed fields. It is stored like every
      other fd0 record, so a login is shared, synced, and revoked exactly the
      way a secret or an SSH key is — through its scope.
    </P>

    <H2>Field types</H2>
    <div class="mb-6">
      {[
        ["text", "Plain values shown as-is: usernames, account ids, backup addresses."],
        ["secret", "Masked in output. Reveal or copy it explicitly."],
        ["totp", "An otpauth:// URI. fd0 prints or copies the current code."],
        ["passkey", "Passkey material stored as data, so it syncs and shares with the item."],
        ["file", "A small attached file — a recovery key, a certificate."],
        ["section", "A named group. Fields under it use a slash path, like Recovery/code-1."],
      ].map(([term, text]) => (
        <div
          class="grid sm:grid-cols-[7rem_1fr] gap-x-6 gap-y-1 py-3"
          style={`border-top:1px solid ${C.border};`}
        >
          <div
            class="text-sm font-medium"
            style={`color:${C.acc};font-family:${FONT_MONO};`}
          >
            {term}
          </div>
          <div class="text-[15px] leading-relaxed" style={`color:${C.dim};`}>
            {text}
          </div>
        </div>
      ))}
    </div>

    <H2>Create an item</H2>
    <Box>{`$ fd0 pass add github --url https://github.com --scope work
$ fd0 pass field set github username ada@example.com
$ fd0 pass field set github password --secret --generate --length 32
$ fd0 pass totp add github "otpauth://totp/GitHub:ada@example.com?secret=..."`}</Box>
    <P>
      <Code>--generate</Code> creates the value without it ever appearing in
      your shell history. To pass a value you already have without recording
      it either, use <Code>-</Code> and pipe it in:{" "}
      <Code>fd0 pass field set github password - --secret</Code>.
    </P>
    <Cmd signature="fd0 pass add <name> [--url URL] [--notes TEXT] [--scope <scope>]" body="Create an item. Repeat --url for several matching URLs. The command refuses an existing name; --force replaces the whole record rather than merging." />
    <Cmd signature="fd0 pass field set <name> <path> [value] [--secret|--type text|secret|passkey] [--generate] [--length N]" body="Set one field. The path is a plain name, or section/name for a field inside a section." />
    <Cmd signature="fd0 pass section add <name> <path>" body="Add a section so related fields can be grouped under one path." />
    <Cmd signature="fd0 pass totp add <name> <otpauth-uri> [--field <path>]" body="Store a TOTP URI. It lands in the totp field unless you name another one." />
    <Cmd signature="fd0 pass file add <name> <file> [<path>] [--mime <type>]" body="Attach a small file as a field. The field takes the file's basename unless you give a path." />
    <Cmd signature="fd0 pass edit <name> [--title <title>] [--url <url>]" body="Change the title or replace the URL list. Fields are edited with pass field set." />

    <H2>Read it back</H2>
    <Box>{`$ fd0 pass                         # interactive browser
$ fd0 pass github                  # browser, pre-filtered
$ fd0 pass copy github             # password to the clipboard, auto-cleared
$ fd0 pass totp code github
$ fd0 pass show github             # secrets masked
$ fd0 pass list --json`}</Box>
    <P>
      Bare <Code>fd0 pass</Code> opens the interactive browser; it needs a
      terminal, and it tells you to use <Code>pass list</Code> or{" "}
      <Code>pass show</Code> when there is not one. Secrets stay masked in the
      browser until you use the shortcut it shows you.
    </P>
    <Cmd signature="fd0 pass show <name> [--reveal] [--json]" body="Print one item. Secrets are masked; --reveal prints them, --json prints the decrypted item." />
    <Cmd signature="fd0 pass copy <name> [<field>] [--clear-after 30s]" body="Copy a field to the clipboard and clear it again. Without a field it copies the password; on a TOTP field it copies the current code." />
    <Cmd signature="fd0 pass field get <name> <path> [--raw]" body="Print one field value to stdout. --raw drops the trailing newline, which is what scripts want." />
    <Cmd signature="fd0 pass find [<query>] [--url <url>] [--tag <tag>] [--json]" body="Match items by title, URL, or tag. --url keeps its URL-only matching rules; tags do not grant an origin access to a login." />
    <Cmd signature="fd0 pass file export <name> <path> [--out <file>]" body="Write an attached file back to disk. It refuses to overwrite unless you pass --force." />
    <Cmd signature="fd0 pass notes show|set|rm <name>" body="Read, replace, or remove the item's free-text note." />
    <Cmd signature="fd0 pass generate [--length 32] [--raw]" body="Generate a password without storing anything." />

    <H2>Organize with tags</H2>
    <P>
      Add tags when creating an item with repeatable <Code>--tag</Code>{" "}
      flags, or change them later with <Code>pass tags</Code>. Quote tags
      containing spaces. Adding the same tag again has no effect.
    </P>
    <Box>{`$ fd0 pass add github --scope work --tag Development --tag "Team A"
$ fd0 pass tags add github Server --scope work
$ fd0 pass tags rm github "Team A" --scope work
$ fd0 pass tags list --scope work --json
$ fd0 pass list --scope work --tag Development --tag Server
$ fd0 pass find github --scope work --tag Development
$ fd0 pass browse --scope work --tag Development
$ fd0 pass list --scope work --untagged
$ fd0 pass tags clear github --scope work`}</Box>
    <P>
      <Code>tags list</Code> shows each tag and its item count per scope.
      Repeat <Code>--tag</Code> to require all selected tags. Use{" "}
      <Code>--untagged</Code> on its own to find items without tags. Tags
      appear in <Code>pass show</Code> and list/find JSON output. The regular
      list columns stay the same.
    </P>
    <P>
      Tags sync with the item, including when you move it to another scope.
      They organize passwords; sharing still comes from scope membership.
      Desktop suggests existing tags from the selected vault as you type.
    </P>

    <H2>Everything else is the shared grammar</H2>
    <P>
      <Code>pass</Code> takes the same verbs as every other module —{" "}
      <Code>list</Code>, <Code>rename</Code>, <Code>move</Code>,{" "}
      <Code>rm</Code>, and <Code>history</Code>. See{" "}
      <Link href="/docs/cli">the CLI reference</Link> for the full set.
    </P>
    <Box>{`$ fd0 pass rename github github-work
$ fd0 pass move github --to-scope personal
$ fd0 pass history show github
$ fd0 pass history restore github 3
$ fd0 pass rm github`}</Box>
    <Note>
      Prefer <Code>fd0 pass copy</Code> over <Code>--reveal</Code> for
      passwords and TOTP codes. Reveal, <Code>field get</Code>, and{" "}
      <Code>file export</Code> put plaintext where your terminal, your history,
      and your logs can see it.
    </Note>
  </>
);

const BrowserBody = () => (
  <>
    <Note>
      Install fd0 from the{" "}
      <Link href="https://chromewebstore.google.com/detail/fd0/kcbjlgbkgoabcdflpnohkknfbegcigel">
        Chrome Web Store
      </Link>
      . It connects Chrome or Chromium on macOS and Linux to the encrypted fd0
      vault on the same device.
    </Note>
    <P>
      Choose an fd0 login beside a credential field to fill it without
      submitting the form. The extension also generates passwords, explicitly
      saves or revision-updates logins, accepts pasted <Code>otpauth://</Code>
      setup links, and fills fresh TOTP codes.
    </P>

    <H2>Connect the extension to fd0</H2>
    <P>
      Install the current fd0 Desktop or CLI before adding the extension. New
      installers register the local Native Messaging host automatically. If
      fd0 was installed earlier, register it once:
    </P>
    <Box>{`$ fd0 browser enable`}</Box>
    <P>
      Unlock fd0, focus a username or password field on an HTTPS page, and
      choose the matching fd0 item. The field button reopens the picker; the
      toolbar action selects one concrete frame with a visible credential
      field.
    </P>

    <H2>Build a development copy</H2>
    <P>
      Clone the fd0 repository, then build the unpacked Manifest V3 extension,
      the CLI, and its dedicated Native Messaging host.
    </P>
    <Box>{`$ cd browser
$ bun install --frozen-lockfile
$ bun run typecheck
$ bun test
$ bun run build

$ cd ..
$ go build -o .build/browser/fd0 ./cmd/fd0
$ go build -o .build/browser/fd0-browser-host ./cmd/fd0-browser-host
$ .build/browser/fd0 browser enable \\
    --host .build/browser/fd0-browser-host`}</Box>
    <P>
      Open <Code>chrome://extensions</Code> or{" "}
      <Code>chromium://extensions</Code>, enable <strong>Developer mode</strong>,
      choose <strong>Load unpacked</strong>, and select <Code>browser/dist</Code>.
      The browser must show extension id{" "}
      <Code>flkmmllfacmjnhjgdfliahdkhfjmdoec</Code>.
    </P>

    <H2>Create a login for testing</H2>
    <Box>{`$ fd0 pass add demo --url https://example.com
$ fd0 pass field set demo username ada@example.com
$ fd0 pass field set demo password --secret --generate
$ fd0 unlock`}</Box>
    <P>
      Existing HTTPS tabs reconnect after an extension update without a manual
      reload.
    </P>
    <P>
      Only matching item metadata crosses into the extension before selection:
      opaque references, titles, usernames, vault labels, revisions, and
      whether a TOTP is available. The password is requested from the local
      agent after selection, and fd0 checks the HTTPS origin again before
      filling the same browser document.
    </P>

    <H2>Disconnect fd0 from Chrome</H2>
    <Box>{`$ fd0 browser disable`}</Box>
    <P>
      This removes only fd0's Native Messaging manifest. Remove the Store or
      unpacked extension separately from <Code>chrome://extensions</Code>.
      Neither action removes your vault.
    </P>

    <H2>If the picker does not appear</H2>
    <P>
      Unlock fd0, confirm the page uses HTTPS, and check that the browser still
      shows the extension id above. If more than one saved account could be
      updated, choose the intended login explicitly. HTTP pages remain
      unsupported. Firefox is not supported yet.
    </P>
  </>
);

const CliBody = () => (
  <>
    <P>
      Using fd0 through a coding agent?{" "}
      <Link href="/docs/install#agent-skill">Install the fd0 skill</Link>{" "}
      to give it the commands and workflows for your vault.
    </P>
    <P>
      The CLI works mostly from local state. <Code>fd0 sync</Code> is the
      explicit network command; the agent can also sync after unlock when{" "}
      <Code>on_unlock = true</Code>.
    </P>

    <H2>One grammar for every module</H2>
    <P>
      Six modules hold items: <Code>secret</Code>, <Code>pass</Code>,{" "}
      <Code>ssh</Code>, <Code>key</Code>, <Code>kube</Code>, and{" "}
      <Code>talos</Code>. They take the same verbs, so learning one teaches the
      rest.
    </P>
    <Box>{`$ fd0 <module> add <name> ...              # create; refuses an existing name
$ fd0 <module> edit <name> --flag value    # change only the fields you name
$ fd0 <module> show <name>                 # human-readable, secrets masked
$ fd0 <module> list                        # alias: ls
$ fd0 <module> rename <name> <new-name>
$ fd0 <module> move <name> --to-scope <scope>
$ fd0 <module> rm <name>                   # tombstone
$ fd0 <module> history show <name>         # versions, newest first
$ fd0 <module> history restore <name> <seq>`}</Box>
    <P>
      <Code>list</Code> takes <Code>--json</Code> on every module, with the
      same key names throughout and <Code>[]</Code> rather than{" "}
      <Code>null</Code> when empty. Secret material is never in that output —{" "}
      <Code>fd0 key list --json</Code> carries the fingerprint and the
      authorized_keys line, never the private half.
    </P>
    <P>
      <Code>edit</Code> patches; <Code>add --force</Code> replaces. An edit
      leaves every field you did not name alone, and passing an empty value
      clears exactly that one field. A forced add rewrites the whole record, so
      anything the command did not carry returns to its default. An edit that
      changes nothing writes nothing and does not burn a revision.
    </P>
    <P>
      Restore writes forward. <Code>history restore</Code> appends a new
      version carrying the old content instead of rewinding the chain, so the
      history stays append-only and the undo is itself auditable.
    </P>
    <P>
      Module-specific commands sit alongside the shared verbs, not instead of
      them: <Code>pass field/notes/totp/file</Code>,{" "}
      <Code>ssh connect/tag/enable</Code>, <Code>kube sync</Code>,{" "}
      <Code>talos secrets</Code>.
    </P>

    <H2>Plain secrets</H2>
    <P>
      A plain secret is a name and a value. Everything richer belongs to one of
      the other modules.
    </P>
    <Cmd signature="fd0 secret set <NAME> <value> [--scope <scope>]" body="Store a string secret in a scope. Use - as the value to read it from stdin. Without --scope, fd0 uses the only live scope, asks interactively, or requires --scope in non-interactive use." />
    <Cmd signature="fd0 secret get [<NAME>] [--raw] [--scope <scope>]" body="Print a secret. Without a name, fd0 opens the interactive picker. --raw drops the trailing newline." />
    <Cmd signature="fd0 secret copy <NAME> [--clear-after=30s]" body="Copy a secret to the clipboard and clear it after the timeout." />
    <Cmd signature="fd0 secret list [--json] [--all]" body="List plain secret names across scopes. --all also lists records owned by other modules — hosts, keys, pass items, clusters. Values stay encrypted until you request one." />
    <Cmd signature="fd0 secret rm <NAME> [--scope <scope>]" body="Write a tombstone for a secret. The old event remains audit history." />
    <P>
      Each module owns its own records, and the secret commands say so rather
      than acting on someone else's:
    </P>
    <Box>{`$ fd0 secret rm host:prod
✗ "host:prod" is a host, not a plain secret
  use: fd0 ssh rm prod`}</Box>
    <Note>
      The older top-level spellings — <Code>fd0 get</Code>,{" "}
      <Code>fd0 set</Code>, <Code>fd0 rm</Code>, <Code>fd0 ls</Code>, and{" "}
      <Code>fd0 copy</Code> — still work and will keep working. They no longer
      appear in <Code>--help</Code>. Prefer the <Code>fd0 secret</Code> form in
      anything you write down.
    </Note>

    <H2>Item history</H2>
    <P>
      Every module keeps earlier versions of its items. The listing gives you
      the sequence numbers restore takes.
    </P>
    <Box>{`$ fd0 secret history show DEPLOY_KEY
$ fd0 secret history restore DEPLOY_KEY 4
$ fd0 ssh history show prod-db --json`}</Box>

    <H2>Scopes and sharing</H2>
    <P>
      A scope is the sharing boundary. Add a member to share every current
      secret in the scope. Remove a member to rotate the scope key for future
      writes.
    </P>
    <Box>{`# Alice exports her card.
$ fd0 card export

# Bob imports Alice, Alice imports Bob, then Alice grants access.
$ fd0 card import "fd0://card/..." --label bob
$ fd0 scope add-member bob --scope work
$ fd0 sync

# Bob discovers the scope on his next sync.
$ fd0 sync
$ fd0 secret list`}</Box>
    <Cmd signature="fd0 card export" body="Print your signed card and safety number. Share the card over any channel; verify the safety number over a trusted channel." />
    <Cmd signature="fd0 card import <fd0://card/...> --label <name>" body="Pin another identity under a local label." />
    <Cmd signature="fd0 scope add-member <label> --scope <scope>" body="Grant a pinned card access to the scope." />
    <Cmd signature="fd0 scope remove-member <label> --scope <scope>" body="Remove access and rotate the scope key." />

    <H2>Unlock methods</H2>
    <P>
      Auth methods are stored in the vault. The default unlock method is a
      local device preference in <Code>~/.fd0/config.toml</Code>; it is not
      synced to other machines. When several methods are available and no
      default or <Code>--method</Code> override is set, an interactive unlock
      asks which method to use.
    </P>
    <Cmd signature="fd0 auth ls" body="List enrolled unlock methods. The current session is marked with *, and the local default is marked with default." />
    <Cmd signature="fd0 auth default" body="Show the default unlock method for this device." />
    <Cmd signature="fd0 auth default yubikey" body="Use YubiKey unlock by default on this device. Use passphrase or a method_id instead when needed." />
    <Cmd signature="fd0 auth default --clear" body="Clear the local default. Interactive unlocks ask which enrolled method to use; non-interactive commands retain a deterministic fallback." />

    <H2>Local health</H2>
    <Cmd signature="fd0 status" body="Show whether the agent is running and whether the vault is unlocked." />
    <Cmd signature="fd0 doctor" body="Replay local chains, check vault tips, auth wraps, scope keys, YubiKey flavor state, orphan chain files, and SSH socket health." />
    <Cmd signature="fd0 lock" body="Lock the vault in the running agent and zeroize in-memory keys." />
    <Cmd signature="fd0 agent status" body="Show fd0-agent process, vault, agent socket, and SSH socket state." />
    <Cmd signature="fd0 agent restart" body="Replace fd0-agent with the current binary and repair stale agent sockets." />
    <Cmd signature="fd0 agent stop" body="Stop fd0-agent and clean stale sockets when safe." />
    <Note>
      If a command needs an unlocked vault in an interactive terminal, fd0
      prompts for the passphrase instead of failing immediately.
    </Note>
  </>
);

const SshBody = () => (
  <>
    <P>
      fd0 stores SSH keys and host entries as scope-shared secrets. The agent
      serves keys over the standard ssh-agent protocol. Host entries render to{" "}
      <Code>~/.ssh/fd0.conf</Code>.
    </P>

    <H2>Enable native ssh</H2>
    <Box>{`$ fd0 ssh enable
$ export SSH_AUTH_SOCK="$(fd0 ssh sock)"`}</Box>
    <P>
      <Code>fd0 ssh enable</Code> writes the fd0 config file and adds an
      Include line to <Code>~/.ssh/config</Code> with confirmation. After that,
      normal <Code>ssh</Code>, <Code>git</Code>, <Code>scp</Code>, and
      compatible tools can use fd0 keys.
    </P>

    <H2>Add a key and host</H2>
    <Box>{`$ fd0 key add laptop --scope work
$ fd0 ssh add prod-db app@db.internal --key laptop --scope work
$ fd0 sync

$ fd0 ssh prod-db
$ ssh prod-db`}</Box>
    <Cmd signature="fd0 key add <name> [--import <path>]" body="Generate an ed25519 key, or import an existing OpenSSH key. Private bytes stay encrypted in fd0." />
    <Cmd signature="fd0 ssh add <alias> [user@]host[:port] --key <name>" body="Create a structured host entry and re-render ~/.ssh/fd0.conf." />
    <Cmd signature="fd0 ssh ls" body="List host aliases." />
    <Cmd signature="fd0 ssh show <alias>" body="Show the host record and rendered ssh_config block." />
    <Cmd signature="fd0 ssh rm <alias>" body="Remove the host entry and re-render the config." />

    <H2>Browse and transfer files</H2>
    <P>
      In fd0 Desktop, open an SSH host and choose <strong>Browse files</strong>.
      The dedicated Files window supports navigation, drag-and-drop uploads,
      downloads, folders, rename, delete, progress, and cancellation. It uses
      the same host, key, jump host, and strict host verification as{" "}
      <Code>fd0 ssh</Code>.
    </P>
    <Box>{`$ fd0 sftp prod-db
$ fd0 sftp ls prod-db /var/log
$ fd0 sftp tree prod-db /srv/app --depth 2
$ fd0 sftp cp prod-db ./release.tar remote:/tmp/release.tar
$ fd0 sftp cp prod-db remote:/var/log/app.log ./app.log`}</Box>
    <Cmd signature="fd0 sftp <host>" body="Open the native interactive SFTP client with fd0's exact rendered SSH configuration." />
    <Cmd signature="fd0 sftp ls <host> [path] [--json]" body="List a remote directory. Use --json for scripts." />
    <Cmd signature="fd0 sftp tree <host> [path] [--depth N]" body="Print a bounded remote tree. The default depth is 3." />
    <Cmd signature="fd0 sftp cp <host> <source> <dest>" body="Upload or download. Mark exactly one side with remote:, and add --recursive for directories." />
    <Cmd signature="fd0 sftp mkdir|mv|rm …" body="Manage remote paths. Non-interactive recursive delete requires both --recursive and --yes." />
    <Note>
      Transfers do not weaken host verification and never follow remote
      symlinks recursively. Existing destinations require an explicit{" "}
      <Code>--force</Code>; existing directory trees are never replaced
      implicitly.
    </Note>
    <P>
      Desktop file sessions are non-interactive: unlock fd0 first and assign a
      usable key to the host. If a host is new, open it in Terminal and verify
      its fingerprint before browsing files. A server without an enabled SFTP
      subsystem can still work in Terminal, but not in the Files window.
      Transfers stop when that window closes; fd0 is a file browser, not a
      background synchronization service.
    </P>

    <H2>Team sharing</H2>
    <P>
      Keys and hosts belong to scopes. Add a teammate to the scope and their
      next <Code>fd0 sync</Code> pulls the same key and host inventory. Native
      <Code>ssh</Code> works after that teammate enables fd0 SSH once on their
      device so their SSH config includes fd0 and <Code>SSH_AUTH_SOCK</Code>{" "}
      points at the fd0 agent. Remove them and the scope key rotates for future
      changes.
    </P>

    <H2>What fd0 does not do</H2>
    <P>
      fd0 does not edit remote <Code>sshd_config</Code>, deploy
      <Code>authorized_keys</Code>, or run <Code>ssh-copy-id</Code>. Use your
      normal provisioning tool for remote machines.
    </P>
  </>
);

const TalosKubeBody = () => (
  <>
    <P>
      fd0 stores Talos contexts and Kubernetes configs as typed secrets. It
      renders deterministic config files and can merge them into your normal
      tool config after sync.
    </P>

    <H2>Talos</H2>
    <Box>{`$ fd0 talos add --from-config ~/.talos/config \\
    --import-context prod --scope work
$ fd0 talos enable --merge
$ fd0 sync

$ talosctl --talosconfig ~/.talos/config.fd0 config contexts`}</Box>
    <P>
      Enabled Talos refresh means every <Code>fd0 sync</Code> re-renders{" "}
      <Code>~/.talos/config.fd0</Code>. With <Code>--merge</Code>, fd0 also
      folds those contexts into <Code>~/.talos/config</Code>.
    </P>

    <H2>Kubernetes</H2>
    <Box>{`$ fd0 kube add prod --from-config ~/.kube/config \\
    --import-context admin@prod --scope work
$ fd0 kube enable --merge
$ fd0 sync

$ kubectl --kubeconfig ~/.kube/config.fd0 get nodes`}</Box>
    <P>
      Enabled Kube refresh means every <Code>fd0 sync</Code> re-renders{" "}
      <Code>~/.kube/config.fd0</Code>. With <Code>--merge</Code>, fd0 also
      folds those entries into <Code>~/.kube/config</Code>.
    </P>

    <H2>Current context</H2>
    <P>
      When fd0 renders exactly one Talos or Kube context, it marks that context
      current. When it merges into an existing user config, it preserves your
      existing current context unless you change it yourself.
    </P>

    <H2>Day-0 Talos credentials</H2>
    <P>
      <Code>fd0 talos new</Code> can generate cluster PKI and store the
      disaster-recovery <Code>secrets.yaml</Code> bundle. That path shells out
      to <Code>talosctl</Code>. Normal add/list/render/merge paths are pure Go.
    </P>
  </>
);

const SyncBody = () => (
  <>
    <P>
      Sync moves signed encrypted events between your local files and one
      primary server. It also refreshes enabled local projections: SSH config,
      Talos config, and Kube config.
    </P>

    <H2>What sync does</H2>
    <Box>{`$ fd0 sync
-> push local events
-> pull remote events
-> verify signatures, hash links, STHs, and witness policy
-> discover new scopes
-> refresh enabled SSH/Talos/Kube projections`}</Box>

    <H2>One primary</H2>
    <P>
      A client reads and writes exactly one primary. That keeps each scope in
      one ordered history. Redundancy is handled by server-side disaster
      recovery, not by writing to multiple primaries.
    </P>

    <H2>Automatic sync</H2>
    <Box>{`[sync]
server = "https://api.fd0.sh"
interval = "1h"
on_unlock = true`}</Box>
    <P>
      <Code>interval</Code> enables background sync from the agent.{" "}
      <Code>on_unlock</Code> runs sync after a successful unlock.
    </P>

    <H2>Scope discovery</H2>
    <P>
      When someone adds you to a scope, your next sync discovers the scope,
      pulls its full event chain, decrypts your key delivery, and stores the
      scope locally.
    </P>
  </>
);

const ServerBody = () => (
  <>
    <P>
      You can use the hosted primary at fd0.sh or run your own primary. The
      client command surface is the same.
    </P>

    <H2>Hosted</H2>
    <Box>{`[sync]
server = "https://api.fd0.sh"`}</Box>
    <P>
      fd0.sh stores ciphertext and signed events only. The operator cannot
      decrypt user secrets.
    </P>

    <H2>Self-host</H2>
    <Box>{`$ mkdir fd0-server
$ cd fd0-server
$ curl -fsSLO https://fd0.sh/files/compose.yml
$ umask 077
$ printf 'METRICS_TOKEN=%s\\n' "$(openssl rand -hex 32)" > .env
$ case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\\n' 'ghcr.io/valentinkolb/fd0-server:latest-arm64' >> .env ;; esac
$ docker compose up -d`}</Box>
    <P>
      This starts one <Code>fd0-server</Code> on localhost port{" "}
      <Code>4048</Code>.
      Put your own TLS terminator in front before pointing real clients at it.
      Use{" "}
      <Link href="https://github.com/k2b-dev/fd0.sh/blob/main/docs/HOSTING.md">
        the production hosting runbook
      </Link>{" "}
      for backup, TLS, metrics, witness, and key-rotation details.
    </P>

    <H2>Disaster recovery</H2>
    <P>
      A standby can mirror the primary with <Code>FD0_REPLICATE_FROM</Code>.
      The standby is a recovery source, not a second writable primary.
    </P>
    <Box>{`# standby
FD0_REPLICATE_FROM=https://fd0.example.com
FD0_REPLICATE_INTERVAL=30s

# primary
FD0_PEERS=https://fd0-backup.example.com`}</Box>
    <Note>
      The quickstart writes the arm64 image override when it detects an ARM
      host. For production, pin a released image tag in <Code>.env</Code>.
    </Note>
  </>
);

const YubikeyBody = () => (
  <>
    <P>
      fd0 can use a YubiKey PIV slot as an unlock method. The slot private key
      stays on the device. Install the <Code>yubikey</Code> client flavor so
      both <Code>fd0</Code> and <Code>fd0-agent</Code> include PIV support.
    </P>

    <H2>Install</H2>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
$ fd0 version
fd0 0.11.0 yubikey
$ fd0 doctor`}</Box>

    <H2>Enroll</H2>
    <Box>{`$ fd0 auth add --yubikey
$ fd0 auth default yubikey
$ fd0 lock
$ fd0 unlock --method=yubikey`}</Box>
    <P>
      <Code>fd0 auth default yubikey</Code> stores a device-local preference
      in <Code>~/.fd0/config.toml</Code>, so plain <Code>fd0 unlock</Code>{" "}
      uses the YubiKey on this machine. <Code>fd0 doctor</Code> reports
      whether the CLI and running agent are both the YubiKey flavor. After an
      update, run{" "}
      <Code>fd0 agent restart</Code> before testing unlock.
    </P>

    <H2>Update</H2>
    <Box>{`$ fd0 update
$ fd0 update --flavor=standard   # switch away deliberately`}</Box>
    <P>
      A YubiKey install stays on the YubiKey release flavor during normal{" "}
      <Code>fd0 update</Code>. Switching back to the standard flavor is
      explicit.
    </P>

    <H2>Multiple readers</H2>
    <P>
      If more than one compatible reader is present, set{" "}
      <Code>FD0_YUBIKEY_CARD=&lt;substring&gt;</Code>. Without it, fd0 refuses
      to choose a card silently.
    </P>
  </>
);

const RecoveryBody = () => (
  <>
    <P>
      Recovery exports your identity key into a separate encrypted file. Keep
      the file and recovery passphrase offline.
    </P>

    <H2>Export</H2>
    <Box>{`$ fd0 recovery export ~/fd0-recovery.cbor`}</Box>

    <H2>Restore</H2>
    <Box>{`$ fd0 recovery import ~/fd0-recovery.cbor
$ fd0 unlock
$ fd0 sync`}</Box>
    <P>
      After import, sync discovers every scope where the restored identity is a
      member.
    </P>
  </>
);

const TroubleshootingBody = () => (
  <>
    <P>
      Start with <Code>fd0 doctor</Code>. It checks local chain state, vault
      bindings, auth wraps, orphan chain files, and the SSH agent socket.
    </P>

    <H2>Vault is locked</H2>
    <P>
      Interactive commands prompt for the passphrase when the agent is locked.
      Non-interactive commands fail instead of reading a secret from an unsafe
      input stream.
    </P>
    <Box>{`$ fd0 unlock
$ fd0 status`}</Box>

    <H2>ssh says unknown host</H2>
    <P>
      Run sync. If SSH integration is enabled, sync refreshes{" "}
      <Code>~/.ssh/fd0.conf</Code>. If this is the first setup on the machine,
      check that <Code>~/.ssh/config</Code> includes the fd0 config.
    </P>
    <Box>{`$ fd0 sync
$ ssh -G prod-db | grep -E 'hostname|identityagent|identityfile'`}</Box>
    <P>
      Run <Code>fd0 ssh enable</Code> once if the Include line is missing.
      You should not need to repeat it after normal fd0 SSH changes.
    </P>

    <H2>SSH agent socket is stale</H2>
    <P>
      If <Code>ssh-add -L</Code> returns connection refused, restart{" "}
      <Code>fd0-agent</Code>. <Code>fd0 doctor</Code> reports this state.
    </P>
    <Box>{`$ fd0 agent restart
$ SSH_AUTH_SOCK="$(fd0 ssh sock)" ssh-add -L`}</Box>

    <H2>kubectl or talosctl has no current context</H2>
    <P>
      Re-render the fd0 config. A single rendered context becomes current in
      the <Code>*.fd0</Code> file. Merges preserve your existing primary config
      current context.
    </P>
    <Box>{`$ fd0 kube sync --merge
$ fd0 talos sync --merge`}</Box>

    <H2>A new member cannot see a scope</H2>
    <P>
      The inviter must sync after adding the member. The new member then runs
      sync to discover and replay the scope.
    </P>
    <Box>{`# inviter
$ fd0 scope add-member bob --scope work
$ fd0 sync

# new member
$ fd0 sync`}</Box>
  </>
);

export const DocsOverview = ssr(async (c) => {
  setPageSeo(c, "docs");
  return () => (
    <DocsLayout current="overview" title="Documentation" kicker="Use fd0">
      <OverviewBody />
    </DocsLayout>
  );
});

export const DocsConcepts = ssr(async (c) => {
  setPageSeo(c, "docsConcepts");
  return () => (
    <DocsLayout current="concepts" title="Concepts" kicker="Mental model">
      <ConceptsBody />
    </DocsLayout>
  );
});

export const DocsInstall = ssr(async (c) => {
  setPageSeo(c, "docsInstall");
  return () => (
    <DocsLayout current="install" title="Install and start" kicker="First run">
      <InstallBody />
    </DocsLayout>
  );
});

export const DocsDesktop = ssr(async (c) => {
  setPageSeo(c, "docsDesktop");
  return () => (
    <DocsLayout current="desktop" title="fd0 Desktop" kicker="macOS and Linux">
      <DesktopBody />
    </DocsLayout>
  );
});

export const DocsPass = ssr(async (c) => {
  setPageSeo(c, "docsPass");
  return () => (
    <DocsLayout current="pass" title="Passwords" kicker="Password manager">
      <PassBody />
    </DocsLayout>
  );
});

export const DocsBrowser = ssr(async (c) => {
  setPageSeo(c, "docsBrowser");
  return () => (
    <DocsLayout current="browser" title="Browser extension" kicker="Chrome and Chromium">
      <BrowserBody />
    </DocsLayout>
  );
});

export const DocsCli = ssr(async (c) => {
  setPageSeo(c, "docsCli");
  return () => (
    <DocsLayout current="cli" title="Daily use" kicker="CLI">
      <CliBody />
    </DocsLayout>
  );
});

export const DocsSsh = ssr(async (c) => {
  setPageSeo(c, "docsSsh");
  return () => (
    <DocsLayout current="ssh" title="SSH keys, hosts, and files" kicker="Integration">
      <SshBody />
    </DocsLayout>
  );
});

export const DocsTalos = ssr(async (c) => {
  setPageSeo(c, "docsTalos");
  return () => (
    <DocsLayout current="talos" title="Talos and Kube" kicker="Integration">
      <TalosKubeBody />
    </DocsLayout>
  );
});

export const DocsSync = ssr(async (c) => {
  setPageSeo(c, "docsSync");
  return () => (
    <DocsLayout current="sync" title="Sync" kicker="State exchange">
      <SyncBody />
    </DocsLayout>
  );
});

export const DocsServer = ssr(async (c) => {
  setPageSeo(c, "docsServer");
  return () => (
    <DocsLayout current="server" title="Hosted or self-hosted" kicker="Backend">
      <ServerBody />
    </DocsLayout>
  );
});

export const DocsYubikey = ssr(async (c) => {
  setPageSeo(c, "docsYubikey");
  return () => (
    <DocsLayout current="yubikey" title="YubiKey unlock" kicker="Hardware">
      <YubikeyBody />
    </DocsLayout>
  );
});

export const DocsRecovery = ssr(async (c) => {
  setPageSeo(c, "docsRecovery");
  return () => (
    <DocsLayout current="recovery" title="Recovery" kicker="Backup identity">
      <RecoveryBody />
    </DocsLayout>
  );
});

export const DocsTroubleshooting = ssr(async (c) => {
  setPageSeo(c, "docsTroubleshooting");
  return () => (
    <DocsLayout current="troubleshooting" title="Troubleshooting" kicker="Fix common states">
      <TroubleshootingBody />
    </DocsLayout>
  );
});

export default DocsOverview;
