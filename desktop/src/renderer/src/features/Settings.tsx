import { Show, createMemo, createSignal, onMount, type JSX } from "solid-js";
import type {
  TerminalLauncherSettings,
  TerminalLauncherState,
  TerminalProfileID,
  TerminalTheme,
} from "../../../shared/contracts";
import { plural } from "../lib/format";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Field, Input, Select, Switch, Textarea } from "../ui/Fields";

/**
 * Device settings.
 *
 * Two rules shape this panel. Anything fd0 does not actually let you change
 * here is stated as a fact with its reason instead of being rendered as a dead
 * control, and the one unfinished safety step — the recovery file — is allowed
 * to shout, because losing it is the only unrecoverable failure in the product.
 */
export function Settings(props: { onExportRecovery(): void; onShowShortcuts(): void }): JSX.Element {
  const vault = useVault();
  const [launchAtLogin, setLaunchAtLogin] = createSignal(false);
  const [terminal, setTerminal] = createSignal<TerminalLauncherState | null>(null);
  const [terminalProfile, setTerminalProfile] = createSignal<TerminalProfileID>("in-app");
  const [terminalTheme, setTerminalTheme] = createSignal<TerminalTheme>("system");
  const [customExecutable, setCustomExecutable] = createSignal("");
  const [customArguments, setCustomArguments] = createSignal("");

  // A development run uses a throwaway profile, so registering a login item
  // would point the real session at a vault that is about to be deleted.
  const inDevelopment = window.fd0.development;

  onMount(() => {
    void window.fd0
      .launchAtLogin()
      .then(setLaunchAtLogin)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not read your startup setting");
      });
    void window.fd0
      .terminalLauncher()
      .then(applyTerminalState)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not read your terminal setting");
      });
  });

  const authMethods = () => vault.status()?.authMethods ?? [];
  const defaultMethod = () => authMethods().find((method) => method.default)?.id ?? "";
  const terminalOptions = createMemo(() => {
    const state = terminal();
    if (!state) return [{ value: "in-app", label: "In fd0" }];
    return state.profiles
      .filter((profile) => profile.available || profile.id === state.settings.profileId)
      .map((profile) => ({
        value: profile.id,
        label: profile.label,
        hint:
          profile.id === "automatic" && state.automaticProfileId
            ? `Currently uses ${state.profiles.find((candidate) => candidate.id === state.automaticProfileId)?.label ?? "the system default"}`
            : profile.available
              ? profile.description
              : `${profile.description} Not detected on this device.`,
      }));
  });

  const lockingValue = createMemo(() => {
    const millis = vault.status()?.idleTimeoutMillis;
    if (!millis) return "Managed by fd0";
    // Sub-minute timeouts exist in test profiles; never round them away to zero.
    const minutes = Math.max(1, Math.round(millis / 60_000));
    return `After ${plural(minutes, "minute")}`;
  });

  function changeLaunchAtLogin(value: boolean): void {
    void window.fd0
      .setLaunchAtLogin(value)
      .then(setLaunchAtLogin)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not change your startup setting");
      });
  }

  function applyTerminalState(state: TerminalLauncherState): void {
    setTerminal(state);
    setTerminalProfile(state.settings.profileId);
    setTerminalTheme(state.settings.terminalTheme);
    setCustomExecutable(state.settings.customExecutable);
    setCustomArguments(state.settings.customArguments.join("\n"));
  }

  function storedTerminalSettings(profileId: TerminalProfileID): TerminalLauncherSettings {
    const stored = terminal()?.settings;
    return {
      profileId,
      terminalTheme: stored?.terminalTheme ?? "system",
      customExecutable: stored?.customExecutable ?? "",
      customArguments: stored?.customArguments ?? [],
    };
  }

  function saveTerminalSettings(settings: TerminalLauncherSettings): void {
    void window.fd0
      .setTerminalLauncher(settings)
      .then((state) => {
        applyTerminalState(state);
        vault.notify("Terminal launcher updated");
      })
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not save your terminal setting");
      });
  }

  function changeTerminalProfile(value: string): void {
    const profile = terminal()?.profiles.find((candidate) => candidate.id === value);
    if (!profile) return;
    setTerminalProfile(profile.id);
    if (profile.id !== "custom") saveTerminalSettings(storedTerminalSettings(profile.id));
  }

  function saveCustomTerminal(): void {
    saveTerminalSettings({
      profileId: "custom",
      terminalTheme: terminalTheme(),
      customExecutable: customExecutable().trim(),
      customArguments: customArguments()
        .split("\n")
        .map((argument) => argument.trim())
        .filter(Boolean),
    });
  }

  function changeTerminalTheme(value: string): void {
    if (value !== "system" && value !== "light" && value !== "dark") return;
    setTerminalTheme(value);
    saveTerminalSettings({
      ...storedTerminalSettings(terminalProfile()),
      terminalTheme: value,
    });
  }

  function changeDefaultMethod(method: string): void {
    void window.fd0
      .setDefaultAuthMethod(method)
      .then((next) => {
        vault.setStatus(next);
        vault.notify("Default unlock method updated");
      })
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not change the default unlock method");
      });
  }

  function openBrowserLink(target: "browser" | "browserDocs"): void {
    void window.fd0.openSupportLink(target).catch((cause: unknown) => {
      vault.fail(cause, "fd0 could not open the browser extension link");
    });
  }

  return (
    <section class="panel">
      <header class="panel-header">
        <h1>Settings</h1>
        <p>Control how fd0 behaves on this device.</p>
      </header>

      <div class="panel-column">
        <section class="setting-group">
          <h2 class="eyebrow">Appearance</h2>
          <div class="setting-row">
            <div>
              <strong>Color theme</strong>
              <small>Follow your operating system or choose a fixed theme.</small>
            </div>
            <Select
              label="Color theme"
              value={vault.theme()}
              onChange={(value) => {
                if (value === "system" || value === "light" || value === "dark") vault.setTheme(value);
              }}
              options={[
                { value: "system", label: "System" },
                { value: "light", label: "Light" },
                { value: "dark", label: "Dark" },
              ]}
            />
          </div>
          <Switch
            label="Compact rows"
            description="Fit more items on screen without making the text smaller."
            checked={vault.compactRows()}
            onChange={(value) => vault.setCompactRows(value)}
          />
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Desktop</h2>
          <Switch
            label="Open at login"
            description={
              inDevelopment
                ? "Unavailable while fd0 runs in development, which uses a temporary vault."
                : "Keep fd0 ready in the menu bar after you sign in."
            }
            checked={launchAtLogin()}
            disabled={inDevelopment}
            onChange={changeLaunchAtLogin}
          />
          <div class="setting-row">
            <div>
              <strong>SSH terminal</strong>
              <small>Choose where Open in terminal starts SSH sessions on this device.</small>
            </div>
            <Select
              label="SSH terminal"
              value={terminalProfile()}
              disabled={!terminal()}
              onChange={changeTerminalProfile}
              options={terminalOptions()}
            />
          </div>
          <Show when={terminalProfile() === "in-app"}>
            <div class="setting-row">
              <div>
                <strong>Terminal theme</strong>
                <small>Choose the fd0 terminal appearance independently from the app.</small>
              </div>
              <Select
                label="Terminal theme"
                value={terminalTheme()}
                onChange={changeTerminalTheme}
                options={[
                  { value: "system", label: "System" },
                  { value: "light", label: "Light" },
                  { value: "dark", label: "Dark" },
                ]}
              />
            </div>
          </Show>
          <Show when={terminalProfile() === "custom"}>
            <div class="terminal-custom-settings">
              <Field
                label="Executable or wrapper"
                hint="Use an absolute path. fd0 appends its SSH command as separate arguments."
              >
                {(field) => (
                  <Input
                    id={field.id}
                    aria-describedby={field.describedBy}
                    value={customExecutable()}
                    placeholder="/opt/bin/my-terminal-wrapper"
                    spellcheck={false}
                    onInput={(event) => setCustomExecutable(event.currentTarget.value)}
                  />
                )}
              </Field>
              <Field
                label="Arguments before fd0"
                hint="Optional. Enter one exact argument per line; no shell parsing is used."
                optional
              >
                {(field) => (
                  <Textarea
                    id={field.id}
                    aria-describedby={field.describedBy}
                    value={customArguments()}
                    rows={3}
                    spellcheck={false}
                    placeholder={"--new-window\n-e"}
                    onInput={(event) => setCustomArguments(event.currentTarget.value)}
                  />
                )}
              </Field>
              <div class="terminal-custom-actions">
                <Button onClick={saveCustomTerminal}>Save launcher</Button>
              </div>
            </div>
          </Show>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Browser</h2>
          <div class="setting-row">
            <div>
              <strong>Chrome extension</strong>
              <small>Fill passwords and one-time codes from this fd0 vault in Chrome and Chromium browsers.</small>
            </div>
            <div class="support-actions">
              <Button onClick={() => openBrowserLink("browserDocs")}>Setup guide</Button>
              <Button variant="primary" onClick={() => openBrowserLink("browser")}>
                Open Chrome Web Store
              </Button>
            </div>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Security</h2>
          <Show when={(vault.status()?.sshGrantCount ?? 0) > 0}>
            <div class="setting-row">
              <div><strong>SSH access while locked</strong><small>{vault.status()?.sshGrantCount} active grants on this device. Existing SSH connections stay open.</small></div>
              <Button onClick={() => void vault.lock(true)}>Lock everything</Button>
            </div>
          </Show>

          <Show when={authMethods().length > 1}>
            <div class="setting-row">
              <div>
                <strong>Default unlock method</strong>
                <small>Tried first when fd0 opens this vault on this device.</small>
              </div>
              <Select
                label="Default unlock method"
                value={defaultMethod()}
                onChange={changeDefaultMethod}
                options={[
                  { value: "", label: "Automatic", hint: "Whichever method fd0 considers best" },
                  ...authMethods().map((method) => ({ value: method.id, label: method.label })),
                ]}
              />
            </div>
          </Show>

          <div class="setting-row setting-static">
            <div>
              <strong>Clipboard</strong>
              <small>Copied secrets are cleared automatically.</small>
            </div>
            <span class="setting-value">After 30 seconds</span>
          </div>

          <div class="setting-row setting-static">
            <div>
              <strong>Automatic locking</strong>
              <small>
                fd0 locks itself after a period of inactivity. This is enforced outside the app and cannot be
                changed here.
              </small>
            </div>
            <span class="setting-value">{lockingValue()}</span>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Backup</h2>
          <Show
            when={vault.needsRecovery()}
            fallback={
              <div class="setting-row">
                <div>
                  <strong>Recovery file</strong>
                  <small>An offline copy of this vault's identity, protected by its own passphrase.</small>
                </div>
                <Button onClick={props.onExportRecovery}>Export…</Button>
              </div>
            }
          >
            <div class="callout callout-warn">
              <span class="eyebrow">Not set up yet</span>
              <div class="setting-row">
                <div>
                  <strong>Recovery file</strong>
                  <small>
                    This is the only way back into your vault if you lose this device. It is protected by its own
                    passphrase, and nobody can recreate it for you — not even fd0.
                  </small>
                </div>
                <Button variant="primary" onClick={props.onExportRecovery}>
                  Create recovery file
                </Button>
              </div>
            </div>
          </Show>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Keyboard</h2>
          <div class="setting-row">
            <div>
              <strong>Shortcuts</strong>
              <small>fd0 is fully operable from the keyboard.</small>
            </div>
            <Button onClick={props.onShowShortcuts}>View all shortcuts</Button>
          </div>
        </section>
      </div>
    </section>
  );
}
