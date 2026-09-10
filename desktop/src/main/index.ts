import { basename, dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { createReadStream } from "node:fs";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  Menu,
  nativeTheme,
  nativeImage,
  protocol,
  powerMonitor,
  screen,
  session,
  shell,
  net,
  Tray,
  type MessageBoxOptions,
  type MenuItemConstructorOptions,
} from "electron";
import electronUpdater from "electron-updater";
import { BridgeSupervisor, DesktopBridgeError } from "./bridge";
import { AgentLifecycle } from "./agent-lifecycle";
import { DesktopAutoLock, type SecurityLockReason } from "./auto-lock";
import { ManagedClipboard } from "./managed-clipboard";
import { supportLink, trustedItemURL, type SupportLinkTarget } from "./external-links";
import { OperationGrants, type OperationGrantKind } from "./operation-grants";
import { DiagnosticsLog, persistedSyncState, redactDiagnosticText } from "./diagnostics";
import {
  checksumForAsset,
  compareSemver,
  linuxDesktopAssetName,
  requireSelectedNewerRelease,
  selectDesktopRelease,
  type DesktopRelease,
} from "./release-verification";
import {
  buildTerminalLaunchPlan,
  detectTerminalEnvironment,
  readTerminalLauncherSettings,
  spawnTerminal,
  terminalLauncherState,
  writeTerminalLauncherSettings,
} from "./terminal-launcher";
import { TerminalSessionManager, verifyTerminalRuntime } from "./terminal-session";
import { SFTPBridgeClient } from "./sftp-bridge";
import type {
  BridgeErrorShape,
  DesktopCommand,
  DesktopTheme,
  DiagnosticsSnapshot,
  FieldRef,
  FieldView,
  GenerateSSHKeyInput,
  IdentityCardInfo,
  Inventory,
  ItemDetail,
  ItemSummary,
  ItemVersionRef,
  LargeTypeValue,
  LargeTypeWindowResult,
  MoveItemInput,
  OrganizationBatch, RecordRef,
  RenameItemInput,
  ResolvedDesktopTheme,
  SavePassInput,
  SaveSSHKeyInput,
  SaveSSHHostInput,
  SaveSecretInput,
  ScopeShareInfo,
  StartupStatus,
  SFTPEntry,
  SFTPPreview,
  SFTPProgress,
  SFTPSessionInfo,
  SFTPTransferEvent,
  SyncPreparation,
  TerminalLauncherSettings,
  TerminalLauncherState,
  TerminalSessionInfo,
  TerminalTheme,
  UnlockInput,
  UpdateStatus,
  VaultStatus,
} from "../shared/contracts";

let mainWindow: BrowserWindow | null = null;
let desktopTheme: DesktopTheme = "system";
const terminalSessions = new TerminalSessionManager();
type TerminalWindowState = {
  window: BrowserWindow;
  sessionId: string;
  host: string;
  theme: TerminalTheme;
  processName: string;
  remoteTitle: string;
};
const terminalWindows = new Map<number, TerminalWindowState>();
type FileWindowState = {
  window: BrowserWindow;
  client: SFTPBridgeClient;
  host: string;
  theme: TerminalTheme;
  alias: string;
  scopeId: string;
  environment: NodeJS.ProcessEnv;
  activeTransfers: Set<string>;
};
const fileWindows = new Map<number, FileWindowState>();
let bridge: BridgeSupervisor | null = null;
const agentLifecycle = new AgentLifecycle();
const managedClipboard = new ManagedClipboard(clipboard);
const operationGrants = new OperationGrants();
let tray: Tray | null = null;
let updateTimer: NodeJS.Timeout | null = null;
let installingUpdate = false;
let updateState: UpdateStatus = { state: app.isPackaged ? "idle" : "unsupported" };
let selectedUpdateRelease: DesktopRelease | null = null;
let autoLock: DesktopAutoLock | null = null;
let disposeAutoLockEvents: (() => void) | null = null;
let securityStatusTimer: NodeJS.Timeout | null = null;
let securityStatusRefreshing = false;
let lastObservedUnlocked: boolean | undefined;
let lastVaultStatus: VaultStatus | null = null;
let diagnostics: DiagnosticsLog | null = null;
let startupStatus: StartupStatus = { state: "starting" };
let domainIPCRegistered = false;
let servicesStarting: Promise<StartupStatus> | null = null;
let syncState: DiagnosticsSnapshot["sync"] = { state: "never" };
let selectedRecoveryFile: { path: string; version: 1 | 2 } | null = null;
const { autoUpdater } = electronUpdater;
const desktopUpdateRequestArg = "--fd0-desktop-update";
const terminalRuntimeSmokeArg = "--fd0-terminal-runtime-smoke";
const applicationRoot = app.isPackaged ? app.getAppPath() : resolve(import.meta.dirname, "../..");
const nativeAgentManaged = app.isPackaged
  && process.env.FD0_HOME === undefined
  && process.env.FD0_SSH_SOCK === undefined;
let pendingDesktopUpdateRequest = process.argv.includes(desktopUpdateRequestArg);
let rendererDesktopUpdateRequested = false;
let updaterConfigured = false;

app.setName("fd0");
if (!app.isPackaged) app.setPath("userData", requiredEnv("FD0_DESKTOP_USER_DATA"));
nativeTheme.themeSource = "system";
protocol.registerSchemesAsPrivileged([
  {
    scheme: "fd0-app",
    privileges: {
      standard: true,
      secure: true,
      codeCache: true,
    },
  },
]);

const lifecycleCommand = process.argv.find((value) => [
  "--fd0-agent-service-stop",
  "--fd0-agent-service-restart",
  "--fd0-agent-service-uninstall",
].includes(value));
const terminalRuntimeSmokeRequested = process.argv.includes(terminalRuntimeSmokeArg);
const relayExitCode = runPackagedRelay();
if (relayExitCode !== null) process.exit(relayExitCode);

if (!lifecycleCommand && !terminalRuntimeSmokeRequested && !app.requestSingleInstanceLock()) {
  app.quit();
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for the isolated desktop build`);
  return value;
}

function runtimeEnvironment(): NodeJS.ProcessEnv {
  const inherited = Object.fromEntries(
    ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "SHELL"]
      .map((name) => [name, process.env[name]])
      .filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
  if (app.isPackaged) {
    return {
      ...inherited,
      FD0_HOME: process.env.FD0_HOME?.trim() || join(homedir(), ".fd0"),
      FD0_AGENT_BIN: join(process.resourcesPath, "bin", "fd0-agent"),
      FD0_BIN: join(process.resourcesPath, "bin", "fd0"),
      FD0_SFTP_BRIDGE_BIN: join(process.resourcesPath, "bin", "fd0-sftp-bridge"),
      FD0_DESKTOP_MODE: "system",
      FD0_DESKTOP_VERSION: app.getVersion(),
      ...(process.platform === "linux"
        ? { LD_LIBRARY_PATH: join(process.resourcesPath, "runtime") }
        : {}),
      ...(nativeAgentManaged ? { FD0_AGENT_MANAGED: "1" } : {}),
      ...(process.env.FD0_SSH_SOCK !== undefined ? { FD0_SSH_SOCK: process.env.FD0_SSH_SOCK } : {}),
    };
  }
  return {
    ...inherited,
    FD0_HOME: requiredEnv("FD0_HOME"),
    FD0_SSH_SOCK: requiredEnv("FD0_SSH_SOCK"),
    FD0_AGENT_BIN: requiredEnv("FD0_AGENT_BIN"),
    FD0_BIN: requiredEnv("FD0_BIN"),
    FD0_SFTP_BRIDGE_BIN: requiredEnv("FD0_SFTP_BRIDGE_BIN"),
    FD0_DESKTOP_MODE: "isolated",
    FD0_AGENT_SYNC_DISABLED: "1",
    FD0_SSH_CONFIG_PATH: requiredEnv("FD0_SSH_CONFIG_PATH"),
    FD0_KUBE_CONFIG_PATH: requiredEnv("FD0_KUBE_CONFIG_PATH"),
    FD0_KUBE_USER_CONFIG: requiredEnv("FD0_KUBE_USER_CONFIG"),
    FD0_TALOS_CONFIG_PATH: requiredEnv("FD0_TALOS_CONFIG_PATH"),
    FD0_TALOS_USER_CONFIG: requiredEnv("FD0_TALOS_USER_CONFIG"),
  };
}

function bridgeBinary(): string {
  if (!app.isPackaged) return requiredEnv("FD0_DESKTOP_BRIDGE_BIN");
  return join(process.resourcesPath, "bin", "fd0-desktop-bridge");
}

function sftpBridgeBinary(): string {
  if (!app.isPackaged) return requiredEnv("FD0_SFTP_BRIDGE_BIN");
  return join(process.resourcesPath, "bin", "fd0-sftp-bridge");
}

function terminalLauncherSettingsPath(): string {
  return join(app.getPath("userData"), "terminal-launcher.json");
}

async function currentTerminalLauncherState(
  settings?: TerminalLauncherSettings,
): Promise<TerminalLauncherState> {
  const environment = runtimeEnvironment();
  const current =
    settings ??
    (await readTerminalLauncherSettings(terminalLauncherSettingsPath(), process.platform));
  const detection = await detectTerminalEnvironment({
    platform: process.platform,
    environment,
  });
  return terminalLauncherState(process.platform, current, detection);
}

function runPackagedRelay(): number | null {
  if (!app.isPackaged) return null;
  const relays = [
    { marker: "--fd0-cli-relay", binary: "fd0" },
    { marker: "--fd0-agent-relay", binary: "fd0-agent" },
    { marker: "--fd0-browser-host-relay", binary: "fd0-browser-host" },
  ];
  const selected = relays
    .map((relay) => ({ ...relay, index: process.argv.indexOf(relay.marker) }))
    .filter((relay) => relay.index >= 0);
  if (selected.length === 0) return null;
  if (selected.length !== 1) {
    console.error("fd0 Desktop: invalid CLI relay request");
    return 2;
  }
  const relay = selected[0]!;
  const executable = join(process.resourcesPath, "bin", relay.binary);
  const result = spawnSync(executable, process.argv.slice(relay.index + 1), {
    env: {
      ...runtimeEnvironment(),
      FD0_DESKTOP_MANAGED: "1",
      FD0_DESKTOP_APP: process.env.APPIMAGE || process.execPath,
      ...(relay.binary === "fd0" && process.env.FD0_BROWSER_HOST_BIN
        ? { FD0_BROWSER_HOST_BIN: process.env.FD0_BROWSER_HOST_BIN }
        : {}),
      // Only the agent relay — the systemd unit's ExecStart — is this app
      // starting a service of its own. An agent that `fd0 unlock` happens to
      // spawn through the CLI relay belongs to that shell session, and marking
      // it as ours would licence this app to stop it.
      ...(relay.binary === "fd0-agent" ? { FD0_AGENT_STARTED_BY: "desktop" } : {}),
    },
    stdio: "inherit",
  });
  if (result.error) {
    console.error(`fd0 Desktop: ${result.error.message}`);
    return 1;
  }
  return result.status ?? 1;
}

function sendCommand(command: DesktopCommand): void {
  mainWindow?.webContents.send("desktop:command", command);
}

function publishUpdate(status: UpdateStatus): void {
  updateState = status;
  diagnostics?.record("updater", `state:${status.state}`, status.state === "error" ? status.message : undefined);
  mainWindow?.webContents.send("desktop:update", status);
}

function showAppMessageBox(options: MessageBoxOptions) {
  return mainWindow ? dialog.showMessageBox(mainWindow, options) : dialog.showMessageBox(options);
}

function flushDesktopUpdateRequest(): void {
  if (!pendingDesktopUpdateRequest || !updaterConfigured || !mainWindow || mainWindow.webContents.isLoadingMainFrame()) {
    return;
  }
  pendingDesktopUpdateRequest = false;
  rendererDesktopUpdateRequested = true;
  showMainWindow();
  sendCommand("open-support");
  void checkForUpdates();
}

function requestDesktopUpdate(): void {
  pendingDesktopUpdateRequest = true;
  showMainWindow();
  flushDesktopUpdateRequest();
}

async function checkForUpdates(): Promise<UpdateStatus> {
  if (!app.isPackaged) return updateState;
  selectedUpdateRelease = null;
  publishUpdate({ state: "checking" });
  try {
    const release = await resolveDesktopUpdateRelease();
    if (compareSemver(release.version, app.getVersion()) <= 0) {
      selectedUpdateRelease = null;
      publishUpdate({ state: "current", version: app.getVersion() });
      return updateState;
    }
    selectedUpdateRelease = release;
    autoUpdater.setFeedURL({ provider: "generic", url: release.feedURL });
    await autoUpdater.checkForUpdates();
  } catch (error) {
    console.error("fd0 update check failed", error);
    publishUpdate({ state: "error", message: "Could not check for updates." });
  }
  return updateState;
}

async function resolveDesktopUpdateRelease(): Promise<DesktopRelease> {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": `fd0-desktop/${app.getVersion()}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const allowPrerelease = app.getVersion().includes("-");
  try {
    const response = await net.fetch("https://fd0.sh/api/desktop/releases", { headers });
    if (response.ok) {
      const release = selectDesktopRelease(await response.json() as unknown, allowPrerelease);
      if (release) return release;
    }
  } catch {
    // The authenticated artifact path below remains available through GitHub.
  }

  const payload: unknown[] = [];
  for (let page = 1; page <= 20; page++) {
    const response = await net.fetch(
      `https://api.github.com/repos/k2b-dev/fd0.sh/releases?per_page=100&page=${page}`,
      { headers },
    );
    if (!response.ok) throw new Error(`GitHub release lookup failed with HTTP ${response.status}`);
    const pagePayload = await response.json() as unknown;
    if (!Array.isArray(pagePayload)) throw new Error("GitHub release lookup returned invalid data");
    payload.push(...pagePayload);
    if (pagePayload.length < 100) break;
  }
  const release = selectDesktopRelease(payload, allowPrerelease);
  if (!release) throw new Error("No fd0 Desktop release is available");
  return release;
}

async function fetchReleaseFile(release: DesktopRelease, name: string, maxBytes = 4 << 20): Promise<Uint8Array> {
  const response = await net.fetch(new URL(name, release.feedURL).toString());
  if (!response.ok) throw new Error(`Could not fetch ${name}: HTTP ${response.status}`);
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error(`${name} exceeds the update metadata limit`);
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.byteLength > maxBytes) throw new Error(`${name} exceeds the update metadata limit`);
  return body;
}

async function verifyDownloadedDesktopUpdate(version: string, downloadedFile: string): Promise<void> {
  if (process.platform !== "linux") return;
  const release = requireSelectedNewerRelease(selectedUpdateRelease, version, app.getVersion());
  const assetName = linuxDesktopAssetName(version, process.arch);
  const [manifestBytes, signatureBundle, actual] = await Promise.all([
    fetchReleaseFile(release, "checksums.txt"),
    fetchReleaseFile(release, "checksums.txt.sigstore.json"),
    sha256Path(downloadedFile),
  ]);
  const manifest = new TextDecoder().decode(manifestBytes);
  const expected = checksumForAsset(manifest, assetName);
  if (actual !== expected) throw new Error("Downloaded update does not match the authenticated release manifest");

  const root = await mkdtemp(join(tmpdir(), "fd0-update-"));
  try {
    const manifestPath = join(root, "checksums.txt");
    const bundlePath = join(root, "checksums.txt.sigstore.json");
    await Promise.all([
      writeFile(manifestPath, manifestBytes, { mode: 0o600 }),
      writeFile(bundlePath, signatureBundle, { mode: 0o600 }),
    ]);
    const verifier = join(process.resourcesPath, "bin", "fd0-release-verify");
    const verification = spawnSync(verifier, [
      "--bundle", bundlePath,
      "--tag", release.tag,
      manifestPath,
    ], {
      env: runtimeEnvironment(),
      encoding: "utf8",
      timeout: 30_000,
    });
    if (verification.error) throw verification.error;
    if (verification.status !== 0) {
      throw new Error("fd0 rejected the desktop release signature");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function sha256Path(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function isExpectedUpdateVersion(version: string): boolean {
  try {
    return selectedUpdateRelease?.version === version && compareSemver(version, app.getVersion()) > 0;
  } catch {
    return false;
  }
}

function announceDownloadedUpdate(version: string): void {
  publishUpdate({ state: "ready", version, progress: 100 });
  void showAppMessageBox({
    type: "info",
    buttons: ["Restart fd0", "Later"],
    defaultId: 0,
    cancelId: 1,
    title: "fd0 is ready to update",
    message: `fd0 ${version} has been downloaded.`,
    detail: "Restart now to install it. fd0 will stop the current agent so the app, CLI, and agent stay on one version.",
    noLink: true,
  }).then((answer) => {
    if (answer.response === 0) {
      void installReadyUpdate().catch((error) => {
        console.error("fd0 update install failed", error);
        publishUpdate({ state: "error", message: "Could not prepare fd0 for the update." });
      });
    }
  });
}

function configureUpdater(): void {
  updaterConfigured = true;
  if (!app.isPackaged) return;
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowPrerelease = app.getVersion().includes("-");
  if (process.platform === "darwin") autoUpdater.channel = process.arch;
  autoUpdater.allowDowngrade = false;
  autoUpdater.on("checking-for-update", () => publishUpdate({ state: "checking" }));
  autoUpdater.on("update-not-available", () => publishUpdate({ state: "current", version: app.getVersion() }));
  autoUpdater.on("update-available", (info) => {
    if (!isExpectedUpdateVersion(info.version)) {
      publishUpdate({ state: "error", message: "The update feed returned an unexpected release." });
      return;
    }
    publishUpdate({ state: "available", version: info.version });
    void showAppMessageBox({
      type: "info",
      buttons: ["Download", "Later"],
      defaultId: 0,
      cancelId: 1,
      title: "fd0 update available",
      message: `fd0 ${info.version} is available.`,
      detail: "Download the signed update now? You can keep using fd0 while it downloads.",
      noLink: true,
    }).then((answer) => {
      if (answer.response !== 0) return;
      publishUpdate({ state: "downloading", version: info.version, progress: 0 });
      void autoUpdater.downloadUpdate().catch((error) => {
        console.error("fd0 update download failed", error);
        publishUpdate({ state: "error", message: "Could not download the update." });
      });
    });
  });
  autoUpdater.on("download-progress", (progress) => {
    publishUpdate({ state: "downloading", version: updateState.version, progress: Math.max(0, Math.min(100, progress.percent)) });
  });
  autoUpdater.on("update-downloaded", (info) => {
    void verifyDownloadedDesktopUpdate(info.version, info.downloadedFile)
      .then(() => announceDownloadedUpdate(info.version))
      .catch((error) => {
        console.error("fd0 update authentication failed", error);
        publishUpdate({
          state: "error",
          message: error instanceof Error ? error.message : "Could not authenticate the downloaded update.",
        });
      });
  });
  autoUpdater.on("error", (error) => {
    console.error("fd0 updater error", error);
    publishUpdate({ state: "error", message: "The updater encountered an error." });
  });
  updateTimer = setTimeout(() => {
    void checkForUpdates();
    updateTimer = setInterval(() => void checkForUpdates(), 6 * 60 * 60_000);
  }, 15_000);
}

async function installReadyUpdate(): Promise<void> {
  if (updateState.state !== "ready") throw new Error("No downloaded fd0 update is ready to install");
  if (installingUpdate) return;
  installingUpdate = true;
  try {
    if (nativeAgentManaged) {
      await agentLifecycle.stop();
    } else if (bridge) {
      await bridge.request("agent.prepareUpdate", {}, 10_000);
    }
    setTimeout(() => autoUpdater.quitAndInstall(false, true), 100);
  } catch (error) {
    installingUpdate = false;
    throw error;
  }
}

function observeVaultStatus(status: VaultStatus): VaultStatus {
  lastVaultStatus = status;
  const lockedTransition = lastObservedUnlocked === true && !status.unlocked;
  lastObservedUnlocked = status.unlocked;
  autoLock?.observe(status);
  if (lockedTransition) {
    closeLargeTypeWindow();
    managedClipboard.clear();
    operationGrants.clear();
    sendCommand("refresh");
  }
  return status;
}

async function refreshSecurityStatus(): Promise<void> {
  if (!bridge || securityStatusRefreshing) return;
  securityStatusRefreshing = true;
  try {
    observeVaultStatus(await bridge.request<VaultStatus>("vault.status", {}));
  } catch (error) {
    console.error("fd0 security status refresh failed", error);
  } finally {
    securityStatusRefreshing = false;
  }
}

async function requestVaultLock(): Promise<void> {
  if (!bridge) throw new Error("fd0 bridge is unavailable");
  const status = await bridge.request<VaultStatus>("vault.lock", {});
  observeVaultStatus(status);
  closeLargeTypeWindow();
  managedClipboard.clear();
  operationGrants.clear();
  sendCommand("refresh");
}

function writeManagedClipboard(value: string): { clearAfterSeconds: number } {
  managedClipboard.write(value);
  return { clearAfterSeconds: 30 };
}

function reportAutomaticLockFailure(error: unknown): void {
  console.error("fd0 automatic lock failed", error);
}

function configureAutoLock(): () => void {
  autoLock = new DesktopAutoLock({
    getSystemIdleState: (thresholdSeconds) => powerMonitor.getSystemIdleState(thresholdSeconds),
    lock: async (_reason: SecurityLockReason) => requestVaultLock(),
    onError: reportAutomaticLockFailure,
  });
  autoLock.start();

  const lockFor = (reason: SecurityLockReason) => {
    void autoLock?.lockNow(reason, true).catch(reportAutomaticLockFailure);
  };
  const onSuspend = () => lockFor("suspend");
  const onResume = () => lockFor("resume");
  const onLockScreen = () => lockFor("system-lock");
  const onSessionInactive = () => lockFor("session-inactive");
  powerMonitor.on("suspend", onSuspend);
  powerMonitor.on("resume", onResume);
  if (process.platform === "darwin" || process.platform === "win32") {
    powerMonitor.on("lock-screen", onLockScreen);
  }
  if (process.platform === "darwin") {
    powerMonitor.on("user-did-resign-active", onSessionInactive);
  }

  return () => {
    autoLock?.stop();
    powerMonitor.removeListener("suspend", onSuspend);
    powerMonitor.removeListener("resume", onResume);
    if (process.platform === "darwin" || process.platform === "win32") {
      powerMonitor.removeListener("lock-screen", onLockScreen);
    }
    if (process.platform === "darwin") {
      powerMonitor.removeListener("user-did-resign-active", onSessionInactive);
    }
    autoLock = null;
  };
}

async function lockVaultFromMain(): Promise<void> {
  try {
    await requestVaultLock();
  } catch (error) {
    dialog.showErrorBox("fd0 could not lock", error instanceof Error ? error.message : String(error));
  }
}

function showMainWindow(): void {
  if (!mainWindow) mainWindow = createWindow();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function createTray(): void {
  const source = join(applicationRoot, "resources", "tray.png");
  const image = nativeImage.createFromPath(source).resize({ width: 18, height: 18 });
  if (process.platform === "darwin") image.setTemplateImage(true);
  tray = new Tray(image);
  tray.setToolTip("fd0");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open fd0", click: showMainWindow },
    { type: "separator" },
    { label: "Lock Vault", click: () => void lockVaultFromMain() },
    { type: "separator" },
    { label: "Quit fd0", click: () => app.quit() },
  ]));
  tray.on("click", showMainWindow);
}

function buildMenu(): void {
  const isMac = process.platform === "darwin";
  const template: MenuItemConstructorOptions[] = [
    ...(isMac
      ? [
          {
            label: "fd0",
            submenu: [
              { role: "about" as const },
              { type: "separator" as const },
              {
                label: "Settings…",
                accelerator: "CmdOrCtrl+,",
                click: () => sendCommand("open-settings"),
              },
              { type: "separator" as const },
              { role: "services" as const },
              { type: "separator" as const },
              { role: "hide" as const },
              { role: "hideOthers" as const },
              { role: "unhide" as const },
              { type: "separator" as const },
              { role: "quit" as const },
            ],
          },
        ]
      : []),
    {
      label: "File",
      submenu: [
        { label: "New Item", accelerator: "CmdOrCtrl+N", click: () => sendCommand("new-item") },
        { type: "separator" },
        isMac ? { role: "close" } : { role: "quit" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
        { type: "separator" },
        { label: "Find", accelerator: "CmdOrCtrl+F", click: () => sendCommand("focus-search") },
      ],
    },
    {
      label: "Vault",
      submenu: [
        { label: "Refresh", accelerator: "CmdOrCtrl+R", click: () => sendCommand("refresh") },
        {
          label: "Lock",
          accelerator: "CmdOrCtrl+Shift+L",
          click: () => void lockVaultFromMain(),
        },
      ],
    },
    {
      label: "View",
      submenu: [
        ...(process.env.NODE_ENV === "development"
          ? [{ role: "reload" as const }, { role: "toggleDevTools" as const }, { type: "separator" as const }]
          : []),
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "zoom" }, ...(isMac ? [{ type: "separator" as const }, { role: "front" as const }] : [])],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function assertTrustedSender(event: Electron.IpcMainInvokeEvent): void {
  if (!mainWindow || event.sender.id !== mainWindow.webContents.id) {
    throw new Error("Untrusted IPC sender");
  }
}

function assertAppWindowSender(event: Electron.IpcMainInvokeEvent): void {
  const id = event.sender.id;
  const trusted = mainWindow?.webContents.id === id
    || largeTypeWindow?.webContents.id === id
    || terminalWindows.get(id)?.window.webContents === event.sender
    || fileWindows.get(id)?.window.webContents === event.sender;
  if (!trusted) throw new Error("Untrusted IPC sender");
}

function terminalWindowForSender(
  event: Electron.IpcMainInvokeEvent | Electron.IpcMainEvent,
): TerminalWindowState {
  const state = terminalWindows.get(event.sender.id);
  if (!state || state.window.isDestroyed() || state.window.webContents !== event.sender) {
    throw new Error("Untrusted terminal IPC sender");
  }
  return state;
}

function fileWindowForSender(
  event: Electron.IpcMainInvokeEvent,
): FileWindowState {
  const state = fileWindows.get(event.sender.id);
  if (!state || state.window.isDestroyed() || state.window.webContents !== event.sender) {
    throw new Error("Untrusted file window IPC sender");
  }
  return state;
}

function transferError(error: unknown): BridgeErrorShape {
  if (error instanceof DesktopBridgeError) {
    return {
      code: error.code,
      message: error.message,
      action: error.action,
      retryable: error.retryable,
    };
  }
  return {
    code: "transfer_failed",
    message: "The file transfer failed.",
    action: "Try again. Open Support if the problem continues.",
    retryable: true,
  };
}

type IPCResult<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string; action?: string; retryable: boolean } };

function flattenFields(fields: FieldView[]): FieldView[] {
  return fields.flatMap((field) => [field, ...flattenFields(field.children ?? [])]);
}

function dialogText(value: string, fallback: string): string {
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return [...clean].slice(0, 160).join("") || fallback;
}

async function loadTrustedItem(client: BridgeSupervisor, ref: RecordRef): Promise<ItemDetail> {
  return client.request<ItemDetail>("item.detail", {
    scopeId: ref.scopeId,
    name: ref.name,
    ...(ref.raw ? { raw: true } : {}),
  });
}

async function confirmItemAction(
  client: BridgeSupervisor,
  ref: RecordRef,
  options: {
    title: string;
    action: string;
    message(detail: ItemDetail): string;
    detail: string;
    type?: "question" | "warning";
  },
): Promise<ItemDetail | null> {
  if (!mainWindow) throw new Error("fd0 window is unavailable");
  const item = await loadTrustedItem(client, ref);
  const confirmation = await dialog.showMessageBox(mainWindow, {
    type: options.type ?? "question",
    buttons: ["Cancel", options.action],
    defaultId: 0,
    cancelId: 0,
    title: options.title,
    message: options.message(item),
    detail: options.detail,
    noLink: true,
  });
  return confirmation.response === 1 ? item : null;
}

async function issueEditGrant(
  client: BridgeSupervisor,
  ref: RecordRef,
  kind: OperationGrantKind,
): Promise<string | null> {
  const detail = await confirmItemAction(client, ref, {
    title: "Edit protected item?",
    action: "Edit",
    message: ({ item }) => `Edit ${dialogText(item.title, "this item")} from ${dialogText(item.vault, "this vault")}?`,
    detail: "The editor will receive this item's decrypted fields until you save or close it.",
  });
  return detail ? operationGrants.issue(kind, ref.scopeId, ref.name) : null;
}

function requireEditGrant(
  authorization: string | undefined,
  kind: OperationGrantKind,
  scopeId: string,
  name: string,
): void {
  if (!operationGrants.consume(authorization, kind, scopeId, name)) {
    throw new Error("Edit authorization expired. Close the editor and open the item again.");
  }
}

async function respond<T>(operation: () => Promise<T>): Promise<IPCResult<T>> {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    if (error instanceof DesktopBridgeError) {
      return {
        ok: false,
        error: {
          code: error.code,
          message: error.message,
          action: error.action,
          retryable: error.retryable,
        },
      };
    }
    return {
      ok: false,
      error: {
        code: "desktop_error",
        message: error instanceof Error ? error.message : "fd0 could not complete that action.",
        retryable: true,
      },
    };
  }
}

function displayPath(path: string): string {
  const home = homedir();
  return path === home ? "~" : path.startsWith(home + sep) ? `~${path.slice(home.length)}` : path;
}

async function diagnosticSnapshot(): Promise<DiagnosticsSnapshot> {
  const serviceState = await agentLifecycle.status();
  const status = lastVaultStatus;
  const effectiveSyncState = persistedSyncState(syncState, status?.readiness);
  const recentErrors = (diagnostics?.recent() ?? []).filter((entry) =>
    /error|failed|failure|stderr|exit|crash|rejected/i.test(`${entry.event} ${entry.message ?? ""}`),
  );
  const healthy = startupStatus.state === "ready"
    && Boolean(status?.agentRunning)
    && !status?.agentIncompatible
    && effectiveSyncState.state !== "error"
    && updateState.state !== "error"
    && (!status?.vaultExists || Boolean(status.readiness?.firstSyncAt && status.readiness?.recoveryVerifiedAt));
  return {
    generatedAt: new Date().toISOString(),
    health: healthy ? "healthy" : "attention",
    app: {
      version: app.getVersion(),
      platform: process.platform,
      architecture: process.arch,
      packageType: process.platform === "darwin"
        ? "dmg"
        : process.env.APPIMAGE
          ? "AppImage"
          : "deb/rpm",
    },
    paths: {
      application: displayPath(process.env.APPIMAGE || process.execPath),
      fd0Home: displayPath(runtimeEnvironment().FD0_HOME ?? join(homedir(), ".fd0")),
      logs: displayPath(diagnostics?.path ?? app.getPath("logs")),
    },
    service: {
      state: serviceState,
      running: status?.agentRunning,
      version: status?.version,
      flavor: status?.flavor,
      startedBy: status?.agentStartedBy,
      incompatible: status?.agentIncompatible,
    },
    vault: {
      exists: status?.vaultExists,
      unlocked: status?.unlocked,
      firstSyncComplete: Boolean(status?.readiness?.firstSyncAt),
      recoveryVerified: Boolean(status?.readiness?.recoveryVerifiedAt),
    },
    sync: effectiveSyncState,
    update: updateState,
    recentErrors,
  };
}

function registerInfrastructureIPC(): void {
  const handle = <T>(channel: string, operation: () => Promise<T>): void => {
    ipcMain.handle(channel, (event) => {
      assertTrustedSender(event);
      return respond(operation);
    });
  };
  handle("fd0:startup-status", async () => startupStatus);
  handle("fd0:consume-update-request", async () => {
    const requested = rendererDesktopUpdateRequested;
    rendererDesktopUpdateRequested = false;
    return requested;
  });
  handle("fd0:retry-startup", initializeServices);
  handle("fd0:repair-service", async () => {
    diagnostics?.record("agent", "repair-requested");
    if (nativeAgentManaged) {
      if (bridge) await restartManagedAgent(bridge);
      else await agentLifecycle.restart();
    }
    return initializeServices();
  });
  handle("fd0:diagnostics", diagnosticSnapshot);
  handle("fd0:copy-diagnostics", async () => {
    clipboard.writeText(JSON.stringify(await diagnosticSnapshot(), null, 2));
    return { copied: true };
  });
  handle("fd0:open-logs", async () => {
    const error = await shell.openPath(dirname(diagnostics?.path ?? app.getPath("logs")));
    if (error) throw new Error(error);
  });
  handle("fd0:open-login-items", async () => {
    if (process.platform !== "darwin") return;
    await shell.openExternal("x-apple.systempreferences:com.apple.LoginItems-Settings.extension");
  });
  handle("fd0:quit", async () => {
    app.quit();
  });
  ipcMain.handle("fd0:system-theme", (event) => {
    assertAppWindowSender(event);
    return respond(async () => resolvedSystemTheme());
  });
  handle("fd0:terminal-launcher", currentTerminalLauncherState);
  ipcMain.handle("fd0:set-theme", (event, theme: DesktopTheme) => {
    assertTrustedSender(event);
    return respond(async () => {
      if (theme !== "system" && theme !== "dark" && theme !== "light") throw new Error("Invalid desktop theme");
      desktopTheme = theme;
      updateWindowBackgrounds();
    });
  });
  ipcMain.handle("fd0:set-terminal-launcher", (event, settings: TerminalLauncherSettings) => {
    assertTrustedSender(event);
    return respond(async () => {
      const saved = await writeTerminalLauncherSettings(
        terminalLauncherSettingsPath(),
        process.platform,
        settings,
      );
      updateTerminalThemes(saved.terminalTheme);
      return currentTerminalLauncherState(saved);
    });
  });
}

function registerTerminalIPC(): void {
  ipcMain.handle("fd0:terminal-session", (event) => {
    return respond(async (): Promise<TerminalSessionInfo> => {
      const state = terminalWindowForSender(event);
      return { host: state.host, terminalTheme: state.theme };
    });
  });
  ipcMain.handle("fd0:terminal-start", (event, cols: number, rows: number) => {
    return respond(async () => {
      const state = terminalWindowForSender(event);
      terminalSessions.start(state.sessionId, cols, rows);
    });
  });
  ipcMain.handle("fd0:terminal-close", (event) => {
    return respond(async () => {
      const state = terminalWindowForSender(event);
      setImmediate(() => {
        if (!state.window.isDestroyed()) state.window.close();
      });
    });
  });
  ipcMain.handle("fd0:terminal-copy", (event, value: string) => {
    return respond(async () => {
      terminalWindowForSender(event);
      if (typeof value !== "string" || value.length > 1024 * 1024) {
        throw new Error("Terminal selection is invalid");
      }
      managedClipboard.write(value);
    });
  });
  ipcMain.handle("fd0:terminal-paste", (event) => {
    return respond(async () => {
      const state = terminalWindowForSender(event);
      const value = clipboard.readText();
      if (value.length > 1024 * 1024) throw new Error("Clipboard text is too large");
      terminalSessions.write(state.sessionId, value);
    });
  });
  ipcMain.on("fd0:terminal-write", (event, data: string) => {
    try {
      const state = terminalWindowForSender(event);
      terminalSessions.write(state.sessionId, data);
    } catch (error) {
      diagnostics?.record("terminal", "input-rejected", error);
    }
  });
  ipcMain.on("fd0:terminal-resize", (event, cols: number, rows: number) => {
    try {
      const state = terminalWindowForSender(event);
      terminalSessions.resize(state.sessionId, cols, rows);
    } catch (error) {
      diagnostics?.record("terminal", "resize-rejected", error);
    }
  });
  ipcMain.on("fd0:terminal-title", (event, title: string) => {
    try {
      const state = terminalWindowForSender(event);
      state.remoteTitle = terminalTitlePart(title);
      updateTerminalWindowTitle(state);
    } catch (error) {
      diagnostics?.record("terminal", "title-rejected", error);
    }
  });
}

function sendFileTransfer(state: FileWindowState, value: SFTPTransferEvent): void {
  if (state.window.isDestroyed() || state.window.webContents.isDestroyed()) return;
  state.window.webContents.send("fd0:sftp-transfer", value);
}

function startFileTransfer(
  state: FileWindowState,
  direction: "upload" | "download",
  name: string,
  remotePath: string,
  localPath: string,
  recursive: boolean,
  force: boolean,
): void {
  if (state.activeTransfers.size >= 8) {
    throw new Error("Wait for an active transfer to finish before starting another.");
  }
  const transfer = state.client.transfer<{ path: string; bytes: number }>(
    direction === "upload" ? "transfer.upload" : "transfer.download",
    { remotePath, localPath, recursive, force },
    (progress: SFTPProgress) => {
      sendFileTransfer(state, {
        id: transfer.id,
        direction,
        name,
        remotePath,
        state: "running",
        ...progress,
      });
    },
  );
  state.activeTransfers.add(transfer.id);
  sendFileTransfer(state, {
    id: transfer.id,
    direction,
    name,
    remotePath,
    state: "running",
    transferred: 0,
    total: 0,
  });
  void transfer.result.then((result) => {
    state.activeTransfers.delete(transfer.id);
    sendFileTransfer(state, {
      id: transfer.id,
      direction,
      name,
      remotePath,
      state: "completed",
      transferred: result.bytes,
      total: result.bytes,
    });
  }).catch((error) => {
    state.activeTransfers.delete(transfer.id);
    const publicError = transferError(error);
    diagnostics?.record("sftp", `${direction}-failed`, error);
    sendFileTransfer(state, {
      id: transfer.id,
      direction,
      name,
      remotePath,
      state: publicError.code === "cancelled" ? "cancelled" : "failed",
      transferred: 0,
      total: 0,
      error: publicError,
    });
  });
}

function requireTransferCapacity(state: FileWindowState, count: number): void {
  if (count < 1 || state.activeTransfers.size+count > 8) {
    throw new Error("Up to eight file transfers can run at once.");
  }
}

function validRemotePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && !value.includes("\0");
}

function registerFileIPC(): void {
  ipcMain.handle("fd0:sftp-session", (event) => respond(async (): Promise<SFTPSessionInfo> => {
    const state = fileWindowForSender(event);
    const session = await state.client.request<{ workingDirectory: string }>("session.info", {});
    return { host: state.host, workingDirectory: session.workingDirectory, terminalTheme: state.theme };
  }));
  ipcMain.handle("fd0:sftp-reconnect", (event) => respond(async (): Promise<SFTPSessionInfo> => {
    const state = fileWindowForSender(event);
    if (state.activeTransfers.size > 0) {
      throw new Error("Cancel or wait for active file transfers before reconnecting.");
    }
    state.client.dispose();
    state.client = new SFTPBridgeClient(
      sftpBridgeBinary(),
      state.alias,
      state.scopeId,
      state.environment,
      (diagnosticEvent) => diagnostics?.record("sftp", diagnosticEvent),
    );
    const session = await state.client.request<{ workingDirectory: string }>("session.info", {});
    return { host: state.host, workingDirectory: session.workingDirectory, terminalTheme: state.theme };
  }));
  ipcMain.handle("fd0:sftp-list", (event, path: string) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(path)) throw new Error("Remote path is invalid");
    return state.client.request<SFTPEntry[]>("dir.list", { path });
  }));
  ipcMain.handle("fd0:sftp-preview", (event, path: string) => respond(async (): Promise<SFTPPreview> => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(path)) throw new Error("Remote path is invalid");
    const preview = await state.client.request<{ data: string; size: number; truncated: boolean }>(
      "file.preview",
      { path },
    );
    return {
      contentBase64: preview.data,
      size: preview.size,
      truncated: preview.truncated,
    };
  }));
  ipcMain.handle("fd0:sftp-mkdir", (event, path: string) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(path)) throw new Error("Remote path is invalid");
    await state.client.request("dir.mkdir", { path, parents: false });
  }));
  ipcMain.handle("fd0:sftp-rename", (event, oldPath: string, newPath: string) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(oldPath) || !validRemotePath(newPath)) throw new Error("Remote path is invalid");
    await state.client.request("path.rename", { old: oldPath, new: newPath, force: false });
  }));
  ipcMain.handle("fd0:sftp-remove", (event, path: string, recursive: boolean) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(path)) throw new Error("Remote path is invalid");
    await state.client.request("path.remove", { path, recursive: Boolean(recursive) });
  }));
  ipcMain.handle("fd0:sftp-upload", (event, remoteDirectory: string) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(remoteDirectory)) throw new Error("Remote path is invalid");
    const selection = await dialog.showOpenDialog(state.window, {
      title: `Upload to ${state.host}`,
      properties: ["openFile", "openDirectory", "multiSelections"],
    });
    if (selection.canceled) return { started: 0 };
    requireTransferCapacity(state, selection.filePaths.length);
    for (const localPath of selection.filePaths) {
      const info = await stat(localPath);
      const name = basename(localPath);
      startFileTransfer(
        state,
        "upload",
        name,
        remoteDirectory,
        localPath,
        info.isDirectory(),
        false,
      );
    }
    return { started: selection.filePaths.length };
  }));
  ipcMain.handle("fd0:sftp-upload-dropped", (event, remoteDirectory: string, localPaths: string[]) => respond(async () => {
    const state = fileWindowForSender(event);
    if (!validRemotePath(remoteDirectory) || !Array.isArray(localPaths) || localPaths.length > 100) {
      throw new Error("Dropped files are invalid");
    }
    requireTransferCapacity(state, localPaths.length);
    let started = 0;
    for (const localPath of localPaths) {
      if (typeof localPath !== "string" || !isAbsolute(localPath) || localPath.includes("\0")) {
        throw new Error("Dropped file is invalid");
      }
      const info = await stat(localPath);
      const name = basename(localPath);
      startFileTransfer(
        state,
        "upload",
        name,
        remoteDirectory,
        localPath,
        info.isDirectory(),
        false,
      );
      started += 1;
    }
    return { started };
  }));
  ipcMain.handle("fd0:sftp-download", (event, entry: SFTPEntry) => respond(async () => {
    const state = fileWindowForSender(event);
    if (
      !entry ||
      !validRemotePath(entry.path) ||
      typeof entry.name !== "string" ||
      !["file", "directory"].includes(entry.type)
    ) {
      throw new Error("Remote file is invalid");
    }
    let localPath: string;
    if (entry.type === "directory") {
      const selection = await dialog.showOpenDialog(state.window, {
        title: `Download ${entry.name}`,
        properties: ["openDirectory", "createDirectory"],
      });
      if (selection.canceled || selection.filePaths.length === 0) return { started: false };
      localPath = join(selection.filePaths[0]!, entry.name);
    } else {
      const selection = await dialog.showSaveDialog(state.window, {
        title: `Download ${entry.name}`,
        defaultPath: entry.name,
      });
      if (selection.canceled || !selection.filePath) return { started: false };
      localPath = selection.filePath;
    }
    startFileTransfer(
      state,
      "download",
      entry.name,
      entry.path,
      localPath,
      entry.type === "directory",
      true,
    );
    return { started: true };
  }));
  ipcMain.handle("fd0:sftp-cancel", (event, id: string) => respond(async () => {
    const state = fileWindowForSender(event);
    if (typeof id !== "string" || id.length > 128) throw new Error("Transfer id is invalid");
    await state.client.cancel(id);
  }));
  ipcMain.handle("fd0:sftp-close", (event) => respond(async () => {
    const state = fileWindowForSender(event);
    setImmediate(() => {
      if (!state.window.isDestroyed()) state.window.close();
    });
  }));
}

function registerIPC(client: BridgeSupervisor): void {
  const handle = <TArgs extends unknown[], TResult>(
    channel: string,
    operation: (...args: TArgs) => Promise<TResult>,
  ): void => {
    ipcMain.handle(channel, (event, ...args: TArgs) => {
      assertTrustedSender(event);
      return respond(() => operation(...args));
    });
  };

  handle("fd0:status", async () => observeVaultStatus(await client.request<VaultStatus>("vault.status", {})));
  handle("fd0:create-vault", async (passphrase: string, label: string) => {
    await ensureManagedAgent(client);
    const buffer = Buffer.from(passphrase, "utf8");
    const encoded = buffer.toString("base64");
    buffer.fill(0);
    return observeVaultStatus(await client.request<VaultStatus>("vault.create", { passphrase: encoded, label }));
  });
  handle("fd0:unlock", async (input: UnlockInput) => {
    await ensureManagedAgent(client);
    const passphrase = Buffer.from(input?.passphrase ?? "", "utf8");
    const pin = Buffer.from(input?.pin ?? "", "utf8");
    const params = {
      method: input?.method ?? "",
      passphrase: passphrase.toString("base64"),
      pin: pin.toString("base64"),
    };
    passphrase.fill(0);
    pin.fill(0);
    return observeVaultStatus(await client.request<VaultStatus>("vault.unlock", params, 60_000));
  });
  handle("fd0:lock", async () => {
    const status = observeVaultStatus(await client.request<VaultStatus>("vault.lock", {}));
    closeLargeTypeWindow();
    managedClipboard.clear();
    operationGrants.clear();
    sendCommand("refresh");
    return status;
  });
  handle("fd0:restart-agent", async () => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Restart local service"],
      defaultId: 0,
      cancelId: 0,
      title: "Restart the fd0 local service?",
      message: "Restart the fd0 local service?",
      detail: "The vault will lock. Unlock it again after the restart.",
      noLink: true,
    });
    if (confirmation.response !== 1) return observeVaultStatus(await client.request<VaultStatus>("vault.status", {}));
    if (nativeAgentManaged) {
      return observeVaultStatus(await restartManagedAgent(client));
    }
    return observeVaultStatus(await client.request<VaultStatus>("agent.restart", {}, 15_000));
  });
  handle("fd0:select-recovery-file", async () => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: "Restore an fd0 vault",
      properties: ["openFile"],
      filters: [{ name: "fd0 recovery file", extensions: ["cbor", "fd0-recovery"] }, { name: "All files", extensions: ["*"] }],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) {
      selectedRecoveryFile = null;
      return null;
    }
    const info = await stat(path);
    if (!info.isFile() || info.size > 4 * 1024 * 1024) throw new Error("Recovery files must be smaller than 4 MB");
    const data = await readFile(path);
    const inspected = await client.request<{ version: 1 | 2 }>("recovery.inspect", { data: data.toString("base64") });
    data.fill(0);
    selectedRecoveryFile = { path, version: inspected.version };
    return { version: inspected.version };
  });
  handle("fd0:restore-vault", async (recoveryPassphrase: string, newPassphrase: string) => {
    const selection = selectedRecoveryFile;
    if (!selection) throw new Error("Choose an fd0 recovery file first");
    const info = await stat(selection.path);
    if (!info.isFile() || info.size > 4 * 1024 * 1024) throw new Error("Recovery files must be smaller than 4 MB");
    const data = await readFile(selection.path);
    const recovery = Buffer.from(recoveryPassphrase, "utf8");
    const local = Buffer.from(newPassphrase, "utf8");
    const params = {
      data: data.toString("base64"),
      recoveryPassphrase: recovery.toString("base64"),
      newPassphrase: local.toString("base64"),
    };
    data.fill(0);
    recovery.fill(0);
    local.fill(0);
    await client.request<VaultStatus>("recovery.import", params, 2 * 60_000);
    selectedRecoveryFile = null;
    await ensureManagedAgent(client);
    const status = selection.version === 1
      ? await client.request<VaultStatus>("vault.unlock", { method: "passphrase", passphrase: params.newPassphrase, pin: "" }, 60_000)
      : await client.request<VaultStatus>("vault.status", {});
    return observeVaultStatus(status);
  });
  handle("fd0:export-recovery", async (passphrase: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: "Save fd0 recovery file",
      defaultPath: join(app.getPath("documents"), "fd0-recovery.cbor"),
      filters: [{ name: "fd0 recovery file", extensions: ["cbor"] }],
    });
    if (destination.canceled || !destination.filePath) return { saved: false };
    const secret = Buffer.from(passphrase, "utf8");
    const encoded = secret.toString("base64");
    secret.fill(0);
    return client.request<{ saved: boolean; verified: boolean }>(
      "recovery.exportFile",
      { path: destination.filePath, passphrase: encoded },
      2 * 60_000,
    );
  });
  handle("fd0:set-default-auth", async (method: string) => observeVaultStatus(await client.request<VaultStatus>("auth.default", { method })));
  handle("fd0:inventory", () => client.request("inventory.list", {}));
  handle("fd0:deleted-items", () => client.request("deleted.list", {}));
  handle("fd0:parse-totp", (uri: string) => {
    if (typeof uri !== "string" || uri.length > 4096) throw new Error("TOTP setup link is invalid");
    return client.request("totp.parse", { uri });
  });
  handle("fd0:item-detail", (ref: RecordRef) => client.request("item.detail", ref));
  handle("fd0:item-history", (ref: RecordRef, options?: { limit?: number; offset?: number }) =>
    client.request("item.history", {
      scopeId: ref.scopeId,
      name: ref.name,
      ...(typeof options?.limit === "number" ? { limit: options.limit } : {}),
      ...(typeof options?.offset === "number" ? { offset: options.offset } : {}),
    }),
  );
  handle("fd0:item-version", (ref: ItemVersionRef) =>
    client.request("item.version", { scopeId: ref.scopeId, name: ref.name, seq: ref.seq }),
  );
  /*
   * Restoring overwrites the item's current value, so it is confirmed natively
   * like every other destructive action. It never rewrites history: the bridge
   * writes the old payload back as a new event.
   */
  handle("fd0:restore-item-version", async (ref: ItemVersionRef) => {
    const confirmed = await confirmItemAction(client, { scopeId: ref.scopeId, name: ref.name }, {
      title: "Restore this version?",
      action: "Restore",
      type: "warning",
      message: ({ item }) => `Replace ${dialogText(item.title, "this item")} with an earlier version?`,
      detail: "The current value is replaced. It stays in this item's history, so you can restore it again.",
    });
    if (!confirmed) return { ok: false };
    return client.request("item.restore", { scopeId: ref.scopeId, name: ref.name, seq: ref.seq });
  });
  handle("fd0:reveal", async (ref: FieldRef) => {
    const detail = await loadTrustedItem(client, ref);
    const field = flattenFields(detail.fields).find((candidate) => candidate.path === ref.path);
    if (!field) throw new Error("That field is no longer available");
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Reveal"],
      defaultId: 0,
      cancelId: 0,
      title: "Reveal protected value?",
      message: `Reveal ${dialogText(field.name, "this field")} from ${dialogText(detail.item.title, "this item")}?`,
      detail: `Vault: ${dialogText(detail.item.vault, "this vault")}\n\nThe value will be visible on screen for 15 seconds.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return null;
    return client.request("field.value", ref);
  });
  handle("fd0:copy", async (ref: FieldRef) => {
    const result = await client.request<{ value: string }>("field.value", ref);
    return writeManagedClipboard(result.value);
  });
  handle("fd0:copy-text", async (value: string) => {
    if (typeof value !== "string" || value.length > 64 * 1024) throw new Error("Clipboard value is invalid");
    return writeManagedClipboard(value);
  });
  handle("fd0:save-pass", async (input: SavePassInput) => {
    const { authorization, ...params } = input;
    if (input.create !== true) {
      requireEditGrant(authorization, "pass.edit", input.scopeId, `pass:${input.recordName.trim()}`);
    }
    return client.request("pass.save", params);
  });
  handle("fd0:edit-pass", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "pass.edit");
    if (!authorization) return null;
    const input = await client.request<SavePassInput>("pass.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:organization-inventory", () => client.request("organization.inventory", {}));
  handle("fd0:organization-batch", (request: OrganizationBatch) => client.request("organization.batch", request));
  handle("fd0:set-item-tags", (ref: RecordRef, tags: string[], expectedTags?: string[]) => client.request("item.tags", { ...ref, tags, expectedTags }));
  handle("fd0:set-favorite", (ref: RecordRef, favorite: boolean) => client.request("pass.favorite", { ...ref, favorite: Boolean(favorite) }));
  handle("fd0:pick-attachment", async () => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: "Attach a small file",
      properties: ["openFile"],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) return null;
    const info = await stat(path);
    if (!info.isFile() || info.size > 32 * 1024) throw new Error("Attachments must be smaller than 32 KB");
    const data = await readFile(path);
    const result = {
      name: basename(path),
      mime: mimeForExtension(extname(path)),
      size: data.length,
      sha256: createHash("sha256").update(data).digest("hex"),
      data_b64: data.toString("base64"),
    };
    data.fill(0);
    return result;
  });
  handle("fd0:save-secret", async (input: SaveSecretInput) => {
    const { authorization, ...params } = input;
    if (input.create !== true) {
      requireEditGrant(authorization, "secret.edit", input.scopeId, input.oldName?.trim() ?? "");
    }
    return client.request("secret.save", params);
  });
  handle("fd0:edit-secret", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "secret.edit");
    if (!authorization) return null;
    const input = await client.request<SaveSecretInput>("secret.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:save-ssh-host", async (input: SaveSSHHostInput) => {
    const { authorization, ...params } = input;
    if (input.oldName) {
      requireEditGrant(authorization, "ssh.edit", input.scopeId, input.oldName);
    }
    return client.request("sshHost.save", params);
  });
  handle("fd0:edit-ssh-host", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "ssh.edit");
    if (!authorization) return null;
    const input = await client.request<SaveSSHHostInput>("sshHost.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:generate-ssh-key", (input: GenerateSSHKeyInput) => client.request("sshKey.generate", input));
  handle("fd0:list-ssh-keys", (scopeId: string) => client.request("sshKey.list", { scopeId }));
  handle("fd0:save-ssh-key", async (input: SaveSSHKeyInput) => {
    const { authorization, ...params } = input;
    requireEditGrant(authorization, "ssh-key.edit", input.scopeId, `ssh:${input.name}`);
    return client.request("sshKey.save", params);
  });
  handle("fd0:edit-ssh-key", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "ssh-key.edit");
    if (!authorization) return null;
    const input = await client.request<SaveSSHKeyInput>("sshKey.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:import-config", async (kind: "kubernetes" | "talos", scopeId: string) => {
    if (!mainWindow || (kind !== "kubernetes" && kind !== "talos")) throw new Error("Invalid config import");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: kind === "kubernetes" ? "Import kubeconfig" : "Import talosconfig",
      properties: ["openFile"],
      filters: [{ name: "YAML config", extensions: ["yaml", "yml", "config"] }, { name: "All files", extensions: ["*"] }],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) return null;
    const info = await stat(path);
    if (!info.isFile() || info.size > 512 * 1024) throw new Error("Config must be a file smaller than 512 KB");
    const data = await readFile(path);
    const encoded = data.toString("base64");
    data.fill(0);
    return client.request("config.import", { kind, scopeId, data: encoded });
  });
  handle("fd0:save-attachment", async (ref: FieldRef) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const result = await client.request<{ name: string; mime?: string; data: string }>("file.value", ref);
    const name = basename(result.name || "fd0-attachment");
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: "Save attachment",
      defaultPath: join(app.getPath("downloads"), name),
    });
    if (destination.canceled || !destination.filePath) return { saved: false };
    const data = Buffer.from(result.data, "base64");
    if (data.length > 32 * 1024) {
      data.fill(0);
      throw new Error("Attachment is larger than 32 KB");
    }
    try {
      await writeFile(destination.filePath, data, { mode: 0o600 });
      await chmod(destination.filePath, 0o600);
    } finally {
      data.fill(0);
    }
    return { saved: true };
  });
  handle("fd0:move-item", async (input: MoveItemInput) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const item = await loadTrustedItem(client, input.source);
    const inventory = await client.request<Inventory>("inventory.list", {});
    const target = inventory.scopes.find((scope) => scope.id === input.targetScopeId);
    if (!target) throw new Error("That destination vault is no longer available");
    if (target.id === item.item.scopeId) throw new Error("Choose another vault");

    const usages = item.relations?.filter((relation) => relation.kind === "used-by") ?? [];
    const sshKeyWarning =
      item.item.badge === "SSH KEY" && usages.length > 0
        ? `\n\nThis key is assigned to ${usages.length} server${usages.length === 1 ? "" : "s"} in the current vault. Those assignments will no longer resolve after the move.`
        : "";
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Move"],
      defaultId: 0,
      cancelId: 0,
      title: "Move item to another vault?",
      message: `Move ${dialogText(item.item.title, "this item")} from ${dialogText(item.item.vault, "this vault")} to ${dialogText(target.label, "the selected vault")}?`,
      detail: `Vault access controls who can open this item. The move will sync to other devices and vault members.${sshKeyWarning}`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("item.move", input);
  });
  handle("fd0:rename-item", async (input: RenameItemInput) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const item = await loadTrustedItem(client, input.source);
    const name = input.name.trim();
    if (!name) throw new Error("Item name is required");
    if (item.item.kind !== "kubernetes" && item.item.kind !== "talos") {
      throw new Error("Rename this item through its editor");
    }
    if (name === item.item.title) return { ok: true };
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Rename"],
      defaultId: 1,
      cancelId: 0,
      title: `Rename ${item.item.title}?`,
      message: `Rename ${dialogText(item.item.title, "this item")} to ${dialogText(name, "the new name")}?`,
      detail: "fd0 will update the generated configuration on this device.",
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("item.rename", { source: input.source, name });
  });
  handle("fd0:remove", async (ref: RecordRef) => {
    const detail = await loadTrustedItem(client, ref);
    const usages = detail.relations?.filter((relation) => relation.kind === "used-by") ?? [];
    if (detail.item.badge === "SSH KEY" && usages.length > 0) {
      if (!mainWindow) throw new Error("fd0 window is unavailable");
      await dialog.showMessageBox(mainWindow, {
        type: "warning",
        buttons: ["OK"],
        defaultId: 0,
        cancelId: 0,
        title: "SSH key is still in use",
        message: `${dialogText(detail.item.title, "This key")} is assigned to ${usages.length} server${usages.length === 1 ? "" : "s"}.`,
        detail: `${usages.map((relation) => relation.item.title).join(", ")}\n\nChoose another key for those servers before removing this key.`,
        noLink: true,
      });
      return { ok: false, blocked: true };
    }
    const item = await confirmItemAction(client, ref, {
      title: "Remove item?",
      action: "Remove",
      message: ({ item }) => `Remove ${dialogText(item.title, "this item")} from ${dialogText(item.vault, "this vault")}?`,
      detail: "This creates a deletion that will sync to other devices and vault members.",
      type: "warning",
    });
    if (!item) return { ok: false };
    return client.request("item.remove", ref);
  });
  handle("fd0:restore-deleted-item", async (ref: ItemVersionRef) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const deleted = await client.request<{ items: Array<{ item: ItemSummary; restoreSeq: number }> }>("deleted.list", {});
    const candidate = deleted.items.find(
      (entry) =>
        entry.item.scopeId === ref.scopeId &&
        entry.item.recordName === ref.name &&
        entry.restoreSeq === ref.seq,
    );
    if (!candidate) throw new Error("That deleted item is no longer available");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Restore"],
      defaultId: 1,
      cancelId: 0,
      title: "Restore deleted item?",
      message: `Restore ${dialogText(candidate.item.title, "this item")} to ${dialogText(candidate.item.vault, "its vault")}?`,
      detail: "The restore is saved as a new version and will sync to other devices and vault members.",
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("item.restore", ref);
  });
  handle("fd0:create-scope", (label: string) => client.request("scope.create", { label }));
  handle("fd0:rename-scope", (scopeId: string, label: string) =>
    client.request("scope.rename", { scopeId, label }),
  );
  handle("fd0:leave-scope", async (scopeId: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const inventory = await client.request<Inventory>("inventory.list", {});
    const scope = inventory.scopes.find((candidate) => candidate.id === scopeId);
    if (!scope) throw new Error("That vault is no longer available");
    if (inventory.scopes.length <= 1) throw new Error("You cannot leave your only vault");
    const count = inventory.items.filter((item) => item.scopeId === scopeId).length;
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Leave vault"],
      defaultId: 0,
      cancelId: 0,
      title: `Leave ${dialogText(scope.label, "this vault")}?`,
      message: `Leave ${dialogText(scope.label, "this vault")} and remove its items from this device?`,
      detail: `${count} item${count === 1 ? "" : "s"} will disappear after the leave syncs. Other vault members keep their access.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("scope.leave", { scopeId });
  });
  handle("fd0:scope-share-info", (scopeId: string) => client.request("scope.shareInfo", { scopeId }));
  handle("fd0:scope-add-member", async (scopeId: string, label: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const info = await client.request<ScopeShareInfo>("scope.shareInfo", { scopeId });
    const contact = info.contacts.find((candidate) => candidate.label === label && !candidate.shared);
    if (!contact) throw new Error("That trusted contact is no longer available");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Share vault"],
      defaultId: 0,
      cancelId: 0,
      title: `Share ${dialogText(info.scopeLabel, "this vault")}?`,
      message: `Give ${dialogText(contact.label, "this contact")} access to ${dialogText(info.scopeLabel, "this vault")}?`,
      detail: `Safety fingerprint: ${contact.fingerprint}…\n\nThey will be able to decrypt every current and future item in this vault.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("scope.addMember", { scopeId, label: contact.label });
  });
  handle("fd0:scope-remove-member", async (scopeId: string, memberId: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const info = await client.request<ScopeShareInfo>("scope.shareInfo", { scopeId });
    const member = info.members.find((candidate) => candidate.id === memberId && !candidate.self);
    if (!member) throw new Error("That vault member is no longer available");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Remove access"],
      defaultId: 0,
      cancelId: 0,
      title: `Remove ${dialogText(member.label, "this member")}?`,
      message: `Remove ${dialogText(member.label, "this member")} from ${dialogText(info.scopeLabel, "this vault")}?`,
      detail: `Safety fingerprint: ${member.fingerprint}…\n\nfd0 will rotate the vault key. They keep anything already downloaded, but cannot decrypt future changes.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("scope.removeMember", { scopeId, memberId });
  });
  handle("fd0:card-export", () => client.request("card.export", {}));
  handle("fd0:card-inspect", (url: string) => client.request("card.inspect", { url }));
  handle("fd0:card-import", async (url: string, label: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const preview = await client.request<IdentityCardInfo>("card.inspect", { url });
    const displayLabel = typeof label === "string" && label.trim() ? label.trim().slice(0, 80) : preview.shortId;
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Trust contact"],
      defaultId: 0,
      cancelId: 0,
      title: "Verify identity card",
      message: `Did you verify ${displayLabel}'s safety number out of band?`,
      detail: `${preview.safetyNumber}\n\nOnly continue if the other person read the same number to you through a trusted channel.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("card.import", { url, label });
  });
  handle("fd0:sync", async () => {
    syncState = { state: "never", lastAttemptAt: new Date().toISOString() };
    diagnostics?.record("sync", "started");
    try {
      const preparation = await client.request<SyncPreparation>("sync.prepare", {}, 30_000);
      if (preparation.requiresConfirmation) {
        if (!mainWindow) throw new Error("fd0 window is unavailable");
        const name = dialogText(preparation.label ?? "", preparation.serverUrl);
        const confirmation = await dialog.showMessageBox(mainWindow, {
          type: "warning",
          buttons: ["Cancel", "Trust and sync"],
          defaultId: 0,
          cancelId: 0,
          title: "Trust this fd0 service?",
          message: `Trust ${name}?`,
          detail: `${preparation.serverUrl}\n\nSafety fingerprint:\n${preparation.fingerprint}\n\nVerify this fingerprint through an independent trusted channel before continuing.`,
          noLink: true,
        });
        if (confirmation.response !== 1) return { ok: false, cancelled: true };
      }
      if (!preparation.alreadyPinned) {
        await client.request("sync.pin", {
          serverUrl: preparation.serverUrl,
          serverPub: preparation.serverPub,
        }, 30_000);
      }
      const result = await client.request<{ ok: boolean }>("sync.run", {
        serverUrl: preparation.serverUrl,
      }, 5 * 60_000);
      syncState = { state: "ok", lastAttemptAt: new Date().toISOString() };
      diagnostics?.record("sync", "completed");
      return result;
    } catch (error) {
      syncState = { state: "error", lastAttemptAt: new Date().toISOString() };
      diagnostics?.record("sync", "failed", error);
      throw error;
    }
  });
  handle("fd0:launch-at-login", async () => agentLifecycle.guiLaunchesAtLogin());
  handle("fd0:set-launch-at-login", async (value: boolean) => {
    return agentLifecycle.setGuiLaunchAtLogin(Boolean(value));
  });
  handle("fd0:open-ssh-host", async (ref: RecordRef) => {
    const detail = await loadTrustedItem(client, ref);
    if (detail.item.badge !== "SSH HOST" || !detail.item.recordName.startsWith("host:")) {
      throw new Error("Only fd0 SSH hosts can be opened in a terminal");
    }
    const alias = detail.item.recordName.slice("host:".length);
    const environment = runtimeEnvironment();
    const settings = await readTerminalLauncherSettings(
      terminalLauncherSettingsPath(),
      process.platform,
    );
    if (settings.profileId === "in-app") {
      openTerminalWindow({
        host: alias,
        scopeId: detail.item.scopeId,
        fd0Binary: environment.FD0_BIN ?? "",
        environment,
        cwd: environment.HOME ?? homedir(),
        theme: settings.terminalTheme,
      });
      return { profileId: "in-app" };
    }
    const detection = await detectTerminalEnvironment({
      platform: process.platform,
      environment,
    });
    const plan = buildTerminalLaunchPlan({
      platform: process.platform,
      settings,
      detection,
      fd0Binary: environment.FD0_BIN ?? "",
      scopeId: detail.item.scopeId,
      alias,
      environment,
    });
    await spawnTerminal(plan);
    return { profileId: plan.profileId };
  });
  handle("fd0:open-ssh-files", async (ref: RecordRef) => {
    const detail = await loadTrustedItem(client, ref);
    if (detail.item.badge !== "SSH HOST" || !detail.item.recordName.startsWith("host:")) {
      throw new Error("Only fd0 SSH hosts can be opened in Files");
    }
    const settings = await readTerminalLauncherSettings(
      terminalLauncherSettingsPath(),
      process.platform,
    );
    openFileWindow({
      host: detail.item.recordName.slice("host:".length),
      scopeId: detail.item.scopeId,
      environment: runtimeEnvironment(),
      theme: settings.terminalTheme,
    });
  });
  handle("fd0:open-item-url", async (ref: RecordRef) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const detail = await loadTrustedItem(client, ref);
    const website = flattenFields(detail.fields).find((field) => field.type === "url" && field.path === "$url");
    const url = trustedItemURL(website?.value ?? "");
    const host = new URL(url).host;
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Open website"],
      defaultId: 0,
      cancelId: 0,
      title: "Open website?",
      message: `Open ${host} for ${dialogText(detail.item.title, "this item")}?`,
      detail: url,
      noLink: true,
    });
    if (confirmation.response !== 1) return;
    await shell.openExternal(url);
  });
  handle("fd0:open-support-link", async (target: SupportLinkTarget) => {
    await shell.openExternal(supportLink(target));
  });
  handle("fd0:update-status", async () => updateState);
  handle("fd0:check-updates", () => checkForUpdates());
  handle("fd0:install-update", async () => {
    await installReadyUpdate();
  });
}

/**
 * Makes sure an fd0 background service is serving this vault before an unlock.
 *
 * There is exactly one agent per FD0_HOME. If the user already unlocked from a
 * terminal, that agent owns the socket and our login item / systemd unit cannot
 * start a second one — by design. So this checks first and starts the service
 * only when nothing is serving: a running, usable agent is simply used, whoever
 * started it. Startup must not fail because our service could not start while a
 * working agent is present.
 */
async function ensureManagedAgent(client: BridgeSupervisor): Promise<void> {
  if (!nativeAgentManaged) return;
  let status = await client.request<VaultStatus>("vault.status", {});
  if (usableAgent(status)) return;
  if (status.agentRunning) {
    // Running but unusable. Ours to restart — or someone else's to leave alone.
    if (status.agentStartedBy !== "desktop") throw new Error(agentBlockedMessage(status));
    status = await restartManagedAgent(client);
  } else {
    await agentLifecycle.assertReady(await agentLifecycle.ensureRunning());
  }
  if (usableAgent(status)) return;
  await waitForAgentStatus(client, usableAgent);
}

async function reconcileManagedAgent(): Promise<void> {
  const client = bridge;
  if (!nativeAgentManaged || !client) return;
  try {
    const serviceStatus = await agentLifecycle.ensureRunning();
    diagnostics?.record("agent", `service:${serviceStatus}`);
    if (serviceStatus === "enabled") await ensureManagedAgent(client);
    else if (serviceStatus !== "requires-approval") await agentLifecycle.assertReady(serviceStatus);
    await refreshSecurityStatus();
    sendCommand("refresh");
  } catch (error) {
    diagnostics?.record("agent", "reconcile-failed", error);
  }
}

async function restartManagedAgent(client: BridgeSupervisor): Promise<VaultStatus> {
  const current = await client.request<VaultStatus>("vault.status", {});
  if (current.agentRunning && current.agentStartedBy !== "desktop") {
    throw new Error(agentBlockedMessage(current));
  }
  await agentLifecycle.stop();
  if (current.agentRunning) {
    await waitForAgentStatus(client, (status) => !status.agentRunning, "The fd0 background service did not stop");
  }
  await agentLifecycle.assertReady(await agentLifecycle.ensureRunning());
  return waitForAgentStatus(client, usableAgent);
}

async function waitForAgentStatus(
  client: BridgeSupervisor,
  ready: (status: VaultStatus) => boolean,
  failureMessage?: string,
): Promise<VaultStatus> {
  const deadline = Date.now() + 5_000;
  let status = await client.request<VaultStatus>("vault.status", {});
  while (!ready(status) && Date.now() < deadline) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    status = await client.request<VaultStatus>("vault.status", {});
  }
  if (ready(status)) return status;
  throw new Error(failureMessage ?? agentBlockedMessage(status));
}

function usableAgent(status: VaultStatus): boolean {
  return status.agentRunning && !status.agentIncompatible;
}

/**
 * Names the actual obstacle. Sending someone to repair this app's service is
 * useless — and alarming — when the real situation is that another program is
 * running a perfectly healthy service of its own.
 */
function agentBlockedMessage(status: VaultStatus): string {
  if (!status.agentRunning) {
    return "The fd0 background service did not start. Open Support and repair the local service.";
  }
  const reason = status.agentIncompatibleReason ?? "It reports a state this app cannot work with.";
  if (status.agentStartedBy === "desktop") {
    return `The fd0 background service restarted but this app still cannot use it. ${reason}`;
  }
  return `Another program started the fd0 background service for this vault and this app cannot use it. ${reason}`
    + " fd0 Desktop does not stop a service it did not start: run `fd0 agent stop` in the terminal you started it from, then try again.";
}

function mimeForExtension(extension: string): string {
  switch (extension.toLowerCase()) {
    case ".txt": return "text/plain";
    case ".json": return "application/json";
    case ".pem":
    case ".crt": return "application/x-pem-file";
    case ".key": return "application/octet-stream";
    default: return "application/octet-stream";
  }
}

/**
 * The one hardened renderer configuration. Every fd0 window shares it so a new
 * surface cannot quietly gain node access, drop the sandbox, or miss the preload.
 */
function secureWebPreferences(extraArguments: string[] = []): Electron.WebPreferences {
  return {
    preload: join(applicationRoot, "out", "preload", "index.cjs"),
    additionalArguments: [app.isPackaged ? "--fd0-system" : "--fd0-isolated", ...extraArguments],
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
  };
}

/** Denies popups and any navigation away from the document the window loaded. */
function applyWindowGuards(window: BrowserWindow): void {
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event, url) => {
    const current = window.webContents.getURL();
    if (url !== current) event.preventDefault();
  });
}

function rendererEntryURL(fragment = ""): string {
  const base = !app.isPackaged && process.env.ELECTRON_RENDERER_URL
    ? process.env.ELECTRON_RENDERER_URL
    : "fd0-app://app/index.html";
  return `${base}${fragment}`;
}

function windowBackgroundColor(): string {
  const dark = desktopTheme === "dark" || (desktopTheme === "system" && nativeTheme.shouldUseDarkColors);
  return dark ? "#0b0e0c" : "#ffffff";
}

function resolvedSystemTheme(): ResolvedDesktopTheme {
  return nativeTheme.shouldUseDarkColors ? "dark" : "light";
}

function terminalBackgroundColor(theme: TerminalTheme): string {
  const dark = theme === "dark" || (theme === "system" && nativeTheme.shouldUseDarkColors);
  return dark ? "#0b0e0c" : "#f7f8f6";
}

function terminalTitlePart(value: unknown): string {
  if (typeof value !== "string") throw new Error("Terminal title is invalid");
  const clean = value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return [...clean].slice(0, 120).join("");
}

function updateTerminalWindowTitle(state: TerminalWindowState): void {
  if (state.window.isDestroyed()) return;
  const context = state.remoteTitle || state.processName || "SSH";
  try {
    state.window.setTitle(
      context.localeCompare(state.host, undefined, { sensitivity: "accent" }) === 0
        ? state.host
        : `${state.host} — ${context}`,
    );
  } catch (error) {
    if (!state.window.isDestroyed()) diagnostics?.record("terminal", "title-update-failed", error);
  }
}

function sendTerminalEvent(state: TerminalWindowState, channel: string, value: unknown): void {
  if (state.window.isDestroyed()) return;
  try {
    const contents = state.window.webContents;
    if (!contents.isDestroyed()) contents.send(channel, value);
  } catch (error) {
    if (!state.window.isDestroyed()) diagnostics?.record("terminal", "renderer-update-failed", error);
  }
}

function releaseTerminalWindow(id: number, state: TerminalWindowState): void {
  terminalWindows.delete(id);
  terminalSessions.close(state.sessionId);
}

function updateLiveTerminalWindows(
  operation: (state: TerminalWindowState) => void,
): void {
  for (const [id, state] of terminalWindows) {
    if (state.window.isDestroyed()) {
      releaseTerminalWindow(id, state);
      continue;
    }
    try {
      operation(state);
    } catch (error) {
      if (state.window.isDestroyed()) {
        releaseTerminalWindow(id, state);
      } else {
        diagnostics?.record("terminal", "window-update-failed", error);
      }
    }
  }
}

function updateLiveFileWindows(
  operation: (state: FileWindowState) => void,
): void {
  for (const [id, state] of fileWindows) {
    if (state.window.isDestroyed()) {
      fileWindows.delete(id);
      continue;
    }
    try {
      operation(state);
    } catch (error) {
      if (state.window.isDestroyed()) {
        fileWindows.delete(id);
      } else {
        diagnostics?.record("sftp", "window-update-failed", error);
      }
    }
  }
}

function updateTerminalThemes(theme: TerminalTheme): void {
  updateLiveTerminalWindows((state) => {
    state.theme = theme;
    state.window.setBackgroundColor(terminalBackgroundColor(theme));
    sendTerminalEvent(state, "fd0:terminal-theme", theme);
  });
  updateLiveFileWindows((state) => {
    state.theme = theme;
    state.window.setBackgroundColor(terminalBackgroundColor(theme));
    const contents = state.window.webContents;
    if (!contents.isDestroyed()) contents.send("fd0:terminal-theme", theme);
  });
}

function updateWindowBackgrounds(): void {
  const background = windowBackgroundColor();
  mainWindow?.setBackgroundColor(background);
  largeTypeWindow?.setBackgroundColor(background);
  updateLiveFileWindows((state) => {
    state.window.setBackgroundColor(terminalBackgroundColor(state.theme));
  });
  updateLiveTerminalWindows((state) => {
    state.window.setBackgroundColor(terminalBackgroundColor(state.theme));
  });
}

function updateSystemAppearance(): void {
  updateWindowBackgrounds();
  const theme = resolvedSystemTheme();
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed() && !window.webContents.isDestroyed()) {
      window.webContents.send("fd0:system-theme", theme);
    }
  }
}

function openFileWindow(options: {
  host: string;
  scopeId: string;
  environment: NodeJS.ProcessEnv;
  theme: TerminalTheme;
}): BrowserWindow {
  const mac = process.platform === "darwin";
  const displayHost = terminalTitlePart(options.host) || "SSH host";
  const window = new BrowserWindow({
    width: 1040,
    height: 700,
    minWidth: 720,
    minHeight: 480,
    show: false,
    title: `${displayHost} — Files — fd0`,
    backgroundColor: terminalBackgroundColor(options.theme),
    ...(mac
      ? {
          titleBarStyle: "hiddenInset" as const,
          trafficLightPosition: { x: 18, y: 18 },
        }
      : {}),
    webPreferences: secureWebPreferences(["--fd0-files"]),
  });
  const client = new SFTPBridgeClient(
    sftpBridgeBinary(),
    options.host,
    options.scopeId,
    options.environment,
    (event) => diagnostics?.record("sftp", event),
  );
  const id = window.webContents.id;
  const state = {
    window,
    client,
    host: displayHost,
    theme: options.theme,
    alias: options.host,
    scopeId: options.scopeId,
    environment: options.environment,
    activeTransfers: new Set<string>(),
  } satisfies FileWindowState;
  fileWindows.set(id, state);
  applyWindowGuards(window);
  window.on("closed", () => {
    fileWindows.delete(id);
    state.client.dispose();
  });
  window.webContents.on("render-process-gone", () => {
    if (!window.isDestroyed()) window.destroy();
  });
  window.once("ready-to-show", () => {
    window.show();
    window.focus();
  });
  void window.loadURL(rendererEntryURL());
  return window;
}

function openTerminalWindow(options: {
  host: string;
  scopeId: string;
  fd0Binary: string;
  environment: NodeJS.ProcessEnv;
  cwd: string;
  theme: TerminalTheme;
}): BrowserWindow {
  const mac = process.platform === "darwin";
  const displayHost = terminalTitlePart(options.host) || "SSH host";
  const window = new BrowserWindow({
    width: 980,
    height: 640,
    minWidth: 640,
    minHeight: 360,
    show: false,
    title: `${displayHost} — SSH — fd0`,
    backgroundColor: terminalBackgroundColor(options.theme),
    ...(mac
      ? {
          titleBarStyle: "hiddenInset" as const,
          trafficLightPosition: { x: 18, y: 18 },
        }
      : {}),
    webPreferences: secureWebPreferences(["--fd0-terminal"]),
  });
  const state = {
    window,
    sessionId: "",
    host: displayHost,
    theme: options.theme,
    processName: "ssh",
    remoteTitle: "",
  } satisfies TerminalWindowState;
  state.sessionId = terminalSessions.create(
    {
      host: options.host,
      scopeId: options.scopeId,
      fd0Binary: options.fd0Binary,
      environment: options.environment,
      cwd: options.cwd,
    },
    {
      data: (value) => sendTerminalEvent(state, "fd0:terminal-data", value),
      exit: (value) => sendTerminalEvent(state, "fd0:terminal-exit", value),
      process: (value) => {
        state.processName = terminalTitlePart(value) || "ssh";
        updateTerminalWindowTitle(state);
        sendTerminalEvent(state, "fd0:terminal-process", state.processName);
      },
    },
  );
  const terminalWindowId = window.webContents.id;
  terminalWindows.set(terminalWindowId, state);
  applyWindowGuards(window);
  updateTerminalWindowTitle(state);
  window.on("closed", () => {
    releaseTerminalWindow(terminalWindowId, state);
  });
  window.webContents.on("render-process-gone", () => {
    if (!window.isDestroyed()) window.destroy();
  });
  window.once("ready-to-show", () => {
    window.show();
    window.focus();
  });
  void window.loadURL(rendererEntryURL());
  return window;
}

function createWindow(): BrowserWindow {
  const mac = process.platform === "darwin";
  const window = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 860,
    minHeight: 600,
    show: false,
    backgroundColor: windowBackgroundColor(),
    ...(mac
      ? {
          titleBarStyle: "hiddenInset" as const,
          trafficLightPosition: { x: 18, y: 18 },
        }
      : {}),
    webPreferences: secureWebPreferences(),
  });
  applyWindowGuards(window);
  window.on("closed", () => {
    if (mainWindow === window) mainWindow = null;
  });
  window.once("ready-to-show", () => window.show());
  window.webContents.once("did-finish-load", flushDesktopUpdateRequest);
  void window.loadURL(rendererEntryURL(pendingDesktopUpdateRequest ? "#support" : ""));
  return window;
}

// ------------------------------------------------------------------ large type

const LARGE_TYPE_SECONDS = 30;
/**
 * The renderer counts down from 30 and closes itself. Main keeps a slightly
 * later hard stop so a stalled or paused renderer cannot leave the value on
 * screen — and in main-process memory — indefinitely.
 */
const LARGE_TYPE_HARD_STOP_MS = (LARGE_TYPE_SECONDS + 5) * 1000;
const LARGE_TYPE_MAX_CHARACTERS = 512;

let largeTypeWindow: BrowserWindow | null = null;
/**
 * The only copy of the value outside the renderer that asked for it.
 *
 * The value never touches disk, the network, or a third process: the main
 * window hands it over the existing validated IPC, main holds it in this
 * variable, and the floating window pulls it back over IPC once its document is
 * live. Passing it through the URL, a query string, or localStorage instead
 * would persist it in session history and in the Electron profile on disk.
 */
let largeTypeValue: LargeTypeValue | null = null;
let largeTypeTimer: NodeJS.Timeout | null = null;

function closeLargeTypeWindow(): void {
  if (largeTypeTimer) clearTimeout(largeTypeTimer);
  largeTypeTimer = null;
  largeTypeValue = null;
  const window = largeTypeWindow;
  largeTypeWindow = null;
  if (window && !window.isDestroyed()) window.destroy();
}

/** Centres the window on the display holding the focused window, or the cursor. */
function largeTypeBounds(width: number, height: number): Electron.Rectangle {
  const focused = BrowserWindow.getFocusedWindow();
  const bounds = focused && !focused.isDestroyed() ? focused.getBounds() : null;
  const anchor = bounds
    ? { x: Math.round(bounds.x + bounds.width / 2), y: Math.round(bounds.y + bounds.height / 2) }
    : screen.getCursorScreenPoint();
  const area = screen.getDisplayNearestPoint(anchor).workArea;
  const fitted = { width: Math.min(width, area.width), height: Math.min(height, area.height) };
  return {
    ...fitted,
    x: Math.round(area.x + (area.width - fitted.width) / 2),
    y: Math.round(area.y + (area.height - fitted.height) / 2),
  };
}

function openLargeTypeWindow(label: unknown, value: unknown): LargeTypeWindowResult {
  if (typeof label !== "string" || typeof value !== "string") throw new Error("Invalid large type request");
  const characters = [...value];
  if (characters.length === 0 || characters.length > LARGE_TYPE_MAX_CHARACTERS) {
    throw new Error("That value cannot be shown in large type");
  }
  // Only one at a time: a second request replaces the first and drops its value.
  closeLargeTypeWindow();

  const window = new BrowserWindow({
    ...largeTypeBounds(780, 440),
    minWidth: 420,
    minHeight: 260,
    show: false,
    frame: false,
    resizable: true,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    alwaysOnTop: true,
    title: "fd0 large type",
    backgroundColor: windowBackgroundColor(),
    webPreferences: secureWebPreferences(["--fd0-large-type"]),
  });
  /*
   * "floating" maps to NSFloatingWindowLevel on macOS and the equivalent
   * always-on-top band elsewhere. Window levels are a system-wide ordering, so
   * this sits above ordinary windows of every application — the point of the
   * feature is reading a code out while typing into a different app.
   */
  window.setAlwaysOnTop(true, "floating");
  if (process.platform === "darwin") {
    window.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  }
  applyWindowGuards(window);
  window.on("closed", () => {
    if (largeTypeWindow === window) closeLargeTypeWindow();
  });
  window.once("ready-to-show", () => {
    window.show();
    window.focus();
  });

  largeTypeWindow = window;
  largeTypeValue = { label: dialogText(label, "Value"), value };
  largeTypeTimer = setTimeout(closeLargeTypeWindow, LARGE_TYPE_HARD_STOP_MS);
  void window.loadURL(rendererEntryURL("#large-type"));
  return { window: true };
}

/**
 * The large-type window gets its own sender check rather than being added to
 * `assertTrustedSender`: it may only reach the four channels below, and every
 * other fd0 channel stays main-window-only.
 */
function assertLargeTypeSender(event: Electron.IpcMainInvokeEvent): void {
  if (!largeTypeWindow || largeTypeWindow.isDestroyed() || event.sender.id !== largeTypeWindow.webContents.id) {
    throw new Error("Untrusted IPC sender");
  }
}

function registerLargeTypeIPC(): void {
  ipcMain.handle("fd0:show-large-type", (event, label: unknown, value: unknown) => {
    assertTrustedSender(event);
    return respond(async () => openLargeTypeWindow(label, value));
  });
  ipcMain.handle("fd0:large-type-value", (event) => {
    assertLargeTypeSender(event);
    return respond(async () => largeTypeValue);
  });
  ipcMain.handle("fd0:large-type-copy", (event) => {
    assertLargeTypeSender(event);
    return respond(async () => {
      if (!largeTypeValue) throw new Error("That value is no longer available");
      return writeManagedClipboard(largeTypeValue.value);
    });
  });
  ipcMain.handle("fd0:large-type-close", (event) => {
    assertLargeTypeSender(event);
    return respond(async () => closeLargeTypeWindow());
  });
}

function registerAppProtocol(): void {
  const rendererRoot = resolve(applicationRoot, "out", "renderer");
  protocol.handle("fd0-app", (request) => {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return new Response("Not found", { status: 404 });
    }
    if (url.hostname !== "app" || url.username !== "" || url.password !== "" || url.port !== "") {
      return new Response("Not found", { status: 404 });
    }
    let pathname: string;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      return new Response("Not found", { status: 404 });
    }
    const target = resolve(rendererRoot, pathname.replace(/^\/+/, "") || "index.html");
    if (target !== rendererRoot && !target.startsWith(rendererRoot + sep)) {
      return new Response("Not found", { status: 404 });
    }
    return net.fetch(pathToFileURL(target).toString());
  });
}

async function initializeServices(): Promise<StartupStatus> {
  if (startupStatus.state === "ready") return startupStatus;
  if (servicesStarting) return servicesStarting;
  servicesStarting = (async () => {
    startupStatus = { state: "starting" };
    const client = new BridgeSupervisor(
      bridgeBinary(),
      runtimeEnvironment(),
      (event, detail) => diagnostics?.record("bridge", event, detail),
    );
    try {
      await client.start();
      bridge = client;
      if (nativeAgentManaged) {
        const serviceStatus = await agentLifecycle.ensureRunning();
        diagnostics?.record("agent", `service:${serviceStatus}`);
        if (serviceStatus === "enabled") await ensureManagedAgent(client);
        else if (serviceStatus !== "requires-approval") await agentLifecycle.assertReady(serviceStatus);
        if (serviceStatus === "requires-approval") {
          void showAppMessageBox({
            type: "warning",
            buttons: ["Open Login Items", "Later"],
            defaultId: 0,
            cancelId: 1,
            title: "Allow the fd0 background service",
            message: "fd0 needs permission to run its local vault service.",
            detail: "The service starts locked and keeps your CLI and desktop app available after restarts.",
            noLink: true,
          }).then((answer) => {
            if (answer.response === 0) {
              void shell.openExternal("x-apple.systempreferences:com.apple.LoginItems-Settings.extension");
            }
          });
        }
      }
      if (!domainIPCRegistered) {
        registerIPC(client);
        domainIPCRegistered = true;
      }
      if (!disposeAutoLockEvents) disposeAutoLockEvents = configureAutoLock();
      await refreshSecurityStatus();
      if (!securityStatusTimer) {
        securityStatusTimer = setInterval(() => void refreshSecurityStatus(), 10_000);
      }
      startupStatus = { state: "ready" };
      diagnostics?.record("app", "services-ready");
      sendCommand("refresh");
      return startupStatus;
    } catch (error) {
      client.dispose();
      if (bridge === client) bridge = null;
      const message = redactDiagnosticText(error);
      startupStatus = { state: "error", message };
      diagnostics?.record("app", "startup-failed", error);
      return startupStatus;
    } finally {
      servicesStarting = null;
    }
  })();
  return servicesStarting;
}

async function start(): Promise<void> {
  await app.whenReady();
  if (terminalRuntimeSmokeRequested) {
    try {
      await verifyTerminalRuntime();
      console.log("fd0 terminal runtime ok");
      app.exit(0);
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      app.exit(1);
    }
    return;
  }
  nativeTheme.on("updated", updateSystemAppearance);
  diagnostics = new DiagnosticsLog(join(app.getPath("logs"), "fd0-desktop.log"));
  diagnostics.record("app", "starting", `${process.platform}/${process.arch} ${app.getVersion()}`);
  if (lifecycleCommand) {
    if (lifecycleCommand === "--fd0-agent-service-restart") {
      await agentLifecycle.restart();
    } else if (lifecycleCommand === "--fd0-agent-service-stop") {
      await agentLifecycle.stop();
    } else {
      await agentLifecycle.uninstall();
    }
    app.exit(0);
    return;
  }
  if (!app.isPackaged && process.platform === "darwin") {
    app.dock?.setIcon(join(applicationRoot, "resources", "icon.png"));
  }
  registerAppProtocol();
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  registerInfrastructureIPC();
  registerTerminalIPC();
  registerFileIPC();
  registerLargeTypeIPC();
  buildMenu();
  mainWindow = createWindow();
  createTray();
  configureUpdater();
  await initializeServices();
  flushDesktopUpdateRequest();
  app.on("activate", () => {
    if (!mainWindow) mainWindow = createWindow();
    void reconcileManagedAgent();
  });
}

app.on("second-instance", (_event, commandLine) => {
  showMainWindow();
  if (commandLine.includes(desktopUpdateRequestArg)) requestDesktopUpdate();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

let quitPrepared = false;
app.on("before-quit", (event) => {
  // Runs on both passes: the quit below is deferred, and nothing should keep a
  // secret on screen while the vault is being locked.
  closeLargeTypeWindow();
  terminalSessions.closeAll();
  for (const state of fileWindows.values()) state.client.dispose();
  fileWindows.clear();
  if (!quitPrepared && bridge && !installingUpdate) {
    event.preventDefault();
    quitPrepared = true;
    void bridge.request("vault.lock", {}, 5_000)
      .catch(() => undefined)
      .finally(() => app.quit());
    return;
  }
  managedClipboard.clear();
  operationGrants.clear();
  if (updateTimer) clearTimeout(updateTimer);
  if (securityStatusTimer) clearInterval(securityStatusTimer);
  securityStatusTimer = null;
  nativeTheme.removeListener("updated", updateSystemAppearance);
  disposeAutoLockEvents?.();
  disposeAutoLockEvents = null;
  bridge?.dispose();
  tray?.destroy();
});

void start().catch((error) => {
  diagnostics?.record("app", "fatal-startup-error", error);
  startupStatus = { state: "error", message: redactDiagnosticText(error) };
  if (!mainWindow) {
    dialog.showErrorBox("fd0 could not start", "The desktop window could not be created. Reopen fd0 or inspect the application logs.");
    app.quit();
  }
});
