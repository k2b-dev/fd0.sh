import { contextBridge, ipcRenderer, webUtils } from "electron";
import type {
  BridgeErrorShape,
  DesktopAPI,
  DesktopCommand,
  DesktopTheme,
  DiagnosticsSnapshot,
  FieldRef,
  GenerateSSHKeyInput,
  ItemVersionRef,
  LargeTypeValue,
  LargeTypeWindowResult,
  MoveItemInput,
  RenameItemInput,
  OrganizationBatch, RecordRef,
  ResolvedDesktopTheme,
  SavePassInput,
  SaveSecretInput,
  SaveSSHHostInput,
  SaveSSHKeyInput,
  StartupStatus,
  SFTPEntry,
  SFTPPreview,
  SFTPTransferEvent,
  TerminalLauncherSettings,
  TerminalExit,
  TerminalSessionInfo,
  TerminalTheme,
  UpdateStatus,
} from "../shared/contracts";

type IPCResult<T> = { ok: true; value: T } | { ok: false; error: BridgeErrorShape };

class DesktopError extends Error {
  readonly code: string;
  readonly action?: string;
  readonly retryable: boolean;

  constructor(shape: BridgeErrorShape) {
    super(shape.message);
    this.name = "DesktopError";
    this.code = shape.code;
    this.action = shape.action;
    this.retryable = shape.retryable ?? false;
  }
}

async function invoke<T>(channel: string, ...args: unknown[]): Promise<T> {
  const result = (await ipcRenderer.invoke(channel, ...args)) as IPCResult<T>;
  if (!result.ok) throw new DesktopError(result.error);
  return result.value;
}

const api: DesktopAPI = {
  platform: process.platform,
  development: process.argv.includes("--fd0-isolated"),
  largeTypeMode: process.argv.includes("--fd0-large-type"),
  terminalMode: process.argv.includes("--fd0-terminal"),
  fileMode: process.argv.includes("--fd0-files"),
  startupStatus: () => invoke<StartupStatus>("fd0:startup-status"),
  consumeUpdateRequest: () => invoke<boolean>("fd0:consume-update-request"),
  retryStartup: () => invoke<StartupStatus>("fd0:retry-startup"),
  repairService: () => invoke<StartupStatus>("fd0:repair-service"),
  diagnostics: () => invoke<DiagnosticsSnapshot>("fd0:diagnostics"),
  copyDiagnostics: () => invoke("fd0:copy-diagnostics"),
  openLogs: () => invoke("fd0:open-logs"),
  openLoginItems: () => invoke("fd0:open-login-items"),
  quit: () => invoke("fd0:quit"),
  status: () => invoke("fd0:status"),
  createVault: (passphrase: string, label: string) => invoke("fd0:create-vault", passphrase, label),
  unlock: (input) => invoke("fd0:unlock", input),
  lock: () => invoke("fd0:lock"),
  restartAgent: () => invoke("fd0:restart-agent"),
  selectRecoveryFile: () => invoke("fd0:select-recovery-file"),
  restoreVault: (recoveryPassphrase: string, newPassphrase?: string) => invoke("fd0:restore-vault", recoveryPassphrase, newPassphrase ?? ""),
  exportRecovery: (passphrase: string) => invoke("fd0:export-recovery", passphrase),
  setDefaultAuthMethod: (method: string) => invoke("fd0:set-default-auth", method),
  inventory: () => invoke("fd0:inventory"),
  deletedItems: () => invoke("fd0:deleted-items"),
  parseTOTPURI: (uri: string) => invoke("fd0:parse-totp", uri),
  itemDetail: (ref: RecordRef) => invoke("fd0:item-detail", ref),
  itemHistory: (ref: RecordRef, options?: { limit?: number; offset?: number }) => invoke("fd0:item-history", ref, options),
  itemVersion: (ref: ItemVersionRef) => invoke("fd0:item-version", ref),
  restoreItemVersion: (ref: ItemVersionRef) => invoke("fd0:restore-item-version", ref),
  reveal: (ref: FieldRef) => invoke("fd0:reveal", ref),
  copy: (ref: FieldRef) => invoke("fd0:copy", ref),
  copyText: (value: string) => invoke("fd0:copy-text", value),
  savePass: (input: SavePassInput) => invoke("fd0:save-pass", input),
  editPass: (ref: RecordRef) => invoke("fd0:edit-pass", ref),
  organizationInventory: () => invoke("fd0:organization-inventory"),
  organizeItems: (request: OrganizationBatch) => invoke("fd0:organization-batch", request),
  setItemTags: (ref: RecordRef, tags: string[], expectedTags?: string[]) => invoke("fd0:set-item-tags", ref, tags, expectedTags),
  setFavorite: (ref: RecordRef, favorite: boolean) => invoke("fd0:set-favorite", ref, favorite),
  pickAttachment: () => invoke("fd0:pick-attachment"),
  saveSecret: (input: SaveSecretInput) => invoke("fd0:save-secret", input),
  editSecret: (ref: RecordRef) => invoke("fd0:edit-secret", ref),
  saveSSHHost: (input: SaveSSHHostInput) => invoke("fd0:save-ssh-host", input),
  editSSHHost: (ref: RecordRef) => invoke("fd0:edit-ssh-host", ref),
  generateSSHKey: (input: GenerateSSHKeyInput) => invoke("fd0:generate-ssh-key", input),
  listSSHKeys: (scopeId: string) => invoke("fd0:list-ssh-keys", scopeId),
  saveSSHKey: (input: SaveSSHKeyInput) => invoke("fd0:save-ssh-key", input),
  editSSHKey: (ref: RecordRef) => invoke("fd0:edit-ssh-key", ref),
  importConfig: (kind: "kubernetes" | "talos", scopeId: string) => invoke("fd0:import-config", kind, scopeId),
  saveAttachment: (ref: FieldRef) => invoke("fd0:save-attachment", ref),
  moveItem: (input: MoveItemInput) => invoke("fd0:move-item", input),
  renameItem: (input: RenameItemInput) => invoke("fd0:rename-item", input),
  remove: (ref: RecordRef) => invoke("fd0:remove", ref),
  restoreDeletedItem: (ref: ItemVersionRef) => invoke("fd0:restore-deleted-item", ref),
  createScope: (label: string) => invoke("fd0:create-scope", label),
  renameScope: (scopeId: string, label: string) => invoke("fd0:rename-scope", scopeId, label),
  leaveScope: (scopeId: string) => invoke("fd0:leave-scope", scopeId),
  scopeShareInfo: (scopeId: string) => invoke("fd0:scope-share-info", scopeId),
  addScopeMember: (scopeId: string, label: string) => invoke("fd0:scope-add-member", scopeId, label),
  removeScopeMember: (scopeId: string, memberId: string) => invoke("fd0:scope-remove-member", scopeId, memberId),
  exportIdentityCard: () => invoke("fd0:card-export"),
  inspectIdentityCard: (url: string) => invoke("fd0:card-inspect", url),
  importIdentityCard: (url: string, label: string) => invoke("fd0:card-import", url, label),
  sync: () => invoke("fd0:sync"),
  launchAtLogin: () => invoke("fd0:launch-at-login"),
  setLaunchAtLogin: (value: boolean) => invoke("fd0:set-launch-at-login", value),
  systemTheme: () => invoke<ResolvedDesktopTheme>("fd0:system-theme"),
  onSystemTheme: (handler: (theme: ResolvedDesktopTheme) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, theme: ResolvedDesktopTheme) => handler(theme);
    ipcRenderer.on("fd0:system-theme", listener);
    return () => ipcRenderer.removeListener("fd0:system-theme", listener);
  },
  setTheme: (theme: DesktopTheme) => invoke("fd0:set-theme", theme),
  terminalLauncher: () => invoke("fd0:terminal-launcher"),
  setTerminalLauncher: (settings: TerminalLauncherSettings) => invoke("fd0:set-terminal-launcher", settings),
  openSSHHost: (ref: RecordRef) => invoke("fd0:open-ssh-host", ref),
  openSSHFiles: (ref: RecordRef) => invoke("fd0:open-ssh-files", ref),
  terminalSession: () => invoke<TerminalSessionInfo>("fd0:terminal-session"),
  startTerminal: (cols: number, rows: number) => invoke<void>("fd0:terminal-start", cols, rows),
  writeTerminal: (data: string) => ipcRenderer.send("fd0:terminal-write", data),
  resizeTerminal: (cols: number, rows: number) => ipcRenderer.send("fd0:terminal-resize", cols, rows),
  setTerminalTitle: (title: string) => ipcRenderer.send("fd0:terminal-title", title),
  copyTerminalSelection: (value: string) => invoke<void>("fd0:terminal-copy", value),
  pasteTerminal: () => invoke<void>("fd0:terminal-paste"),
  closeTerminal: () => invoke<void>("fd0:terminal-close"),
  onTerminalData: (handler: (data: string) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, data: string) => handler(data);
    ipcRenderer.on("fd0:terminal-data", listener);
    return () => ipcRenderer.removeListener("fd0:terminal-data", listener);
  },
  onTerminalExit: (handler: (result: TerminalExit) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, result: TerminalExit) => handler(result);
    ipcRenderer.on("fd0:terminal-exit", listener);
    return () => ipcRenderer.removeListener("fd0:terminal-exit", listener);
  },
  onTerminalProcess: (handler: (processName: string) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, processName: string) => handler(processName);
    ipcRenderer.on("fd0:terminal-process", listener);
    return () => ipcRenderer.removeListener("fd0:terminal-process", listener);
  },
  onTerminalTheme: (handler: (theme: TerminalTheme) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, theme: TerminalTheme) => handler(theme);
    ipcRenderer.on("fd0:terminal-theme", listener);
    return () => ipcRenderer.removeListener("fd0:terminal-theme", listener);
  },
  sftpSession: () => invoke("fd0:sftp-session"),
  sftpReconnect: () => invoke("fd0:sftp-reconnect"),
  sftpList: (path: string) => invoke("fd0:sftp-list", path),
  sftpPreview: (path: string) => invoke<SFTPPreview>("fd0:sftp-preview", path),
  sftpUpload: (remoteDirectory: string) => invoke("fd0:sftp-upload", remoteDirectory),
  sftpUploadDropped: (remoteDirectory: string, files: File[]) =>
    invoke(
      "fd0:sftp-upload-dropped",
      remoteDirectory,
      files.map((file) => webUtils.getPathForFile(file)),
    ),
  sftpDownload: (entry: SFTPEntry) => invoke("fd0:sftp-download", entry),
  sftpMkdir: (path: string) => invoke("fd0:sftp-mkdir", path),
  sftpRename: (oldPath: string, newPath: string) => invoke("fd0:sftp-rename", oldPath, newPath),
  sftpRemove: (path: string, recursive: boolean) => invoke("fd0:sftp-remove", path, recursive),
  sftpCancel: (id: string) => invoke("fd0:sftp-cancel", id),
  closeSFTP: () => invoke("fd0:sftp-close"),
  onSFTPTransfer: (handler: (event: SFTPTransferEvent) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, value: SFTPTransferEvent) => handler(value);
    ipcRenderer.on("fd0:sftp-transfer", listener);
    return () => ipcRenderer.removeListener("fd0:sftp-transfer", listener);
  },
  openItemURL: (ref: RecordRef) => invoke("fd0:open-item-url", ref),
  openSupportLink: (target: "browser" | "browserDocs" | "docs" | "issues") =>
    invoke("fd0:open-support-link", target),
  showLargeType: (label: string, value: string) => invoke<LargeTypeWindowResult>("fd0:show-large-type", label, value),
  largeTypeValue: () => invoke<LargeTypeValue | null>("fd0:large-type-value"),
  copyLargeType: () => invoke<{ clearAfterSeconds: number }>("fd0:large-type-copy"),
  closeLargeType: () => invoke<void>("fd0:large-type-close"),
  updateStatus: () => invoke("fd0:update-status"),
  checkForUpdates: () => invoke("fd0:check-updates"),
  installUpdate: () => invoke("fd0:install-update"),
  onUpdate: (handler: (status: UpdateStatus) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, status: UpdateStatus) => handler(status);
    ipcRenderer.on("desktop:update", listener);
    return () => ipcRenderer.removeListener("desktop:update", listener);
  },
  onCommand: (handler: (command: DesktopCommand) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, command: DesktopCommand) => handler(command);
    ipcRenderer.on("desktop:command", listener);
    return () => ipcRenderer.removeListener("desktop:command", listener);
  },
};

contextBridge.exposeInMainWorld("fd0", Object.freeze(api));
