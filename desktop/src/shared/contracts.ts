export type ItemKind = "password" | "ssh" | "kubernetes" | "talos" | "secret";

export type BridgeErrorShape = {
  code: string;
  message: string;
  action?: string;
  retryable?: boolean;
};

export type VaultStatus = {
  vaultExists: boolean;
  agentRunning: boolean;
  /**
   * Set only when the running background service genuinely cannot serve this
   * app — a different release version is not such a case. The reason is one
   * sentence written for the user.
   */
  agentIncompatible?: boolean;
  agentIncompatibleReason?: string;
  /** Who started the running service: this app, or anything else. */
  agentStartedBy?: "desktop" | "external";
  unlocked: boolean;
  unlockedSince?: number;
  version?: string;
  flavor?: string;
  expectedVersion?: string;
  expectedFlavor?: string;
  yubikey: boolean;
  idleTimeoutMillis?: number;
  maxLifetimeMillis?: number;
  authMethods?: AuthMethodSummary[];
  readiness?: {
    firstSyncAt?: number;
    lastSyncAt?: number;
    recoveryVerifiedAt?: number;
    recoveryAuthTip?: string;
  };
};

export type AuthMethodSummary = {
  id: string;
  type: string;
  label: string;
  pinMode?: "none" | "required" | "optional";
  touchPolicy?: string;
  default?: boolean;
};

export type UnlockInput = {
  method?: string;
  passphrase?: string;
  pin?: string;
};

export type ScopeSummary = {
  id: string;
  label: string;
};

export type TrustedContact = {
  label: string;
  fingerprint: string;
  shared?: boolean;
};

export type ScopeMember = {
  id: string;
  label: string;
  fingerprint: string;
  self?: boolean;
  trusted?: boolean;
};

export type ScopeShareInfo = {
  scopeLabel: string;
  contacts: TrustedContact[];
  members: ScopeMember[];
};

export type IdentityCardInfo = {
  url?: string;
  shortId: string;
  fingerprint: string;
  safetyNumber: string;
  expiresAt: string;
};

export type SyncPreparation = {
  serverUrl: string;
  serverPub: string;
  fingerprint: string;
  label?: string;
  hosted: boolean;
  alreadyPinned: boolean;
  requiresConfirmation: boolean;
};

export type ItemSummary = {
  id: string;
  scopeId: string;
  recordName: string;
  kind: ItemKind;
  title: string;
  subtitle?: string;
  vault: string;
  badge: string;
  updatedAt?: string;
  favorite?: boolean;
  /** Safe, non-secret metadata used only for local search. */
  searchText?: string;
  hasTOTP?: boolean;
  tags?: string[];
};

export type FileView = {
  name: string;
  mime?: string;
  size: number;
};

export type FieldView = {
  name: string;
  path: string;
  type: string;
  section?: string;
  value?: string;
  sensitive?: boolean;
  copyable?: boolean;
  remaining?: number;
  file?: FileView;
  children?: FieldView[];
};

export type ItemDetail = {
  item: ItemSummary;
  fields: FieldView[];
  relations?: ItemRelation[];
};

export type ItemRelation = {
  kind: "used-by";
  item: ItemSummary;
};

export type Inventory = {
  scopes: ScopeSummary[];
  items: ItemSummary[];
  counts: Record<string, number>;
  truncated?: boolean;
};

export type RecordRef = {
  scopeId: string;
  name: string;
  raw?: boolean;
};

export type MoveItemInput = {
  source: RecordRef;
  targetScopeId: string;
};

export type RenameItemInput = {
  source: RecordRef;
  name: string;
};

export type DeletedItem = {
  item: ItemSummary;
  restoreSeq: number;
};

export type TOTPValue = {
  secret: string;
  issuer?: string;
  account?: string;
  digits: number;
  period: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
};

export type FieldRef = RecordRef & {
  path: string;
  /**
   * Read this field from a historical version instead of the current one.
   * Omitted means "current", and the behaviour is unchanged.
   */
  seq?: number;
};

/** One past version of an item, from the scope's signed event chain. */
export type ItemHistoryEntry = {
  /** Content-addressed chain event id. Stable across reads. */
  id: string;
  /** Position in the chain. Authoritative ordering; always present. */
  seq: number;
  /**
   * Only pass items carry a revision and a timestamp in their payload. These
   * are omitted rather than invented for other types, because the event
   * envelope has no clock of its own.
   */
  revision?: number;
  updatedAt?: string;
  /** Resolved person label, never a raw fingerprint. */
  author: string;
  /** This version deleted the item. */
  tombstone?: boolean;
  /** Shape-only description, e.g. "6 fields" or "Deleted". */
  summary: string;
};

export type ItemHistoryPage = {
  /** Total versions in the chain, regardless of paging. */
  total: number;
  limit: number;
  offset: number;
  entries: ItemHistoryEntry[];
  /** The page stopped early to stay inside the bridge frame limit. */
  truncated?: boolean;
};

export type ItemVersionRef = RecordRef & { seq: number };

export type PassField = {
  type: "text" | "secret" | "totp" | "passkey" | "file" | "section";
  name: string;
  value?: unknown;
  fields?: PassField[];
  meta?: Record<string, unknown>;
};

export type PassItemData = {
  title: string;
  urls?: string[];
  fields: PassField[];
  meta?: Record<string, unknown>;
};

export type SavePassInput = {
  scopeId: string;
  recordName: string;
  item: PassItemData;
  create?: boolean;
  authorization?: string;
};

export type AttachmentValue = {
  name: string;
  mime?: string;
  size: number;
  sha256: string;
  data_b64: string;
};

export type SaveSecretInput = {
  scopeId: string;
  name: string;
  value: string;
  oldName?: string;
  create?: boolean;
  authorization?: string;
};

export type SaveSSHHostInput = {
  scopeId: string;
  oldName?: string;
  authorization?: string;
  host: {
    Alias: string;
    Hostname: string;
    User?: string;
    Port?: number;
    KeyName?: string;
    ProxyJump?: string;
    Tags?: string[];
    Description?: string;
    Options?: Record<string, string>;
  };
};

export type GenerateSSHKeyInput = {
  scopeId: string;
  name: string;
  comment?: string;
};

export type SSHKeySummary = {
  scopeId: string;
  name: string;
  algorithm: string;
  fingerprint: string;
  comment?: string;
};

export type SaveSSHKeyInput = {
  scopeId: string;
  name: string;
  comment?: string;
  authorization?: string;
};

export type ImportConfigResult = {
  imported: string[];
  skipped?: string[];
};

/** The label and value shown by the floating large-type window. */
export type LargeTypeValue = {
  label: string;
  value: string;
};

export type LargeTypeWindowResult = {
  /**
   * False when the floating window could not be created. The caller then falls
   * back to the in-window modal instead of failing silently.
   */
  window: boolean;
};

export type UpdateStatus = {
  state: "unsupported" | "idle" | "checking" | "available" | "downloading" | "ready" | "current" | "error";
  version?: string;
  progress?: number;
  message?: string;
};

export type StartupStatus = {
  state: "starting" | "ready" | "error";
  message?: string;
};

export type DiagnosticsSnapshot = {
  generatedAt: string;
  health: "healthy" | "attention";
  app: {
    version: string;
    platform: NodeJS.Platform;
    architecture: string;
    packageType: string;
  };
  paths: {
    application: string;
    fd0Home: string;
    logs: string;
  };
  service: {
    state: string;
    running?: boolean;
    version?: string;
    flavor?: string;
    startedBy?: "desktop" | "external";
    incompatible?: boolean;
  };
  vault: {
    exists?: boolean;
    unlocked?: boolean;
    firstSyncComplete?: boolean;
    recoveryVerified?: boolean;
  };
  sync: {
    state: "never" | "ok" | "error";
    lastAttemptAt?: string;
  };
  update: UpdateStatus;
  recentErrors: Array<{
    at: string;
    component: string;
    event: string;
    message?: string;
  }>;
};

export type DesktopCommand =
  | "focus-search"
  | "new-item"
  | "open-support"
  | "open-settings"
  | "lock"
  | "refresh";

export type DesktopTheme = "system" | "dark" | "light";
export type ResolvedDesktopTheme = Exclude<DesktopTheme, "system">;
export type TerminalTheme = "system" | "dark" | "light";

export type TerminalProfileID =
  | "in-app"
  | "automatic"
  | "macos-terminal"
  | "iterm2"
  | "ghostty"
  | "linux-system"
  | "debian-default"
  | "ptyxis"
  | "gnome-terminal"
  | "konsole"
  | "custom";

export type TerminalLauncherSettings = {
  profileId: TerminalProfileID;
  /** Appearance of the fd0 terminal only; independent from the main app theme. */
  terminalTheme: TerminalTheme;
  /** Absolute executable or wrapper path. Used only by the custom profile. */
  customExecutable: string;
  /** Exact argv inserted before fd0's command. One entry is one argument. */
  customArguments: string[];
};

export type TerminalProfileSummary = {
  id: TerminalProfileID;
  label: string;
  description: string;
  available: boolean;
};

export type TerminalLauncherState = {
  settings: TerminalLauncherSettings;
  profiles: TerminalProfileSummary[];
  /** Concrete profile Automatic currently resolves to. */
  automaticProfileId?: TerminalProfileID;
};

export type TerminalSessionInfo = {
  host: string;
  terminalTheme: TerminalTheme;
};

export type TerminalExit = {
  exitCode: number;
  signal?: number;
};

export type SFTPEntry = {
  name: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  mode: string;
  modifiedAt: string;
  linkTarget?: string;
};

export type SFTPSessionInfo = {
  host: string;
  workingDirectory: string;
  terminalTheme: TerminalTheme;
};

export type SFTPPreview = {
  contentBase64: string;
  size: number;
  truncated: boolean;
};

export type SFTPProgress = {
  transferred: number;
  total: number;
};

export type SFTPTransferEvent = {
  id: string;
  direction: "upload" | "download";
  name: string;
  remotePath: string;
  state: "running" | "completed" | "failed" | "cancelled";
  transferred: number;
  total: number;
  error?: BridgeErrorShape;
};

export type DesktopAPI = {
  platform: NodeJS.Platform;
  development: boolean;
  /**
   * True only inside the dedicated always-on-top large-type window. It comes
   * from a process argument the main process sets on that window, so an in-page
   * navigation or a crafted URL fragment cannot turn the main window into it.
   */
  largeTypeMode: boolean;
  /** True only inside a dedicated fd0 terminal window. */
  terminalMode: boolean;
  /** True only inside a dedicated remote-files window. */
  fileMode: boolean;
  startupStatus(): Promise<StartupStatus>;
  consumeUpdateRequest(): Promise<boolean>;
  retryStartup(): Promise<StartupStatus>;
  repairService(): Promise<StartupStatus>;
  diagnostics(): Promise<DiagnosticsSnapshot>;
  copyDiagnostics(): Promise<{ copied: boolean }>;
  openLogs(): Promise<void>;
  openLoginItems(): Promise<void>;
  quit(): Promise<void>;
  status(): Promise<VaultStatus>;
  createVault(passphrase: string, label: string): Promise<VaultStatus>;
  unlock(input: UnlockInput): Promise<VaultStatus>;
  lock(): Promise<VaultStatus>;
  restartAgent(): Promise<VaultStatus>;
  selectRecoveryFile(): Promise<{ version: 1 | 2 } | null>;
  restoreVault(recoveryPassphrase: string, newPassphrase?: string): Promise<VaultStatus | null>;
  exportRecovery(passphrase: string): Promise<{ saved: boolean }>;
  setDefaultAuthMethod(method: string): Promise<VaultStatus>;
  inventory(): Promise<Inventory>;
  deletedItems(): Promise<{ items: DeletedItem[] }>;
  parseTOTPURI(uri: string): Promise<TOTPValue>;
  itemDetail(ref: RecordRef): Promise<ItemDetail>;
  itemHistory(ref: RecordRef, options?: { limit?: number; offset?: number }): Promise<ItemHistoryPage>;
  itemVersion(ref: ItemVersionRef): Promise<ItemDetail>;
  restoreItemVersion(ref: ItemVersionRef): Promise<{ ok: boolean }>;
  reveal(ref: FieldRef): Promise<{ value: string; remaining?: number } | null>;
  copy(ref: FieldRef): Promise<{ clearAfterSeconds: number }>;
  copyText(value: string): Promise<{ clearAfterSeconds: number }>;
  savePass(input: SavePassInput): Promise<{ ok: boolean }>;
  editPass(ref: RecordRef): Promise<SavePassInput | null>;
  setFavorite(ref: RecordRef, favorite: boolean): Promise<{ ok: boolean }>;
  pickAttachment(): Promise<AttachmentValue | null>;
  saveSecret(input: SaveSecretInput): Promise<{ ok: boolean }>;
  editSecret(ref: RecordRef): Promise<SaveSecretInput | null>;
  saveSSHHost(input: SaveSSHHostInput): Promise<{ ok: boolean }>;
  editSSHHost(ref: RecordRef): Promise<SaveSSHHostInput | null>;
  generateSSHKey(input: GenerateSSHKeyInput): Promise<{ ok: boolean }>;
  listSSHKeys(scopeId: string): Promise<SSHKeySummary[]>;
  saveSSHKey(input: SaveSSHKeyInput): Promise<{ ok: boolean }>;
  editSSHKey(ref: RecordRef): Promise<SaveSSHKeyInput | null>;
  importConfig(kind: "kubernetes" | "talos", scopeId: string): Promise<ImportConfigResult | null>;
  saveAttachment(ref: FieldRef): Promise<{ saved: boolean }>;
  moveItem(input: MoveItemInput): Promise<{ ok: boolean }>;
  renameItem(input: RenameItemInput): Promise<{ ok: boolean }>;
  remove(ref: RecordRef): Promise<{ ok: boolean; blocked?: boolean; undo?: ItemVersionRef }>;
  restoreDeletedItem(ref: ItemVersionRef): Promise<{ ok: boolean }>;
  createScope(label: string): Promise<{ ok: boolean }>;
  renameScope(scopeId: string, label: string): Promise<{ ok: boolean }>;
  leaveScope(scopeId: string): Promise<{ ok: boolean }>;
  scopeShareInfo(scopeId: string): Promise<ScopeShareInfo>;
  addScopeMember(scopeId: string, label: string): Promise<{ ok: boolean }>;
  removeScopeMember(scopeId: string, memberId: string): Promise<{ ok: boolean }>;
  exportIdentityCard(): Promise<IdentityCardInfo>;
  inspectIdentityCard(url: string): Promise<IdentityCardInfo>;
  importIdentityCard(url: string, label: string): Promise<{ ok: boolean }>;
  sync(): Promise<{ ok: boolean; cancelled?: boolean }>;
  launchAtLogin(): Promise<boolean>;
  setLaunchAtLogin(value: boolean): Promise<boolean>;
  systemTheme(): Promise<ResolvedDesktopTheme>;
  onSystemTheme(handler: (theme: ResolvedDesktopTheme) => void): () => void;
  setTheme(theme: DesktopTheme): Promise<void>;
  terminalLauncher(): Promise<TerminalLauncherState>;
  setTerminalLauncher(settings: TerminalLauncherSettings): Promise<TerminalLauncherState>;
  openSSHHost(ref: RecordRef): Promise<{ profileId: TerminalProfileID }>;
  openSSHFiles(ref: RecordRef): Promise<void>;
  terminalSession(): Promise<TerminalSessionInfo>;
  startTerminal(cols: number, rows: number): Promise<void>;
  writeTerminal(data: string): void;
  resizeTerminal(cols: number, rows: number): void;
  setTerminalTitle(title: string): void;
  copyTerminalSelection(value: string): Promise<void>;
  pasteTerminal(): Promise<void>;
  closeTerminal(): Promise<void>;
  onTerminalData(handler: (data: string) => void): () => void;
  onTerminalExit(handler: (result: TerminalExit) => void): () => void;
  onTerminalProcess(handler: (processName: string) => void): () => void;
  onTerminalTheme(handler: (theme: TerminalTheme) => void): () => void;
  sftpSession(): Promise<SFTPSessionInfo>;
  sftpReconnect(): Promise<SFTPSessionInfo>;
  sftpList(path: string): Promise<SFTPEntry[]>;
  sftpPreview(path: string): Promise<SFTPPreview>;
  sftpUpload(remoteDirectory: string): Promise<{ started: number }>;
  sftpUploadDropped(remoteDirectory: string, files: File[]): Promise<{ started: number }>;
  sftpDownload(entry: SFTPEntry): Promise<{ started: boolean }>;
  sftpMkdir(path: string): Promise<void>;
  sftpRename(oldPath: string, newPath: string): Promise<void>;
  sftpRemove(path: string, recursive: boolean): Promise<void>;
  sftpCancel(id: string): Promise<void>;
  closeSFTP(): Promise<void>;
  onSFTPTransfer(handler: (event: SFTPTransferEvent) => void): () => void;
  openItemURL(ref: RecordRef): Promise<void>;
  openSupportLink(target: "browser" | "browserDocs" | "docs" | "issues"): Promise<void>;
  showLargeType(label: string, value: string): Promise<LargeTypeWindowResult>;
  largeTypeValue(): Promise<LargeTypeValue | null>;
  copyLargeType(): Promise<{ clearAfterSeconds: number }>;
  closeLargeType(): Promise<void>;
  updateStatus(): Promise<UpdateStatus>;
  checkForUpdates(): Promise<UpdateStatus>;
  installUpdate(): Promise<void>;
  onUpdate(handler: (status: UpdateStatus) => void): () => void;
  onCommand(handler: (command: DesktopCommand) => void): () => void;
};
