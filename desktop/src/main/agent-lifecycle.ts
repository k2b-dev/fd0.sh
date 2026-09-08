import { app } from "electron";
import { execFile } from "node:child_process";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const macServiceName = "sh.fd0.desktop.agent.plist";
const linuxServiceName = "fd0-agent.service";
const desktopManagedMarker = "# fd0-desktop-managed-v1";

export type AgentServiceStatus =
  | "enabled"
  | "requires-approval"
  | "not-registered"
  | "unsupported";

export class AgentLifecycle {
  readonly #platform: NodeJS.Platform;
  readonly #packaged: boolean;
  readonly #appPath: string;
  readonly #home: string;
  readonly #run: typeof execFileAsync;
  readonly #linuxReadyTimeoutMs: number;
  readonly #macReadyTimeoutMs: number;

  constructor(options?: {
    platform?: NodeJS.Platform;
    packaged?: boolean;
    appPath?: string;
    home?: string;
    run?: typeof execFileAsync;
    linuxReadyTimeoutMs?: number;
    macReadyTimeoutMs?: number;
  }) {
    this.#platform = options?.platform ?? process.platform;
    this.#packaged = options?.packaged ?? app.isPackaged;
    this.#appPath = options?.appPath ?? (process.env.APPIMAGE || process.execPath);
    this.#home = options?.home ?? homedir();
    this.#run = options?.run ?? execFileAsync;
    this.#linuxReadyTimeoutMs = options?.linuxReadyTimeoutMs ?? 5_000;
    this.#macReadyTimeoutMs = options?.macReadyTimeoutMs ?? 5_000;
  }

  async ensureRunning(): Promise<AgentServiceStatus> {
    if (!this.#packaged) return "unsupported";
    if (this.#platform === "darwin") {
      const settings = { type: "agentService" as const, serviceName: macServiceName };
      const current = app.getLoginItemSettings(settings);
      if (current.status === "not-registered" || current.status === "not-found") {
        app.setLoginItemSettings({ ...settings, openAtLogin: true });
      }
      return this.#waitForMacRegistration();
    }
    if (this.#platform === "linux") {
      await this.#installLinuxUnit();
      await this.#systemctl(["enable", "--now", linuxServiceName]);
      await this.#waitForLinuxActive();
      return "enabled";
    }
    return "unsupported";
  }

  async status(): Promise<string> {
    if (!this.#packaged) return "development";
    if (this.#platform === "darwin") {
      return app.getLoginItemSettings({
        type: "agentService",
        serviceName: macServiceName,
      }).status;
    }
    if (this.#platform === "linux") {
      try {
        const result = await this.#run(
          "systemctl",
          ["--user", "is-active", linuxServiceName],
          { timeout: 5_000 },
        );
        return result.stdout.trim() || "unknown";
      } catch {
        return "inactive";
      }
    }
    return "unsupported";
  }

  async restart(): Promise<void> {
    if (!this.#packaged) throw new Error("Native agent supervision is unavailable in development mode");
    if (this.#platform === "darwin") {
      await this.stop();
      const status = await this.ensureRunning();
      if (status !== "enabled") throw approvalError(status);
      return;
    }
    if (this.#platform === "linux") {
      await this.#installLinuxUnit();
      // An explicit retry should also recover a service stopped by its start limit.
      await this.#systemctl(["reset-failed", linuxServiceName]);
      await this.#systemctl(["restart", linuxServiceName]);
      await this.#waitForLinuxActive();
      return;
    }
    throw new Error("Native agent supervision is unavailable on this platform");
  }

  async stop(): Promise<void> {
    if (!this.#packaged) return;
    if (this.#platform === "darwin") {
      const settings = { type: "agentService" as const, serviceName: macServiceName };
      const status = app.getLoginItemSettings(settings).status;
      if (status !== "not-registered" && status !== "not-found") {
        app.setLoginItemSettings({ ...settings, openAtLogin: false });
        await this.#waitForMacRemoval();
      }
      return;
    }
    if (this.#platform === "linux") {
      if (!(await this.#ownsLinuxUnit())) return;
      await this.#systemctl(["stop", linuxServiceName], true);
    }
  }

  async uninstall(): Promise<void> {
    if (this.#platform === "linux") {
      if (!(await this.#ownsLinuxUnit())) return;
      await this.stop();
      await this.#systemctl(["disable", linuxServiceName], true);
      await rm(this.#linuxUnitPath(), { force: true });
      await this.#systemctl(["daemon-reload"], true);
      return;
    }
    await this.stop();
  }

  async assertReady(status: AgentServiceStatus): Promise<void> {
    if (status === "enabled" || status === "unsupported") return;
    throw approvalError(status);
  }

  async guiLaunchesAtLogin(): Promise<boolean> {
    if (!this.#packaged) return false;
    if (this.#platform === "darwin") {
      return app.getLoginItemSettings({ type: "mainAppService" }).openAtLogin;
    }
    if (this.#platform === "linux") {
      try {
        await readFile(this.#linuxAutostartPath(), "utf8");
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  async setGuiLaunchAtLogin(enabled: boolean): Promise<boolean> {
    if (!this.#packaged) return false;
    if (this.#platform === "darwin") {
      app.setLoginItemSettings({ type: "mainAppService", openAtLogin: enabled });
      return this.guiLaunchesAtLogin();
    }
    if (this.#platform === "linux") {
      const path = this.#linuxAutostartPath();
      if (!enabled) {
        await rm(path, { force: true });
        return false;
      }
      const entry = [
        "[Desktop Entry]",
        "Type=Application",
        "Name=fd0",
        "Comment=Password and infrastructure credential manager",
        `Exec=${desktopExecQuote(this.#appPath)}`,
        "Terminal=false",
        "X-GNOME-Autostart-enabled=true",
        "",
      ].join("\n");
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, entry, { mode: 0o600 });
      return true;
    }
    return false;
  }

  async #installLinuxUnit(): Promise<void> {
    const path = this.#linuxUnitPath();
    const unit = [
      desktopManagedMarker,
      "[Unit]",
      "Description=fd0 local vault service",
      "Documentation=https://fd0.sh/docs",
      "StartLimitIntervalSec=60s",
      "StartLimitBurst=5",
      "",
      "[Service]",
      "Type=simple",
      `ExecStart=${systemdQuote(this.#appPath)} --fd0-agent-relay`,
      // AppImage's FUSE helper cannot elevate under NoNewPrivileges. Native
      // packages ignore this variable; AppImages extract before running the relay.
      "Environment=APPIMAGE_EXTRACT_AND_RUN=1",
      "Restart=on-failure",
      "RestartSec=2s",
      "TimeoutStopSec=10s",
      "NoNewPrivileges=true",
      "",
      "[Install]",
      "WantedBy=default.target",
      "",
    ].join("\n");
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    let current = "";
    try {
      current = await readFile(path, "utf8");
    } catch {
      // Missing or unreadable unit is replaced atomically below.
    }
    if (current && !current.startsWith(desktopManagedMarker + "\n")) {
      throw new Error(
        `A different fd0 service already owns ${path}. Stop or remove it before enabling fd0 Desktop.`,
      );
    }
    if (current !== unit) {
      const staged = `${path}.new`;
      await writeFile(staged, unit, { mode: 0o600 });
      await rename(staged, path);
      await this.#systemctl(["daemon-reload"]);
      // Repair an old managed unit even if its previous launch hit the limit.
      // Unchanged units retain the limit across ordinary ensureRunning calls.
      if (current) await this.#systemctl(["reset-failed", linuxServiceName]);
    }
  }

  #linuxUnitPath(): string {
    return join(this.#home, ".config", "systemd", "user", linuxServiceName);
  }

  #linuxAutostartPath(): string {
    return join(this.#home, ".config", "autostart", "sh.fd0.desktop.desktop");
  }

  async #ownsLinuxUnit(): Promise<boolean> {
    try {
      return (await readFile(this.#linuxUnitPath(), "utf8"))
        .startsWith(desktopManagedMarker + "\n");
    } catch {
      return false;
    }
  }

  async #systemctl(args: string[], ignoreMissing = false): Promise<void> {
    try {
      await this.#run("systemctl", ["--user", ...args], { timeout: 15_000 });
    } catch (error) {
      if (ignoreMissing) return;
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`Could not manage the fd0 background service: ${detail}`);
    }
  }

  async #waitForLinuxActive(): Promise<void> {
    const deadline = Date.now() + this.#linuxReadyTimeoutMs;
    while (Date.now() < deadline) {
      try {
        const result = await this.#run(
          "systemctl",
          ["--user", "is-active", linuxServiceName],
          { timeout: 5_000 },
        );
        if (result.stdout.trim() === "active") return;
      } catch {
        // A freshly enabled unit can briefly be activating or restarting.
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    let detail = "inactive";
    try {
      const result = await this.#run(
        "systemctl",
        ["--user", "show", linuxServiceName, "--property=ActiveState,SubState,Result", "--no-pager"],
        { timeout: 5_000 },
      );
      detail = result.stdout.trim().replaceAll("\n", ", ") || detail;
    } catch {
      // Keep the stable fallback; command errors may contain local paths.
    }
    throw new Error(`The fd0 background service did not become active (${detail})`);
  }

  async #waitForMacRegistration(): Promise<AgentServiceStatus> {
    const deadline = Date.now() + this.#macReadyTimeoutMs;
    do {
      const status = app.getLoginItemSettings({
        type: "agentService",
        serviceName: macServiceName,
      }).status;
      if (status === "enabled") return "enabled";
      if (status === "requires-approval") return "requires-approval";
      if (Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
    } while (Date.now() < deadline);
    return "not-registered";
  }

  async #waitForMacRemoval(): Promise<void> {
    const deadline = Date.now() + this.#macReadyTimeoutMs;
    do {
      const status = app.getLoginItemSettings({
        type: "agentService",
        serviceName: macServiceName,
      }).status;
      if (status === "not-registered" || status === "not-found") return;
      if (Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
    } while (Date.now() < deadline);
    throw new Error("The fd0 background service did not stop");
  }
}

function approvalError(status: AgentServiceStatus): Error {
  if (status === "requires-approval") {
    return new Error("Allow fd0 in System Settings > General > Login Items, then try again");
  }
  return new Error("The fd0 background service could not be registered");
}

function systemdQuote(value: string): string {
  return `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function desktopExecQuote(value: string): string {
  return `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}
