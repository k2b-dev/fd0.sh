import { beforeEach, expect, mock, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

type MacServiceStatus = "not-registered" | "enabled" | "requires-approval" | "not-found";
let readMacStatus: () => MacServiceStatus = () => "not-registered";
let changeMacService: (enabled: boolean) => void = () => undefined;

mock.module("electron", () => ({
  app: {
    isPackaged: false,
    getLoginItemSettings: () => ({ openAtLogin: false, status: readMacStatus() }),
    setLoginItemSettings: (settings: { openAtLogin?: boolean }) => changeMacService(Boolean(settings.openAtLogin)),
  },
}));

const { AgentLifecycle } = await import("../src/main/agent-lifecycle");

beforeEach(() => {
  readMacStatus = () => "not-registered";
  changeMacService = () => undefined;
});

test("macOS agent service keeps interactive crypto responsive", async () => {
  const plist = await readFile(
    join(import.meta.dir, "../resources/sh.fd0.desktop.agent.plist"),
    "utf8",
  );
  expect(plist).toContain("<string>Standard</string>");
  expect(plist).not.toContain("<string>Background</string>");
});

test("AgentLifecycle waits for delayed macOS service registration", async () => {
  let enabled = false;
  let readsAfterEnable = 0;
  changeMacService = (next) => {
    enabled = next;
  };
  readMacStatus = () => {
    if (!enabled) return "not-registered";
    readsAfterEnable += 1;
    return readsAfterEnable < 2 ? "not-registered" : "enabled";
  };
  const lifecycle = new AgentLifecycle({
    platform: "darwin",
    packaged: true,
    macReadyTimeoutMs: 250,
  });

  expect(await lifecycle.ensureRunning()).toBe("enabled");
  expect(readsAfterEnable).toBe(2);
});

test("AgentLifecycle reports when macOS requires approval", async () => {
  let status: MacServiceStatus = "not-registered";
  changeMacService = (enabled) => {
    if (enabled) status = "requires-approval";
  };
  readMacStatus = () => status;
  const lifecycle = new AgentLifecycle({ platform: "darwin", packaged: true });

  expect(await lifecycle.ensureRunning()).toBe("requires-approval");
});

test("AgentLifecycle waits for macOS removal before registering a restart", async () => {
  let status: MacServiceStatus = "enabled";
  let removalReads = 0;
  const changes: boolean[] = [];
  changeMacService = (enabled) => {
    changes.push(enabled);
    if (enabled) status = "enabled";
    else removalReads = 0;
  };
  readMacStatus = () => {
    if (changes.at(-1) === false) {
      removalReads += 1;
      status = removalReads < 2 ? "enabled" : "not-registered";
    }
    return status;
  };
  const lifecycle = new AgentLifecycle({
    platform: "darwin",
    packaged: true,
    macReadyTimeoutMs: 250,
  });

  await lifecycle.restart();
  expect(changes).toEqual([false, true]);
  expect(removalReads).toBeGreaterThanOrEqual(2);
});

test("AgentLifecycle installs and starts an isolated systemd user service", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-lifecycle-"));
  const calls: string[][] = [];
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0 app/fd0-desktop",
    home,
    run: async (_file, args) => {
      calls.push(args as string[]);
      return { stdout: (args as string[]).includes("is-active") ? "active\n" : "", stderr: "" };
    },
  });

  expect(await lifecycle.ensureRunning()).toBe("enabled");
  const unit = await readFile(
    join(home, ".config", "systemd", "user", "fd0-agent.service"),
    "utf8",
  );
  expect(unit).toContain('ExecStart="/opt/fd0 app/fd0-desktop" --fd0-agent-relay');
  expect(unit).toContain("Restart=on-failure");
  expect(unit).toContain("StartLimitIntervalSec=60s");
  expect(unit).toContain("StartLimitBurst=5");
  expect(unit).toContain("NoNewPrivileges=true");
  expect(calls).toEqual([
    ["--user", "daemon-reload"],
    ["--user", "enable", "--now", "fd0-agent.service"],
    ["--user", "is-active", "fd0-agent.service"],
  ]);
});

test("AgentLifecycle upgrades a failed AppImage service without FUSE and preserves subsequent start limits", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-appimage-"));
  const directory = join(home, ".config", "systemd", "user");
  const unitPath = join(directory, "fd0-agent.service");
  await mkdir(directory, { recursive: true });
  await writeFile(unitPath, '# fd0-desktop-managed-v1\n[Service]\nExecStart="/home/test/fd0-desktop" --fd0-agent-relay\nNoNewPrivileges=true\n');
  const calls: string[][] = [];
  let rateLimited = true;
  const lifecycle = new AgentLifecycle({
    platform: "linux", packaged: true, appPath: "/home/test/fd0-desktop", home,
    run: async (_file, args) => {
      const values = args as string[];
      calls.push(values);
      if (values.includes("reset-failed")) rateLimited = false;
      if (values.includes("enable") || values.includes("restart")) {
        const unit = await readFile(unitPath, "utf8");
        if (!unit.includes("Environment=APPIMAGE_EXTRACT_AND_RUN=1")) throw new Error("AppImage cannot mount under NoNewPrivileges");
        if (rateLimited) throw new Error("start-limit-hit");
      }
      return { stdout: values.includes("is-active") ? "active\n" : "", stderr: "" };
    },
  });
  expect(await lifecycle.ensureRunning()).toBe("enabled");
  expect(calls.slice(0, 3)).toEqual([
    ["--user", "daemon-reload"],
    ["--user", "reset-failed", "fd0-agent.service"],
    ["--user", "enable", "--now", "fd0-agent.service"],
  ]);
  calls.length = 0;
  rateLimited = true;
  await expect(lifecycle.ensureRunning()).rejects.toThrow("start-limit-hit");
  expect(calls).toEqual([["--user", "enable", "--now", "fd0-agent.service"]]);
  calls.length = 0;
  await lifecycle.restart();
  expect(calls).toEqual([
    ["--user", "reset-failed", "fd0-agent.service"],
    ["--user", "restart", "fd0-agent.service"],
    ["--user", "is-active", "fd0-agent.service"],
  ]);
});

test("AgentLifecycle rejects a Linux service that exits during startup", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-failed-"));
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0",
    home,
    linuxReadyTimeoutMs: 25,
    run: async (_file, args) => {
      const values = args as string[];
      if (values.includes("is-active")) throw new Error("inactive");
      if (values.includes("show")) return { stdout: "ActiveState=failed\nSubState=failed\nResult=exit-code\n", stderr: "" };
      return { stdout: "", stderr: "" };
    },
  });

  await expect(lifecycle.ensureRunning()).rejects.toThrow("ActiveState=failed, SubState=failed, Result=exit-code");
});

test("AgentLifecycle waits for a Linux service that is still activating", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-activating-"));
  let probes = 0;
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0",
    home,
    run: async (_file, args) => {
      if ((args as string[]).includes("is-active")) {
        probes += 1;
        return { stdout: probes === 1 ? "activating\n" : "active\n", stderr: "" };
      }
      return { stdout: "", stderr: "" };
    },
  });

  expect(await lifecycle.ensureRunning()).toBe("enabled");
  expect(probes).toBe(2);
});

test("AgentLifecycle explains an unavailable systemd user session", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-no-systemd-"));
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0",
    home,
    run: async () => {
      throw new Error("Failed to connect to bus");
    },
  });

  await expect(lifecycle.ensureRunning()).rejects.toThrow(
    "Could not manage the fd0 background service: Failed to connect to bus",
  );
});

test("AgentLifecycle keeps GUI login separate from the agent service", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-gui-login-"));
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/home/test/fd0%desktop",
    home,
    run: async () => ({ stdout: "", stderr: "" }),
  });

  expect(await lifecycle.guiLaunchesAtLogin()).toBe(false);
  expect(await lifecycle.setGuiLaunchAtLogin(true)).toBe(true);
  const entry = await readFile(
    join(home, ".config", "autostart", "sh.fd0.desktop.desktop"),
    "utf8",
  );
  expect(entry).toContain('Exec="/home/test/fd0%%desktop"');
  expect(await lifecycle.setGuiLaunchAtLogin(false)).toBe(false);
  expect(await lifecycle.guiLaunchesAtLogin()).toBe(false);
});

test("AgentLifecycle refuses to replace a foreign systemd unit", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-foreign-"));
  const unitPath = join(home, ".config", "systemd", "user", "fd0-agent.service");
  await mkdir(join(home, ".config", "systemd", "user"), { recursive: true });
  await writeFile(unitPath, "[Service]\nExecStart=/usr/local/bin/fd0-agent\n");
  const calls: string[][] = [];
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0",
    home,
    run: async (_file, args) => {
      calls.push(args as string[]);
      return { stdout: "", stderr: "" };
    },
  });

  await expect(lifecycle.ensureRunning()).rejects.toThrow("different fd0 service");
  await lifecycle.stop();
  await lifecycle.uninstall();
  expect(calls).toEqual([]);
  expect(await readFile(unitPath, "utf8")).toContain("/usr/local/bin/fd0-agent");
});
