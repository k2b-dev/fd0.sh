import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const desktop = resolve(import.meta.dir, "..");
const fixtures: string[] = [];

afterEach(() => {
  for (const dir of fixtures.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(failures: number, error = 'NSURLErrorDomain Code=-1005 "The network connection was lost."', status = 68) {
  const dir = mkdtempSync(join(tmpdir(), "fd0-notarization-"));
  fixtures.push(dir);
  const executable = (name: string, body: string) => {
    const path = join(dir, name);
    writeFileSync(path, `#!/usr/bin/env bash\nset -euo pipefail\n${body}\n`);
    chmodSync(path, 0o755);
  };
  // Every external Apple tool is stubbed: these tests never contact Apple.
  executable("codesign", 'exit "${TEST_CODESIGN_STATUS:-0}"');
  executable("ditto", "exit 0");
  executable("sleep", 'printf "%s\\n" "$1" >> "$TEST_DIR/delays"');
  executable("xcrun", `
case "$1 $2" in
  "--find notarytool") exit 0 ;;
  "notarytool submit")
    printf 'submit\\n' >> "$TEST_DIR/submissions"
    printf '{"id":"test-submission","status":"%s"}\\n' "$TEST_NOTARY_STATUS"
    exit 0 ;;
  "notarytool log") printf 'test notarization rejection\\n'; exit 0 ;;
  "stapler staple"|"stapler validate")
    count=0
    if [[ -f "$TEST_DIR/attempts" ]]; then count=$(cat "$TEST_DIR/attempts"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$TEST_DIR/attempts"
    if [[ "$count" -le "$TEST_FAILURES" ]]; then
      printf '%s\\n' "$TEST_ERROR" >&2
      exit "$TEST_STATUS"
    fi
    printf 'ticket verified\\n'
    exit 0 ;;
  *) exit 99 ;;
esac`);
  return {
    dir,
    env: {
      ...process.env,
      PATH: `${dir}:${process.env.PATH}`,
      DEBUG: "",
      TEST_DIR: dir,
      TEST_FAILURES: String(failures),
      TEST_ERROR: error,
      TEST_STATUS: String(status),
      TEST_NOTARY_STATUS: "Accepted",
      TEST_CODESIGN_STATUS: "0",
    },
    attempts: () => Number(readFileSync(join(dir, "attempts"), "utf8")),
  };
}

async function runValidation(f: ReturnType<typeof fixture>) {
  const child = Bun.spawn(["bash", "scripts/validate-notarization.sh", join(f.dir, "fd0 test.app")], {
    cwd: desktop, env: f.env, stdout: "pipe", stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
}

describe("release ticket validation", () => {
  test("succeeds on the first valid ticket", async () => {
    const f = fixture(0);
    expect((await runValidation(f)).status).toBe(0);
    expect(f.attempts()).toBe(1);
  });

  test.each([-1005, -1001])("recovers from transport error %s on the fourth attempt", async (code) => {
    const f = fixture(3, `NSURLErrorDomain Code=${code} "transport failure"`);
    const result = await runValidation(f);
    expect(result.status).toBe(0);
    expect(f.attempts()).toBe(4);
    expect(readFileSync(join(f.dir, "delays"), "utf8")).toBe("10\n20\n40\n");
    expect(result.stderr).toContain("retrying validation (4/4)");
  });

  test("fails after four persistent transport failures", async () => {
    const f = fixture(99);
    expect((await runValidation(f)).status).toBe(68);
    expect(f.attempts()).toBe(4);
  });

  test.each([
    [68, "CloudKit ticket is invalid"],
    [65, "No ticket found"],
    [1, "NSURLErrorDomain Code=-1005"],
  ])("fails immediately on non-retryable error %s", async (status, error) => {
    const f = fixture(99, error, status);
    expect((await runValidation(f)).status).toBe(status);
    expect(f.attempts()).toBe(1);
  });
});

describe("electron-builder notarization dependency", () => {
  // Exercise the installed package through Node, as electron-builder does.
  const source = `
    import { notarize } from '@electron/notarize';
    await notarize({ appPath: process.env.TEST_DIR + '/fd0 test.app', keychainProfile: 'test-only' });
  `;

  async function runNotarization(f: ReturnType<typeof fixture>) {
    const child = Bun.spawn(["node", "--input-type=module", "-e", source], {
      cwd: desktop, env: f.env, stdout: "ignore", stderr: "pipe",
    });
    const [status, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
    return { status, stderr };
  }

  test("recovers on the fourth staple attempt without resubmitting", async () => {
    const f = fixture(3);
    expect((await runNotarization(f)).status).toBe(0);
    expect(f.attempts()).toBe(4);
    expect(readFileSync(join(f.dir, "submissions"), "utf8")).toBe("submit\n");
  }, 15_000);

  test("fails after all staple retries without resubmitting", async () => {
    const f = fixture(99);
    const result = await runNotarization(f);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Failed to staple");
    expect(f.attempts()).toBe(4);
    expect(readFileSync(join(f.dir, "submissions"), "utf8")).toBe("submit\n");
  }, 15_000);

  test("rejects an Apple refusal before stapling", async () => {
    const f = fixture(0);
    const result = await runNotarization({ ...f, env: { ...f.env, TEST_NOTARY_STATUS: "Invalid" } });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Failed to notarize");
    expect(readFileSync(join(f.dir, "submissions"), "utf8")).toBe("submit\n");
    expect(() => f.attempts()).toThrow();
  });

  test("rejects an invalid signature before submitting", async () => {
    const f = fixture(0);
    const result = await runNotarization({ ...f, env: { ...f.env, TEST_CODESIGN_STATUS: "1" } });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Failed to codesign");
    expect(() => readFileSync(join(f.dir, "submissions"))).toThrow();
    expect(() => f.attempts()).toThrow();
  });
});
