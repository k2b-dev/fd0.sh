import { describe, expect, test } from "bun:test";

import { pcscRuntimeEnvironment } from "../src/main/pcsc-runtime";

describe("PC/SC runtime", () => {
  test("uses the host library when the system provides one", () => {
    for (const library of [
      "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
      "/usr/lib64/libpcsclite.so.1",
      "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1",
    ]) {
      expect(pcscRuntimeEnvironment("/opt/fd0/resources", (path) => path === library)).toEqual({});
    }
  });

  test("falls back to the bundled library only without a host library", () => {
    expect(pcscRuntimeEnvironment("/opt/fd0/resources", () => false)).toEqual({
      LD_LIBRARY_PATH: "/opt/fd0/resources/runtime",
    });
  });
});
