import { existsSync } from "node:fs";
import { join } from "node:path";

// Locations where distributions install the PC/SC client library.
const hostPCSCLibraries = [
  "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
  "/lib/x86_64-linux-gnu/libpcsclite.so.1",
  "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1",
  "/lib/aarch64-linux-gnu/libpcsclite.so.1",
  "/usr/lib64/libpcsclite.so.1",
  "/usr/lib/libpcsclite.so.1",
];

/**
 * The bundled libpcsclite only helps hosts without PC/SC. A host library must
 * win: the client protocol has to match the host's pcscd, so a bundled copy
 * from the build machine breaks YubiKey unlock on newer or older systems.
 */
export function pcscRuntimeEnvironment(
  resourcesPath: string,
  exists: (path: string) => boolean = existsSync,
): { LD_LIBRARY_PATH?: string } {
  if (hostPCSCLibraries.some((path) => exists(path))) return {};
  return { LD_LIBRARY_PATH: join(resourcesPath, "runtime") };
}
