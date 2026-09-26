import { Show, type JSX } from "solid-js";
import { IconLock } from "@tabler/icons-solidjs";
import type { VaultStatus } from "../../../shared/contracts";
import { ActiveSSHGrants } from "./SSHGrantPanel";
import { AuthenticationForm } from "./AuthenticationForm";

export function Unlock(props: {
  status: VaultStatus | null;
  onUnlock(status: VaultStatus): void;
}): JSX.Element {
  return (
    <div class="auth-shell">
      {/* Empty on purpose: it exists only as a drag region. A wordmark here
          sits underneath the macOS traffic lights, and the screen already says
          what app this is. */}
      <header class="auth-titlebar" aria-hidden="true" />
      <main class="auth-main">
        <div class="auth-card">
          <div class="unlock-glyph" aria-hidden="true">
            <IconLock size={26} />
          </div>
          <h1>Unlock fd0</h1>
          <p>Your vault stays encrypted until you unlock it on this device.</p>
          <AuthenticationForm status={props.status} submitLabel="Unlock" pendingLabel="Unlocking…"
            onAuthenticate={async (input) => props.onUnlock(await window.fd0.unlock(input))} />
          <Show when={window.fd0.development}>
            <p class="auth-footnote">
              Development vault <code>fd0-desktop-dev</code>
            </p>
          </Show>
          <ActiveSSHGrants status={props.status} onStatus={props.onUnlock} />
        </div>
      </main>
    </div>
  );
}
