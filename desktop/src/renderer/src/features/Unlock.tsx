import { Show, createEffect, createSignal, type JSX } from "solid-js";
import { IconLock } from "@tabler/icons-solidjs";
import type { VaultStatus } from "../../../shared/contracts";
import { ActiveGrantsOverview, ActiveGrantsPill, activeGrantCount } from "./ActiveGrants";
import { AuthenticationForm } from "./AuthenticationForm";

export function Unlock(props: {
  status: VaultStatus | null;
  onUnlock(status: VaultStatus): void;
}): JSX.Element {
  const [showGrants, setShowGrants] = createSignal(false);
  const grantCount = () => activeGrantCount(props.status);
  createEffect(() => { if (grantCount() === 0) setShowGrants(false); });
  function closeGrants(): void {
    setShowGrants(false);
    document.querySelector<HTMLButtonElement>(".active-grants-pill")?.focus();
  }
  return (
    <div class="auth-shell">
      {/* Empty on purpose: it exists only as a drag region. A wordmark here
          sits underneath the macOS traffic lights, and the screen already says
          what app this is. */}
      <header class="auth-titlebar" aria-hidden="true" />
      <Show when={!showGrants()} fallback={<ActiveGrantsOverview onBack={closeGrants} onStatus={props.onUnlock} />}>
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
            <Show when={grantCount() > 0}>
              <ActiveGrantsPill count={grantCount()} onOpen={() => setShowGrants(true)} />
            </Show>
          </div>
        </main>
      </Show>
    </div>
  );
}
