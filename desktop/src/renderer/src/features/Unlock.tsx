import { For, Show, createEffect, createMemo, createSignal, onMount, type JSX } from "solid-js";
import { IconDeviceUsb, IconKey, IconLock } from "@tabler/icons-solidjs";
import type { VaultStatus } from "../../../shared/contracts";
import { toAppError, type AppError } from "../lib/errors";
import { ActiveSSHGrants } from "./SSHGrantPanel";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput } from "../ui/Fields";

/**
 * The lock screen. One control matters here, so everything else stays quiet:
 * the method picker only appears when there is more than one method, and the
 * failure message never steals focus from the field being retyped.
 */
export function Unlock(props: {
  status: VaultStatus | null;
  onUnlock(status: VaultStatus): void;
}): JSX.Element {
  const [passphrase, setPassphrase] = createSignal("");
  const [pin, setPIN] = createSignal("");
  const [methodID, setMethodID] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<AppError | null>(null);
  // Both branches of the form reuse this ref — only one input is ever mounted.
  let input: HTMLInputElement | undefined;

  /**
   * `authMethods` is optional in VaultStatus and is passed straight through from
   * the local service. If it ever arrives empty the screen would render no
   * passphrase field and a permanently disabled button — a lockout with no way
   * out. Fall back to the passphrase method that every vault always has.
   */
  const methods = createMemo(() => {
    const reported = props.status?.authMethods ?? [];
    if (reported.length > 0) return reported;
    return [{ id: "passphrase", type: "passphrase", label: "Passphrase", default: true }];
  });
  const selectedMethod = createMemo(() => methods().find((method) => method.id === methodID()) ?? methods()[0]);
  const isPassphrase = (): boolean => selectedMethod()?.type === "passphrase";
  const isYubiKey = (): boolean => selectedMethod()?.type === "yubikey";
  const yubikeySupported = (): boolean => Boolean(props.status?.yubikey);

  createEffect(() => {
    const available = methods();
    if (available.length === 0 || available.some((method) => method.id === methodID())) return;
    setMethodID(available.find((method) => method.default)?.id ?? available[0]!.id);
  });

  onMount(() => input?.focus());

  const submitDisabled = (): boolean =>
    busy() ||
    !selectedMethod() ||
    (isPassphrase() && !passphrase()) ||
    (isYubiKey() && !yubikeySupported());

  async function unlock(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const method = selectedMethod();
    if (!method || (method.type === "passphrase" && !passphrase())) return;
    setBusy(true);
    setError(null);
    try {
      const result = await window.fd0.unlock({
        method: method.id,
        passphrase: method.type === "passphrase" ? passphrase() : "",
        pin: method.type === "yubikey" ? pin() : "",
      });
      setPassphrase("");
      setPIN("");
      props.onUnlock(result);
    } catch (cause) {
      setError(toAppError(cause, "That did not unlock the vault"));
      // Stay on the field so a typo can be corrected by typing over it.
      input?.focus();
      input?.select();
    } finally {
      setBusy(false);
    }
  }

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
          <ActiveSSHGrants status={props.status} onStatus={props.onUnlock} />
          <form class="auth-form" onSubmit={(event) => void unlock(event)}>
            <Show when={methods().length > 1}>
              <div class="unlock-methods" role="radiogroup" aria-label="Unlock method">
                <For each={methods()}>
                  {(method) => (
                    <button
                      classList={{ "is-active": selectedMethod()?.id === method.id }}
                      type="button"
                      role="radio"
                      aria-checked={selectedMethod()?.id === method.id}
                      onClick={() => {
                        setMethodID(method.id);
                        queueMicrotask(() => input?.focus());
                      }}
                    >
                      {method.type === "yubikey" ? <IconDeviceUsb size={17} /> : <IconKey size={17} />}
                      {method.label}
                    </button>
                  )}
                </For>
              </div>
            </Show>
            <div
              classList={{
                "field-stack": true,
                "unlock-method-content": methods().length > 1,
              }}
            >
              <Show when={isPassphrase()}>
                <Field label="Passphrase">
                  {(field) => (
                    <SecretInput
                      ref={input}
                      id={field.id}
                      aria-describedby={field.describedBy}
                      what="passphrase"
                      autocomplete="current-password"
                      value={passphrase()}
                      onInput={(event) => setPassphrase(event.currentTarget.value)}
                    />
                  )}
                </Field>
              </Show>
              <Show when={isYubiKey()}>
                <p class="callout">
                  <IconDeviceUsb size={18} aria-hidden="true" />
                  <span>Insert your YubiKey. fd0 will ask for touch when needed.</span>
                </p>
                <Show when={selectedMethod()?.pinMode !== "none"}>
                  <Field
                    label="YubiKey PIN"
                    hint={selectedMethod()?.pinMode === "optional" ? "Leave empty if your key has no PIN" : undefined}
                  >
                    {(field) => (
                      <Input
                        ref={input}
                        id={field.id}
                        aria-describedby={field.describedBy}
                        type="password"
                        inputmode="numeric"
                        autocomplete="off"
                        maxlength="8"
                        value={pin()}
                        onInput={(event) => setPIN(event.currentTarget.value)}
                      />
                    )}
                  </Field>
                </Show>
                <Show when={!yubikeySupported()}>
                  <p class="callout callout-warn">This installation of fd0 was built without YubiKey support.</p>
                </Show>
              </Show>
            </div>
            <Show when={error()}>
              {(current) => (
                <div class="callout callout-error" role="alert">
                  <strong>{current().title}</strong>
                  <Show when={current().detail}>
                    <p>{current().detail}</p>
                  </Show>
                  <Show when={current().technical}>
                    <details class="technical-details">
                      <summary>Technical details</summary>
                      <pre>{current().technical}</pre>
                    </details>
                  </Show>
                </div>
              )}
            </Show>
            <Button variant="primary" block type="submit" disabled={submitDisabled()}>
              {busy() ? (isYubiKey() ? "Waiting for YubiKey…" : "Unlocking…") : "Unlock"}
            </Button>
          </form>
          <Show when={window.fd0.development}>
            <p class="auth-footnote">
              Development vault <code>fd0-desktop-dev</code>
            </p>
          </Show>
        </div>
      </main>
    </div>
  );
}
