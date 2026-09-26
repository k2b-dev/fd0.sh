import { For, Show, createEffect, createMemo, createSignal, onMount, onCleanup, type JSX } from "solid-js";
import { IconDeviceUsb, IconKey } from "@tabler/icons-solidjs";
import type { UnlockInput, VaultStatus } from "../../../shared/contracts";
import { toAppError, type AppError } from "../lib/errors";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput } from "../ui/Fields";

// One credential form for unlock and fresh operation authorization. The caller
// chooses the operation; this component never reuses an unlocked session.
export function AuthenticationForm(props: {
  status: VaultStatus | null;
  submitLabel: string;
  pendingLabel: string;
  onAuthenticate(input: UnlockInput): Promise<void>;
  onCancel?(): void;
}): JSX.Element {
  const [passphrase, setPassphrase] = createSignal("");
  const [pin, setPIN] = createSignal("");
  const [methodID, setMethodID] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<AppError | null>(null);
  let alive = true;
  onCleanup(() => { alive = false; setPassphrase(""); setPIN(""); });
  // Both branches of the form reuse this ref — only one input is ever mounted.
  let input: HTMLInputElement | undefined;

  const methods = createMemo(() => props.status?.authMethods ?? []);
  const selectedMethod = createMemo(() => methods().find((method) => method.id === methodID()) ?? methods()[0]);
  const isPassphrase = (): boolean => selectedMethod()?.type === "passphrase";
  const isYubiKey = (): boolean => selectedMethod()?.type === "yubikey";
  const yubikeySupported = (): boolean => Boolean(props.status?.yubikey);

  createEffect(() => {
    const available = methods();
    if (available.length === 0) {
      setPassphrase(""); setPIN(""); setMethodID("");
      return;
    }
    if (available.some((method) => method.id === methodID())) return;
    setPassphrase(""); setPIN("");
    setMethodID(available.find((method) => method.default)?.id ?? available[0]!.id);
  });

  onMount(() => input?.focus());

  const submitDisabled = (): boolean =>
    busy() ||
    (isYubiKey() && selectedMethod()?.pinMode === "required" && pin().length < 6) ||
    (isYubiKey() && pin().length > 0 && (pin().length < 6 || pin().length > 8)) ||
    !selectedMethod() ||
    (isPassphrase() && !passphrase()) ||
    (isYubiKey() && !yubikeySupported());

  async function authenticate(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (submitDisabled()) return;
    const method = selectedMethod();
    if (!method || (method.type === "passphrase" && !passphrase())) return;
    setBusy(true);
    setError(null);
    try {
      await props.onAuthenticate({
        method: method.id,
        passphrase: method.type === "passphrase" ? passphrase() : "",
        pin: method.type === "yubikey" ? pin() : "",
      });
      if (alive) { setPassphrase(""); setPIN(""); }
    } catch (cause) {
      if (!alive) return;
      setPassphrase(""); setPIN("");
      setError(toAppError(cause, "Authentication failed"));
    } finally {
      if (alive) {
        setBusy(false);
        if (error()) queueMicrotask(() => { if (alive) input?.focus(); });
      }
    }
  }

  return (
    <form class="auth-form" onSubmit={(event) => void authenticate(event)}>
      <Show when={methods().length === 0}>
        <p class="callout callout-error" role="alert">Authentication methods are unavailable. Refresh fd0 and try again.</p>
      </Show>
      <Show when={methods().length > 1}>
        <div class="unlock-methods" role="radiogroup" aria-label="Authentication method">
          <For each={methods()}>
            {(method) => (
              <button
                classList={{ "is-active": selectedMethod()?.id === method.id }}
                type="button"
                disabled={busy()}
                role="radio"
                aria-checked={selectedMethod()?.id === method.id}
                onClick={() => {
                  setPassphrase(""); setPIN(""); setError(null);
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
                disabled={busy()}
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
                  disabled={busy()}
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
        {busy() ? (isYubiKey() ? "Waiting for YubiKey…" : props.pendingLabel) : props.submitLabel}
      </Button>
      <Show when={props.onCancel}><Button disabled={busy()} onClick={() => props.onCancel?.()}>Cancel</Button></Show>
    </form>
  );
}
