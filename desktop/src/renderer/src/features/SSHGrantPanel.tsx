import { For, Show, createEffect, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
import type { RecordRef, SSHGrantResult, SSHGrantView, VaultStatus } from "../../../shared/contracts";
import { useVault } from "../lib/store";
import { toAppError } from "../lib/errors";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput, Select } from "../ui/Fields";

function grantError(cause: unknown): string {
  const error = toAppError(cause);
  return error.detail ? `${error.title} ${error.detail}` : error.technical ?? error.title;
}

export function SSHGrantPanel(props: { item: RecordRef }): JSX.Element {
  const vault = useVault();
  const [grant, setGrant] = createSignal<SSHGrantView>();
  const [preview, setPreview] = createSignal<SSHGrantResult>();
  const [busy, setBusy] = createSignal(false);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal("");
  const [credential, setCredential] = createSignal("");
  const [method, setMethod] = createSignal("");
  const methods = () => vault.status()?.authMethods ?? [];
  const selected = createMemo(() => methods().find((m) => m.id === method()) ?? methods().find((m) => m.default) ?? methods()[0]);
  let alive = true;
  let revision = 0;
  onCleanup(() => { alive = false; revision++; setCredential(""); });
  async function refresh(): Promise<void> {
    const current = ++revision;
    const ref = props.item;
    setLoading(true);
    try {
      const result = await window.fd0.sshGrant({ action: "list" });
      if (alive && current === revision) setGrant(result.grants.find((g) => g.scopeId === ref.scopeId && `host:${g.name}` === ref.name));
    } catch (cause) { if (alive && current === revision) setError(grantError(cause)); }
    finally { if (alive && current === revision) setLoading(false); }
  }
  createEffect(() => { props.item.scopeId; props.item.name; void refresh(); });
  async function run(action: "prepare" | "create" | "revoke"): Promise<void> {
    setBusy(true); setError("");
    const ref = props.item;
    try {
      const result = await window.fd0.sshGrant({
        action, ...ref, id: grant()?.id, digest: preview()?.digest, method: selected()?.id,
        passphrase: action === "create" && selected()?.type === "passphrase" ? credential() : "",
        pin: action === "create" && selected()?.type === "yubikey" ? credential() : "",
      });
      if (!alive) return;
      if (action === "prepare") { setCredential(""); setPreview(result); }
      else {
        setPreview(undefined); setCredential("");
        await refresh();
        if (alive) { vault.setStatus(await window.fd0.status()); vault.notify(action === "create" ? "SSH grant enabled on this device" : "SSH grant removed"); }
      }
    } catch (cause) { if (alive) { setError(grantError(cause)); if (action === "create") setCredential(""); } }
    finally { if (alive) setBusy(false); }
  }
  return <section class="field-section ssh-grant-panel" aria-label="SSH access while locked">
    <h2 class="section-heading">SSH while locked</h2>
    <p>Keep this host available on this device after locking fd0. After a service or computer restart, unlock once to activate saved grants.</p>
    <Show when={!loading()} fallback={<p role="status">Loading SSH grant…</p>}>
      <Show when={grant()} fallback={<Button disabled={busy() || !!preview()} onClick={() => void run("prepare")}>Allow SSH while locked…</Button>}>
        {(g) => <>
          <p role="status">{g().active ? "Enabled and active on this device" : "Saved, currently inactive. Unlock again; changed hosts or keys require a new grant."}</p>
          <Button disabled={busy()} onClick={() => void run("revoke")}>Remove grant</Button>
        </>}
      </Show>
    </Show>
    <Show when={preview()}>{(p) => <form class="auth-form" onSubmit={(event) => { event.preventDefault(); void run("create"); }}>
      <For each={p().grants}>{(g) => <>
        <p><strong>{g.user}@{g.hostname}:{g.port || 22}</strong></p>
        <p>SSH key: <code>{g.fingerprint}</code></p>
        <For each={g.hostFingerprints}>{(fp) => <p>Server key: <code>{fp}</code></p>}</For>
        <Show when={g.jump}><p>Jump hosts: {g.jump}. Each required jump host needs its own grant.</p></Show>
      </>}</For>
      <p>Authenticate again to authorize this host and user. Requires host-bound OpenSSH authentication. Forwarded agents are not supported while locked.</p>
      <Show when={methods().length > 1}>
        <Field label="Authentication method">{(field) => <Select id={field.id} value={selected()?.id ?? ""} disabled={busy()} options={methods().map((m) => ({ value: m.id, label: m.label }))} onChange={(value) => { setMethod(value); setCredential(""); }} />}</Field>
      </Show>
      <Show when={selected()?.type === "passphrase"}>
        <Field label="Passphrase">{(field) => <SecretInput id={field.id} what="passphrase" autocomplete="current-password" value={credential()} onInput={(e) => setCredential(e.currentTarget.value)} disabled={busy()} />}</Field>
      </Show>
      <Show when={selected()?.type === "yubikey"}>
        <p>Insert your YubiKey and touch it when requested.</p>
        <Show when={selected()?.pinMode !== "none"}>
          <Field label="YubiKey PIN">{(field) => <Input id={field.id} type="password" autocomplete="off" value={credential()} onInput={(e) => setCredential(e.currentTarget.value)} disabled={busy()} />}</Field>
        </Show>
      </Show>
      <Button type="submit" variant="primary" disabled={busy() || !selected() || (selected()?.type === "passphrase" && !credential()) || (selected()?.type === "yubikey" && !vault.status()?.yubikey)}>{busy() ? "Authorizing…" : "Authenticate and allow"}</Button>
      <Button disabled={busy()} onClick={() => { setPreview(undefined); setCredential(""); }}>Cancel</Button>
    </form>}</Show>
    <Show when={error()}><p role="alert">{error()}</p></Show>
  </section>;
}

export function ActiveSSHGrants(props: { status: VaultStatus | null; onStatus(status: VaultStatus): void }): JSX.Element {
  const [grants, setGrants] = createSignal<SSHGrantView[]>([]);
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  let alive = true;
  let revision = 0;
  onCleanup(() => { alive = false; revision++; });
  createEffect(() => {
    const current = ++revision;
    const count = props.status?.sshGrantCount ?? 0;
    if (!count) { setGrants([]); return; }
    void window.fd0.sshGrant({ action: "list" }).then((r) => { if (alive && current === revision) setGrants(r.grants.filter((g) => g.active)); }).catch((cause) => { if (alive) setError(grantError(cause)); });
  });
  async function lockAll(): Promise<void> {
    setBusy(true);
    try { const status = await window.fd0.lock(true); if (alive) { setGrants([]); props.onStatus(status); } }
    catch (cause) { if (alive) setError(grantError(cause)); }
    finally { if (alive) setBusy(false); }
  }
  return <Show when={(props.status?.sshGrantCount ?? 0) > 0}>
    <section class="field-section" aria-label="Active SSH grants">
      <h2 class="section-heading">{props.status?.sshGrantCount} SSH {(props.status?.sshGrantCount ?? 0) === 1 ? "grant remains" : "grants remain"} active</h2>
      <For each={grants()}>{(g) => <Button disabled={busy()} onClick={() => void window.fd0.openSSHHost({ scopeId: g.scopeId, name: `host:${g.name}` }).catch((cause) => { if (alive) setError(grantError(cause)); })}>Open SSH: {g.name}</Button>}</For>
      <Button disabled={busy()} onClick={() => void lockAll()}>Lock everything</Button>
      <p>Stops new SSH authentication until the next unlock. Existing connections stay open.</p>
      <Show when={error()}><p role="alert">{error()}</p></Show>
    </section>
  </Show>;
}
