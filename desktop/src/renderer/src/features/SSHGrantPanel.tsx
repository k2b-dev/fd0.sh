import { For, Show, createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import type { RecordRef, SSHGrantResult, SSHGrantView, UnlockInput, VaultStatus } from "../../../shared/contracts";
import { useVault } from "../lib/store";
import { toAppError } from "../lib/errors";
import { Button } from "../ui/Button";
import { AuthenticationForm } from "./AuthenticationForm";

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
  let alive = true;
  let revision = 0;
  onCleanup(() => { alive = false; revision++; });
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
  async function run(action: "prepare" | "revoke"): Promise<void> {
    setBusy(true); setError("");
    const ref = props.item;
    try {
      const result = await window.fd0.sshGrant({
        action, ...ref, id: grant()?.id,
      });
      if (!alive) return;
      if (action === "prepare") { setPreview(result); }
      else {
        setPreview(undefined);
        await refresh();
        if (alive) { vault.setStatus(await window.fd0.status()); vault.notify("SSH grant removed"); }
      }
    } catch (cause) { if (alive) { setError(grantError(cause)); } }
    finally { if (alive) setBusy(false); }
  }
  async function authorize(input: UnlockInput): Promise<void> {
    const reviewed = preview();
    if (!reviewed) throw new Error("Review the grant again before authorizing it");
    await window.fd0.sshGrant({ action: "create", ...props.item, digest: reviewed.digest, ...input });
    if (!alive) return;
    setPreview(undefined);
    await refresh();
    const status = await window.fd0.status();
    if (alive) { vault.setStatus(status); vault.notify("SSH grant enabled on this device"); }
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
    <Show when={preview()}>{(p) => <div>
      <For each={p().grants}>{(g) => <>
        <p><strong>{g.user}@{g.hostname}:{g.port || 22}</strong></p>
        <p>SSH key: <code>{g.fingerprint}</code></p>
        <For each={g.hostFingerprints}>{(fp) => <p>Server key: <code>{fp}</code></p>}</For>
        <Show when={g.jump}><p>Jump hosts: {g.jump}. Each required jump host needs its own grant.</p></Show>
      </>}</For>
      <p>Authenticate again to authorize this host and user. Requires host-bound OpenSSH authentication. Forwarded agents are not supported while locked.</p>
      <AuthenticationForm status={vault.status()} submitLabel="Authenticate and allow" pendingLabel="Authorizing…"
        onAuthenticate={authorize} onCancel={() => setPreview(undefined)} />
    </div>}</Show>
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
    <details class="auth-ssh-grants" open={Boolean(error()) || undefined}>
      <summary>{props.status?.sshGrantCount} active SSH {(props.status?.sshGrantCount ?? 0) === 1 ? "grant" : "grants"}</summary>
      <div class="auth-ssh-grants-content">
        <p>These hosts remain accessible while fd0 is locked.</p>
        <For each={grants()}>{(g) => <Button disabled={busy()} onClick={() => void window.fd0.openSSHHost({ scopeId: g.scopeId, name: `host:${g.name}` }).catch((cause) => { if (alive) setError(grantError(cause)); })}>Open SSH: {g.name}</Button>}</For>
        <Button disabled={busy()} onClick={() => void lockAll()}>Lock everything</Button>
        <p>Stops new SSH authentication until the next unlock. Existing connections stay open.</p>
        <Show when={error()}><p role="alert">{error()}</p></Show>
      </div>
    </details>
  </Show>;
}
