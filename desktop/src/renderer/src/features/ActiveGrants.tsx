import { For, Show, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { IconChevronLeft, IconLock, IconTerminal2 } from "@tabler/icons-solidjs";
import type { SSHGrantView, VaultStatus } from "../../../shared/contracts";
import { toAppError } from "../lib/errors";
import { Button } from "../ui/Button";

function grantError(cause: unknown): string {
  const error = toAppError(cause);
  return error.detail ? `${error.title} ${error.detail}` : error.technical ?? error.title;
}

export function activeGrantCount(status: VaultStatus | null): number {
  return status?.sshGrantCount ?? 0;
}

/** Lock-screen entry point to the grants that keep working while locked. */
export function ActiveGrantsPill(props: { count: number; onOpen(): void }): JSX.Element {
  return <button type="button" class="active-grants-pill" onClick={() => props.onOpen()}>
    {props.count} active {props.count === 1 ? "grant" : "grants"}
  </button>;
}

/** Full-window overview of active grants, shown instead of the unlock form. */
export function ActiveGrantsOverview(props: { onBack(): void; onStatus(status: VaultStatus): void }): JSX.Element {
  const [grants, setGrants] = createSignal<SSHGrantView[]>([]);
  const [selectedId, setSelectedId] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const selected = createMemo(() => grants().find((g) => g.id === selectedId()) ?? grants()[0]);
  let alive = true;
  let back: HTMLButtonElement | undefined;
  const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") props.onBack(); };
  onMount(() => {
    back?.focus();
    document.addEventListener("keydown", onKey);
    void window.fd0.sshGrant({ action: "list" })
      .then((r) => { if (alive) setGrants(r.grants.filter((g) => g.active)); })
      .catch((cause) => { if (alive) setError(grantError(cause)); })
      .finally(() => { if (alive) setLoading(false); });
  });
  onCleanup(() => { alive = false; document.removeEventListener("keydown", onKey); });
  async function lockAll(): Promise<void> {
    setBusy(true);
    try { const status = await window.fd0.lock(true); if (alive) props.onStatus(status); }
    catch (cause) { if (alive) setError(grantError(cause)); }
    finally { if (alive) setBusy(false); }
  }
  function openSSH(g: SSHGrantView): void {
    void window.fd0.openSSHHost({ scopeId: g.scopeId, name: `host:${g.name}` })
      .catch((cause) => { if (alive) setError(grantError(cause)); });
  }
  return <main class="active-grants" aria-labelledby="active-grants-title">
    <header class="active-grants-head">
      <Button ref={back} variant="quiet" onClick={() => props.onBack()}><IconChevronLeft size={16} aria-hidden="true" />Unlock</Button>
      <div class="active-grants-title">
        <h1 id="active-grants-title">Active while locked</h1>
        <p>These grants keep working on this device while fd0 is locked.</p>
      </div>
      <span class="active-grants-locked"><IconLock size={12} aria-hidden="true" />Vault locked</span>
    </header>
    <div class="active-grants-split">
      <div class="active-grants-list">
        <Show when={!loading()} fallback={<p role="status" class="active-grants-muted">Loading grants…</p>}>
          <Show when={grants().length > 0} fallback={<Show when={!error()}><p class="active-grants-muted">No grants are active.</p></Show>}>
            <h2 class="active-grants-group">SSH hosts <span>{grants().length}</span></h2>
            <ul role="listbox" aria-label="SSH hosts">
              <For each={grants()}>{(g) => <li role="option" tabindex="0" aria-selected={selected()?.id === g.id}
                class="active-grants-row" classList={{ "is-selected": selected()?.id === g.id }}
                onClick={() => setSelectedId(g.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelectedId(g.id); } }}>
                <span class="active-grants-icon" aria-hidden="true"><IconTerminal2 size={16} /></span>
                <span class="active-grants-row-text"><strong>{g.name}</strong><small>{g.user}@{g.hostname}:{g.port || 22}</small></span>
              </li>}</For>
            </ul>
          </Show>
        </Show>
      </div>
      <div class="active-grants-detail">
        <Show when={selected()}>{(g) => <>
          <div class="active-grants-detail-head">
            <span class="active-grants-icon is-large" aria-hidden="true"><IconTerminal2 size={20} /></span>
            <div><h2>{g().name}</h2><p>SSH host grant on this device</p></div>
          </div>
          <dl class="active-grants-facts">
            <dt>Connects as</dt><dd><code>{g().user}@{g().hostname}:{g().port || 22}</code></dd>
            <Show when={g().jump}><dt>Jump hosts</dt><dd>{g().jump} <span class="active-grants-muted">· each needs its own grant</span></dd></Show>
            <dt>SSH key</dt><dd><code>{g().fingerprint}</code></dd>
            <For each={g().hostFingerprints}>{(fp) => <><dt>Server key</dt><dd><code>{fp}</code></dd></>}</For>
          </dl>
          <div class="active-grants-actions">
            <Button variant="primary" disabled={busy()} onClick={() => openSSH(g())}><IconTerminal2 size={16} aria-hidden="true" />Open SSH</Button>
          </div>
          <p class="active-grants-muted">To remove this grant, unlock fd0 and open the host.</p>
        </>}</Show>
        <Show when={error()}><p role="alert" class="active-grants-error">{error()}</p></Show>
      </div>
    </div>
    <footer class="active-grants-foot">
      <p>Locking everything stops all grants until the next unlock. Open SSH sessions stay connected.</p>
      <Button variant="danger" disabled={busy()} onClick={() => void lockAll()}>Lock everything</Button>
    </footer>
  </main>;
}
