import { For, Show, createMemo, createResource, createSignal } from "solid-js";
import type { ItemSummary, OrganizationBatch, OrganizationBatchResult, OrganizationItem } from "../../../shared/contracts";
import { useVault } from "../lib/store";
import { addTag, tagCatalog } from "../lib/tags";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { TagInput } from "./TagInput";

/** Snapshot selection and preview: a later inventory refresh cannot change what is approved. */
export function OrganizeItems(props: { items: ItemSummary[]; onClose(): void }) {
 const vault = useVault();
 const candidates = [...props.items];
 const [inventory] = createResource(() => window.fd0.organizationInventory());
 const items = createMemo(() => (inventory() ?? []).filter(item => candidates.some(candidate => candidate.scopeId === item.scopeId && candidate.recordName === item.name)));
 const key = (item: OrganizationItem) => `${item.scopeId}/${item.id}`;
 const [selected, setSelected] = createSignal<string[]>([]);
 const [operation, setOperation] = createSignal<OrganizationBatch["operation"]>("add");
 const [target, setTarget] = createSignal("");
 const [tags, setTags] = createSignal<string[]>([]);
 const [pending, setPending] = createSignal("");
 const [busy, setBusy] = createSignal(false);
 const [resuming, setResuming] = createSignal(false);
 const [error, setError] = createSignal("");
 const [preview, setPreview] = createSignal<{ request: OrganizationBatch; result: OrganizationBatchResult }>();
 const chosen = createMemo(() => items().filter(item => selected().includes(key(item))));
 const options = createMemo(() => {
  const scopes = new Set(chosen().map(item => item.scopeId));
  return tagCatalog(vault.inventory().items.filter(item => scopes.has(item.scopeId)));
 });
 const infrastructure = () => chosen().some(item => ["ssh", "kube", "talos"].includes(item.kind));
 const hosts = () => chosen().some(item => item.kind === "ssh");
 async function review() {
  setBusy(true); setError("");
  try {
   const request: OrganizationBatch = { items: chosen(), operation: operation(), targetScopeId: target(), tags: addTag(tags(), pending(), options(), infrastructure(), hosts()), dryRun: true };
   const result = await window.fd0.organizeItems(request);
   setResuming(false); setPreview({ request: { ...request, scopes: result.scopes }, result });
  } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not review these changes."); }
  finally { setBusy(false); }
 }
 async function apply() {
  const reviewed = preview(); if (!reviewed || busy()) return;
  setBusy(true); setError("");
  try {
   await window.fd0.organizeItems({ ...reviewed.request, dryRun: false, resume: resuming() });
   await vault.refresh(); vault.notify(`Organized ${reviewed.request.items.length} items`); props.onClose();
  } catch (cause) {
   setError(`${cause instanceof Error ? cause.message : "Could not finish these changes."} Some changes may already be saved. A pending move can be resumed; changed items require a fresh selection and review.`);
   if (reviewed.request.operation === "move") setResuming(true); else setPreview(undefined);
   await vault.refresh();
  } finally { setBusy(false); }
 }
 return <Modal title="Organize items" size="wide" onClose={() => { if (!busy()) props.onClose(); }}
  footer={<><Button disabled={busy()} onClick={props.onClose}>Cancel</Button><Show when={preview()} fallback={<Button variant="primary" disabled={busy() || !chosen().length || chosen().length > 100} onClick={() => void review()}>Review changes</Button>}><Button disabled={busy()} onClick={() => setPreview(undefined)}>Back</Button><Button variant="primary" disabled={busy()} onClick={() => void apply()}>{resuming() ? "Resume move" : "Apply reviewed changes"}</Button></Show></>}>
  <Show when={inventory.loading}><p>Loading item metadata…</p></Show>
  <Show when={inventory.error}><p role="alert">Could not load item metadata. Close and try again.</p></Show>
  <Show when={error()}><p role="alert">{error()}</p></Show>
  <Show when={preview()} fallback={<div class="field-stack">
   <p>Select up to 100 items from the current list. Values stay unchanged.</p>
   <Button disabled={busy() || !items().length} onClick={() => setSelected(items().slice(0, 100).map(key))}>Select first {Math.min(items().length, 100)}</Button>
   <div class="organization-selection"><For each={items()}>{item => <label class="tag-filter-option"><input type="checkbox" checked={selected().includes(key(item))} disabled={busy()} onChange={event => setSelected(event.currentTarget.checked ? [...selected(), key(item)] : selected().filter(id => id !== key(item)))} /><span>{item.title || item.name}</span><small>{item.kind} · {item.scope}</small></label>}</For></div>
   <label class="field">Action<select class="input" disabled={busy()} value={operation()} onChange={event => {
    const value = event.currentTarget.value;
    if (value === "add" || value === "remove" || value === "set" || value === "clear" || value === "move") setOperation(value);
   }}><option value="add">Add tags</option><option value="remove">Remove tags</option><option value="set">Replace all tags</option><option value="clear">Clear tags</option><option value="move">Move to another vault</option></select></label>
   <Show when={operation() !== "move" && operation() !== "clear"}><TagInput value={tags()} pending={pending()} options={options()} caseSensitive={infrastructure()} rejectCommas={hosts()} disabled={busy()} onChange={setTags} onPending={setPending} /></Show>
   <Show when={hosts() && operation() !== "move"}><p>Host tags distinguish uppercase and lowercase; other items ignore case. Host tags cannot contain commas.</p></Show>
   <Show when={operation() === "move"}><label class="field">Destination vault<select class="input" disabled={busy()} value={target()} onChange={event => setTarget(event.currentTarget.value)}><option value="">Choose vault…</option><For each={vault.inventory().scopes}>{scope => <option value={scope.id}>{scope.label}</option>}</For></select></label><p>Members of the destination vault will gain access. fd0 verifies the destination before archiving the source. Include linked hosts and keys together.</p></Show>
  </div>}>{reviewed => <div class="field-stack"><For each={reviewed().result.scopes}>{scope => <p>{scope.label} · {scope.members} vault members</p>}</For><p>{reviewed().request.operation === "move" ? "Move these items and archive their source copies after verification. Destination vault members gain access." : "Apply these resulting tags to the selected items."}</p><For each={reviewed().result.items}>{item => <div><strong>{item.title || item.name}</strong><p>{item.scope} · {(item.tags ?? []).join(", ") || "No tags"}</p></div>}</For><p>Changes are checked again before applying. A changed item stops the batch.</p></div>}</Show>
 </Modal>;
}
