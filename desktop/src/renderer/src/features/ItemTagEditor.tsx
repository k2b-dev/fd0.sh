import { Show, createMemo, createSignal } from "solid-js";
import type { ItemSummary } from "../../../shared/contracts";
import { addTag, tagCatalog, caseSensitiveTags } from "../lib/tags";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { TagInput } from "./TagInput";

export function ItemTagEditor(props: { item: ItemSummary; onClose(): void }) {
  const vault = useVault();
  const original = [...(props.item.tags ?? [])];
  const ref = { scopeId: props.item.scopeId, name: props.item.recordName };
  const [tags, setTags] = createSignal([...original]);
  const [pending, setPending] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const options = createMemo(() => tagCatalog(vault.inventory().items, props.item.scopeId));
  const caseSensitive = () => caseSensitiveTags(props.item);
  const dirty = () => !!pending() || JSON.stringify(tags()) !== JSON.stringify(original);
  async function save() {
    if (busy()) return;
    setBusy(true); setError("");
    try {
      const next = addTag(tags(), pending(), options(), caseSensitive(), props.item.badge === "SSH HOST");
      await window.fd0.setItemTags(ref, next, original);
      await vault.refresh(ref);
      props.onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not save tags.");
    } finally { setBusy(false); }
  }
  return <Modal title={`Tags for ${props.item.title}`} size="small" dirty={dirty()}
    onClose={() => { if (!busy()) props.onClose(); }}
    footer={<><Button disabled={busy()} onClick={props.onClose}>Cancel</Button><Button variant="primary" disabled={busy()} onClick={() => void save()}>Save tags</Button></>}>
    <TagInput value={tags()} pending={pending()} options={options()} caseSensitive={caseSensitive()} rejectCommas={props.item.badge === "SSH HOST"} disabled={busy()} onChange={setTags} onPending={setPending} />
    <Show when={props.item.badge === "SSH HOST"}><p>Host tags distinguish uppercase and lowercase. Commas are not supported.</p></Show>
    <Show when={error()}><p role="alert">{error()}</p></Show>
  </Modal>;
}
