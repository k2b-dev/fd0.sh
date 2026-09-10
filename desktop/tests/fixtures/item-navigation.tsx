import { Show, createEffect, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { ItemList } from "../../src/renderer/src/features/ItemList";
import { DetailNavigation } from "../../src/renderer/src/features/DetailNavigation";
import { CommandPalette } from "../../src/renderer/src/features/CommandPalette";
import { ItemDetail } from "../../src/renderer/src/features/ItemDetail";
import { createVaultStore, VaultContext } from "../../src/renderer/src/lib/store";
import type { Inventory, ItemSummary, OrganizationBatch, OrganizationItem } from "../../src/shared/contracts";
import "../../src/renderer/src/styles.css";

const item = (id: string, scopeId: string, tags: string[]): ItemSummary => ({ id, scopeId, recordName: `pass:${id}`, title: id, kind: "password", vault: scopeId, badge: "PASSWORD", tags });
const inventory: Inventory = {
  scopes: [{ id: "work", label: "Work vault" }, { id: "private", label: "Private vault" }],
  items: [
    { ...item("Login", "work", ["Team"]), favorite: true },
    { ...item("API token", "private", []), kind: "secret", badge: "SECRET" },
    { ...item("Host", "work", []), kind: "ssh", badge: "SSH HOST" },
    { ...item("Key", "work", []), recordName: "ssh:deploy", kind: "ssh", badge: "SSH KEY" },
  ],
  counts: { password: 1, secret: 1, ssh: 2 },
};
const batchCalls: OrganizationBatch[] = [];
const organizationItems = (): OrganizationItem[] => inventory.items.map(item => ({ id:item.id, scopeId:item.scopeId, scope:item.vault, name:item.recordName, title:item.title, kind:item.badge === "SSH HOST" ? "ssh" : item.badge === "SSH KEY" ? "key" : item.kind === "password" ? "pass" : item.kind, tags:item.tags ?? [], revision:"fixture:1" }));
Object.defineProperty(window, "fd0", { value: {
  development: true,
  organizationInventory: async () => organizationItems(),
  organizeItems: async (request: OrganizationBatch) => {
   batchCalls.push(structuredClone(request));
   const result = request.items.map(item => ({ ...item, tags:request.operation === "add" ? [...(item.tags ?? []), ...(request.tags ?? [])] : request.tags ?? [] }));
   if (!request.dryRun) for (const item of result) { const target = inventory.items.find(candidate => candidate.id === item.id); if (target) target.tags = item.tags; }
   return { items:result, completed:request.dryRun ? [] : result.map(item => item.id), dryRun:request.dryRun };
  },
  lock: async () => {},
  setItemTags: async (ref: { name: string }, tags: string[]) => { const item = inventory.items.find((item) => item.recordName === ref.name); if (!item) throw new Error("Missing fixture item"); item.tags = tags; return { ok: true }; },
  status: async () => ({ unlocked: true }),
  inventory: async () => structuredClone(inventory),
  itemDetail: async (ref: { name: string }) => ({ item: inventory.items.find((item) => item.recordName === ref.name), fields: ref.name === "pass:Host" ? [{ path: "key", name: "key", type: "text", value: "deploy" }] : [] }),
} });
const vault = createVaultStore();
const [palette, setPalette] = createSignal(false);
const [narrow, setNarrow] = createSignal(false);
let listShown = false;
const noop = () => {};
render(() => {
  createEffect(() => { void vault.loadDetail(vault.selectedItem()); });
  return (
    <VaultContext.Provider value={vault}>
      <div style={{ display: "flex", height: "100vh" }}>
        <ItemList onCopyPassword={noop} onCopyUsername={noop} onCopyTOTP={noop} onCreate={noop} />
        <div class="detail-pane" style={{ flex: "1" }}><DetailNavigation narrow={narrow()} onShowList={() => { listShown = true; }} /><ItemDetail onEdit={noop} onDuplicate={noop} onRename={noop} onMove={noop} onOpenItem={vault.jumpToItem} onLargeType={noop} /></div>
      </div>
      <Show when={palette()}><CommandPalette open onClose={() => setPalette(false)} actions={[]} onOpenItem={vault.jumpToItem} onCopyPassword={noop} onCopyTOTP={noop} /></Show>
    </VaultContext.Provider>
  );
}, document.body);

const navigationTest = {
  batches: () => batchCalls,
  ready: () => vault.refresh(), palette: () => setPalette(true), filter: vault.updateFilters,
  query: vault.setQuery, raw: vault.setRawSecrets, back: vault.goBack, lock: vault.lock,
  jump: (id: string) => vault.jumpToItem(inventory.items.find((item) => item.id === id)!),
  select: (id: string) => vault.selectItem(inventory.items.find((item) => item.id === id)!),
  remove: async (id: string) => { inventory.items = inventory.items.filter((item) => item.id !== id); await vault.refresh(); },
  narrow: setNarrow,
  rename: async () => { inventory.items[0]!.title = "Renamed"; await vault.refresh(); },
  state: () => ({ listShown, selected: vault.selectedID(), detail: vault.detail()?.item.id, filters: vault.filters(), query: vault.query(), raw: vault.rawSecrets(), back: vault.backItem()?.id }),
};
declare global { interface Window { navigationTest: typeof navigationTest } }
window.navigationTest = navigationTest;
