import { Show, createEffect, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { ItemEditor, emptyDraft, type ItemDraft } from "../../src/renderer/src/features/ItemEditor";
import { ItemList } from "../../src/renderer/src/features/ItemList";
import { ItemDetail } from "../../src/renderer/src/features/ItemDetail";
import { createVaultStore, VaultContext } from "../../src/renderer/src/lib/store";
import type { Inventory, ItemSummary, SavePassInput } from "../../src/shared/contracts";
import "../../src/renderer/src/styles.css";

const item = (id: string, scopeId: string, tags: string[]): ItemSummary => ({ id, scopeId, recordName: `pass:${id}`, title: id, kind: "password", vault: scopeId, badge: "PASSWORD", tags });
const inventory: Inventory = {
  scopes: [{ id: "work", label: "Work vault" }, { id: "private", label: "Private vault" }],
  items: [item("GitHub", "work", ["Existing"]), item("Work login", "work", ["Work", "Team A"]), item("Personal", "private", ["Private"]), item("No tags", "work", [])],
  counts: { password: 4 },
};
let saved: SavePassInput | null = null;
let failSave = false;
let failTags = false;
let secretWrites = 0;
let savedTags: string[] = [];
Object.defineProperty(window, "fd0", { value: {
  development: true,
  saveSecret: async () => { secretWrites++; return { ok:true }; },
  setItemTags: async (_ref: unknown, tags: string[]) => { if (failTags) throw new Error("Synthetic tags failure"); savedTags = [...tags]; return { ok:true }; },
  status: async () => ({ unlocked: true }),
  inventory: async () => structuredClone(inventory),
  itemDetail: async (ref: { name: string }) => ({ item: inventory.items.find((item) => item.recordName === ref.name), fields: [] }),
  savePass: async (input: SavePassInput) => { if (failSave) throw new Error("Synthetic save error"); saved = structuredClone(input); },
} });
const vault = createVaultStore();
const [draft, setDraft] = createSignal<ItemDraft | null>(null);
const noop = () => {};
render(() => {
  createEffect(() => { void vault.loadDetail(vault.selectedItem()); });
  return (
    <VaultContext.Provider value={vault}>
      <div style={{ display: "flex", height: "100vh" }}>
        <ItemList onCopyPassword={noop} onCopyUsername={noop} onCopyTOTP={noop} onCreate={() => openEditor(true)} />
        <ItemDetail onEdit={() => openEditor(false)} onDuplicate={noop} onRename={noop} onMove={noop} onOpenItem={noop} onLargeType={noop} />
      </div>
      <Show when={draft()} keyed>{(value) => <ItemEditor draft={value} scopes={inventory.scopes} onClose={() => setDraft(null)} onSaved={async () => { setDraft(null); }} />}</Show>
    </VaultContext.Provider>
  );
}, document.body);

function openEditor(create = false) {
  saved = null;
  setDraft({ ...emptyDraft("password", "work"), title: "GitHub", recordName: create ? undefined : "GitHub", tags: create ? [] : ["Existing"] });
}
const tagsTest = {
  ready: () => vault.refresh(), openEditor,
  saved: () => saved,
  openSecret: () => setDraft({ ...emptyDraft("secret", "work"), title:"Token", value:"synthetic-only" }),
  failTags: (value: boolean) => { failTags = value; },
  secretState: () => ({ writes:secretWrites, tags:savedTags }),
  fail(value: boolean) { failSave = value; },
  filters: () => vault.filters(),
  filter: vault.updateFilters,
  visible: () => vault.visibleItems().map((item) => item.id),
  errors: () => vault.errors().map((error) => error.title),
};
declare global { interface Window { tagsTest: typeof tagsTest } }
window.tagsTest = tagsTest;
