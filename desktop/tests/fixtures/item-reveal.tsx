import { render } from "solid-js/web";
import type { ItemDetail as Detail } from "../../src/shared/contracts";
import { ItemDetail } from "../../src/renderer/src/features/ItemDetail";
import { createVaultStore, VaultContext } from "../../src/renderer/src/lib/store";

let name = "first";
let pendingReveal: ((result: { value: string }) => void) | undefined;
let deferReveal = false;
const detail = (): Detail => ({
  item: { id: name, scopeId: "test", recordName: name, kind: "secret", title: name, vault: "Test", badge: "SECRET" },
  fields: [{ name: "Token", path: "value", type: "secret", sensitive: true }],
});

// No Electron or fd0 process: every bridge call stays inside this page.
Object.defineProperty(window, "fd0", { value: {
  development: true,
  itemDetail: async () => detail(),
  reveal: async () => deferReveal
    ? new Promise<{ value: string }>((resolve) => { pendingReveal = resolve; })
    : { value: "synthetic-secret" },
} });
const vault = createVaultStore();
const noop = () => {};
render(() => (
  <VaultContext.Provider value={vault}>
    <ItemDetail onEdit={noop} onDuplicate={noop} onRename={noop} onMove={noop} onOpenItem={noop} onLargeType={noop} />
  </VaultContext.Provider>
), document.body);

const revealTest = {
  async refresh(next = name) {
    name = next;
    await vault.loadDetail(detail().item);
  },
  clear: () => vault.loadDetail(undefined),
  defer() { deferReveal = true; },
  resolve() { pendingReveal?.({ value: "synthetic-secret" }); },
};
declare global {
  interface Window { revealTest: typeof revealTest }
}
window.revealTest = revealTest;
