import { matchesItemTags, tagCatalog, tagKey } from "./tags";
import { batch, createContext, createMemo, createSignal, useContext } from "solid-js";
import type {
  Inventory,
  ItemDetail,
  ItemKind,
  ItemSummary,
  RecordRef,
  StartupStatus,
  DesktopTheme,
  VaultStatus,
} from "../../../shared/contracts";
import { appWarning, toAppError, type AppError } from "./errors";
import { readTheme } from "./theme";
import type { ToastMessage } from "../ui/Notices";

export type MainView = "items" | "deleted" | "generator" | "support" | "settings";
export type TypeFilter = "all" | ItemKind;
export type SmartView = "all" | "favorites";

export type Filters = {
  view: SmartView;
  type: TypeFilter;
  vault: string;
  tags: string[];
  untagged: boolean;
};

const emptyInventory: Inventory = { scopes: [], items: [], counts: {} };

export function createVaultStore() {
  const [startup, setStartup] = createSignal<StartupStatus>({ state: "starting" });
  const [status, setStatus] = createSignal<VaultStatus | null>(null);
  const [inventory, setInventory] = createSignal<Inventory>(emptyInventory);
  const [detail, setDetail] = createSignal<ItemDetail | null>(null);
  const [selectedID, setSelectedID] = createSignal("");
  const [mainView, setMainView] = createSignal<MainView>("items");
  const [filters, setFilters] = createSignal<Filters>({ view: "all", type: "all", vault: "", tags: [], untagged: false });
  const [query, setQuery] = createSignal("");
  const [rawSecrets, setRawSecrets] = createSignal(false);
  const [loading, setLoading] = createSignal(true);
  const [detailLoading, setDetailLoading] = createSignal(false);
  const [syncing, setSyncing] = createSignal(false);
  const [errors, setErrors] = createSignal<AppError[]>([]);
  const [toasts, setToasts] = createSignal<ToastMessage[]>([]);
  const [compactRows, setCompactRows] = createSignal(localStorage.getItem("fd0.compactRows") === "1");
  const [theme, setTheme] = createSignal<DesktopTheme>(readTheme(localStorage, window.fd0.development));

  let detailRequest = 0;
  let toastID = 1;
  const toastTimers = new Map<number, ReturnType<typeof setTimeout>>();

  // ---------------------------------------------------------------- notices

  function pushError(error: AppError): void {
    setErrors((current) => [...current.filter((existing) => existing.title !== error.title), error].slice(-3));
  }

  function fail(cause: unknown, fallbackTitle?: string, action?: AppError["action"]): void {
    const error = toAppError(cause, fallbackTitle);
    pushError(action ? { ...error, action } : error);
  }

  function warn(title: string, detail?: string): void {
    pushError(appWarning(title, detail));
  }

  function dismissError(id: number): void {
    setErrors((current) => current.filter((error) => error.id !== id));
  }

  function clearErrors(): void {
    setErrors([]);
  }

  function notify(text: string, countdownSeconds?: number): void {
    const id = toastID++;
    // Repeating an action replaces its toast rather than stacking a second
    // identical copy; two "Item saved" banners say nothing the first did not.
    setToasts((current) => {
      const withoutDuplicate = current.filter((toast) => {
        if (toast.text !== text) return true;
        const timer = toastTimers.get(toast.id);
        if (timer) clearTimeout(timer);
        toastTimers.delete(toast.id);
        return false;
      });
      return [...withoutDuplicate.slice(-2), { id, text, countdown: countdownSeconds }];
    });
    if (countdownSeconds !== undefined) {
      let remaining = countdownSeconds;
      const tick = setInterval(() => {
        remaining -= 1;
        setToasts((current) => current.map((toast) => (toast.id === id ? { ...toast, countdown: remaining } : toast)));
        if (remaining <= 0) clearInterval(tick);
      }, 1000);
      toastTimers.set(id, setTimeout(() => {
        clearInterval(tick);
        setToasts((current) => current.filter((toast) => toast.id !== id));
        toastTimers.delete(id);
      }, countdownSeconds * 1000));
      return;
    }
    toastTimers.set(id, setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
      toastTimers.delete(id);
    }, 3200));
  }

  function notifyAction(text: string, label: string, run: () => void | Promise<void>): void {
    const id = toastID++;
    const dismissAndRun = async (): Promise<void> => {
      const timer = toastTimers.get(id);
      if (timer) clearTimeout(timer);
      toastTimers.delete(id);
      setToasts((current) => current.filter((toast) => toast.id !== id));
      await run();
    };
    setToasts((current) => [...current.slice(-2), { id, text, action: { label, run: dismissAndRun } }]);
    toastTimers.set(id, setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
      toastTimers.delete(id);
    }, 10_000));
  }

  function disposeToasts(): void {
    for (const timer of toastTimers.values()) clearTimeout(timer);
    toastTimers.clear();
  }

  // ---------------------------------------------------------------- derived

  const selectedItem = createMemo(() => inventory().items.find((item) => item.id === selectedID()));

  const visibleItems = createMemo(() => {
    const current = filters();
    let items = inventory().items;

    if (current.view === "favorites") items = items.filter((item) => item.favorite);
    // The raw projection intentionally shows every stored record as a secret.
    if (current.type !== "all" && !(current.type === "secret" && rawSecrets())) {
      items = items.filter((item) => item.kind === current.type);
    }
    if (current.vault) items = items.filter((item) => item.scopeId === current.vault);

    items = items.filter((item) => matchesItemTags(item, current.tags, current.untagged));
    const needle = query().trim().toLocaleLowerCase();
    if (needle) {
      items = items.filter((item) =>
        [item.title, item.subtitle, item.vault, item.badge, item.searchText, ...(item.tags ?? [])].some((value) =>
          value?.toLocaleLowerCase().includes(needle),
        ),
      );
    }
    return items;
  });

  /** Items matching everything except the vault filter — the "N of M" denominator. */
  const scopeTotal = createMemo(() => {
    const current = filters();
    let items = inventory().items;
    if (current.view === "favorites") items = items.filter((item) => item.favorite);
    if (current.type !== "all" && !(current.type === "secret" && rawSecrets())) {
      items = items.filter((item) => item.kind === current.type);
    }
    return items.filter((item) => matchesItemTags(item, current.tags, current.untagged)).length;
  });

  const activeFilterCount = createMemo(() => {
    const current = filters();
    return (current.view !== "all" ? 1 : 0) + (current.type !== "all" ? 1 : 0) + (current.vault ? 1 : 0) + current.tags.length + (current.untagged ? 1 : 0);
  });

  const vaultCounts = createMemo(() => {
    const counts = new Map<string, number>();
    for (const item of inventory().items) counts.set(item.scopeId, (counts.get(item.scopeId) ?? 0) + 1);
    return counts;
  });

  const isEmptyVault = createMemo(() => inventory().items.length === 0);

  const needsRecovery = createMemo(() => {
    const current = status();
    if (!current || window.fd0.development) return false;
    return !current.readiness?.recoveryVerifiedAt || !current.readiness?.firstSyncAt;
  });

  // ---------------------------------------------------------------- actions

  async function refresh(preferred?: RecordRef): Promise<ItemSummary | undefined> {
    try {
      const nextStatus = await window.fd0.status();
      setStatus(nextStatus);
      if (!nextStatus.unlocked) {
        batch(() => {
          setInventory(emptyInventory);
          setDetail(null);
          setSelectedID("");
        });
        return undefined;
      }
      const nextInventory = await window.fd0.inventory();
      const preferredItem = preferred
        ? nextInventory.items.find((item) => item.scopeId === preferred.scopeId && item.recordName === preferred.name)
        : undefined;
      batch(() => {
        setInventory(nextInventory);
        if (preferredItem) setSelectedID(preferredItem.id);
      });
      if (nextInventory.truncated) {
        warn(
          "Some items are hidden from this view",
          "A few records are unusually large or could not be read. Open Support to copy diagnostics.",
        );
      }
      return preferredItem;
    } catch (cause) {
      fail(cause, "fd0 could not load your vault");
      return undefined;
    } finally {
      setLoading(false);
    }
  }

  async function checkLockState(): Promise<void> {
    try {
      const next = await window.fd0.status();
      setStatus(next);
      if (next.unlocked) return;
      batch(() => {
        setInventory(emptyInventory);
        setDetail(null);
        setSelectedID("");
      });
    } catch (cause) {
      fail(cause, "fd0 lost contact with the local service");
    }
  }

  async function loadDetail(item: ItemSummary | undefined): Promise<void> {
    const request = ++detailRequest;
    if (!item) {
      setDetail(null);
      setDetailLoading(false);
      return;
    }
    setDetailLoading(true);
    try {
      const next = await window.fd0.itemDetail({
        scopeId: item.scopeId,
        name: item.recordName,
        raw: filters().type === "secret" && rawSecrets(),
      });
      if (request === detailRequest) setDetail(next);
    } catch (cause) {
      if (request === detailRequest) {
        setDetail(null);
        fail(cause, "fd0 could not open that item");
      }
    } finally {
      if (request === detailRequest) setDetailLoading(false);
    }
  }

  function selectItem(item: ItemSummary): void {
    setSelectedID(item.id);
  }

  function updateFilters(next: Partial<Filters>): void {
    batch(() => {
      setMainView("items");
      setFilters((current) => {
        const updated = { ...current, ...next };
        if (next.type && next.type !== "password" && next.type !== "all") {
          updated.tags = [];
          updated.untagged = false;
        }
        if (next.untagged) updated.tags = [];
        if (next.tags?.length) updated.untagged = false;
        if (next.vault !== undefined && next.vault !== current.vault) {
          const available = new Set(tagCatalog(inventory().items, next.vault).map((option) => tagKey(option.tag)));
          updated.tags = updated.tags.filter((tag) => available.has(tagKey(tag)));
        }
        return updated;
      });
    });
  }

  function resetFilters(): void {
    batch(() => {
      setMainView("items");
      setFilters({ view: "all", type: "all", vault: "", tags: [], untagged: false });
      setQuery("");
      setRawSecrets(false);
    });
  }

  async function lock(): Promise<void> {
    try {
      await window.fd0.lock();
      batch(() => {
        setStatus((current) => (current ? { ...current, unlocked: false } : current));
        setInventory(emptyInventory);
        setDetail(null);
        setSelectedID("");
        clearErrors();
      });
    } catch (cause) {
      fail(cause, "fd0 could not lock the vault");
    }
  }

  async function sync(): Promise<void> {
    if (syncing()) return;
    setSyncing(true);
    try {
      if (!window.fd0.development) {
        const result = await window.fd0.sync();
        if (result.cancelled) return;
      }
      await refresh();
      notify(window.fd0.development ? "Development vault refreshed" : "Vault synced");
    } catch (cause) {
      fail(cause, "Sync did not finish", { label: "Try again", run: () => void sync() });
    } finally {
      setSyncing(false);
    }
  }

  async function copyField(ref: { scopeId: string; name: string; path: string }, label: string): Promise<void> {
    try {
      const result = await window.fd0.copy(ref);
      notify(`${label} copied — clears in`, result.clearAfterSeconds);
    } catch (cause) {
      fail(cause, `fd0 could not copy ${label.toLocaleLowerCase()}`);
    }
  }

  /**
   * Copies a field straight from a list row, without opening the item.
   *
   * The field path is not known until the detail is fetched, so this loads the
   * detail, picks the best-matching field, and copies through the same
   * main-process clipboard handler as the detail pane. No plaintext ever
   * reaches the renderer.
   */
  async function copyFromItem(item: ItemSummary, want: "secret" | "username" | "totp"): Promise<void> {
    try {
      const loaded = await window.fd0.itemDetail({ scopeId: item.scopeId, name: item.recordName });
      const fields = loaded.fields.flatMap(function flatten(field): typeof loaded.fields {
        return [field, ...(field.children ?? []).flatMap(flatten)];
      });

      const target =
        want === "totp"
          ? fields.find((field) => field.type === "totp")
          : want === "secret"
          ? fields.find((field) => field.type === "secret" && /^(password|pass|pin)$/i.test(field.name)) ??
            fields.find((field) => field.type === "secret")
          : fields.find((field) => /^(username|user|login|email|e-mail|account)$/i.test(field.name)) ??
            fields.find((field) => field.type === "text" && field.copyable);

      if (!target) {
        warn(
          want === "secret"
            ? `${item.title} has no password field`
            : want === "totp"
              ? `${item.title} has no one-time code`
              : `${item.title} has no username field`,
          "Open the item to see what it stores.",
        );
        return;
      }
      await copyField({ scopeId: item.scopeId, name: item.recordName, path: target.path }, target.name);
    } catch (cause) {
      fail(cause, `fd0 could not copy from ${item.title}`);
    }
  }

  async function removeItem(item: ItemSummary): Promise<void> {
    try {
      const result = await window.fd0.remove({ scopeId: item.scopeId, name: item.recordName });
      if (!result.ok) {
        // A blocked removal already explained itself in a native warning. Only
        // surface the generic outcome when the user simply cancelled.
        if (!result.blocked) notify("Nothing was removed");
        return;
      }
      setSelectedID("");
      await refresh();
      if (result.undo) {
        const undo = result.undo;
        notifyAction(`${item.title} removed`, "Undo", async () => {
          try {
            const restored = await window.fd0.restoreDeletedItem(undo);
            if (!restored.ok) {
              notify("Nothing was restored");
              return;
            }
            const selected = await refresh({ scopeId: undo.scopeId, name: undo.name });
            await loadDetail(selected);
            notify(`${item.title} restored`);
          } catch (cause) {
            fail(cause, `fd0 could not restore ${item.title}`);
          }
        });
      } else {
        notify(`${item.title} removed`);
      }
    } catch (cause) {
      fail(cause, `fd0 could not remove ${item.title}`);
    }
  }

  async function toggleFavorite(item: ItemSummary): Promise<void> {
    try {
      await window.fd0.setFavorite({ scopeId: item.scopeId, name: item.recordName }, !item.favorite);
      notify(item.favorite ? "Removed from favorites" : "Added to favorites");
      await refresh();
      await loadDetail(inventory().items.find((candidate) => candidate.id === item.id));
    } catch (cause) {
      fail(cause, "fd0 could not update favorites");
    }
  }

  return {
    // state
    startup, setStartup,
    status, setStatus,
    inventory,
    detail,
    selectedID, setSelectedID,
    mainView, setMainView,
    filters, updateFilters, resetFilters,
    query, setQuery,
    rawSecrets, setRawSecrets,
    loading, setLoading,
    detailLoading,
    syncing,
    errors, dismissError, clearErrors, pushError, fail, warn,
    toasts, notify, notifyAction, disposeToasts,
    compactRows, setCompactRows,
    theme, setTheme,
    // derived
    selectedItem, visibleItems, scopeTotal, activeFilterCount, vaultCounts, isEmptyVault, needsRecovery,
    // actions
    refresh, checkLockState, loadDetail, selectItem, lock, sync, copyField, copyFromItem, removeItem, toggleFavorite,
  };
}

export type VaultStore = ReturnType<typeof createVaultStore>;

export const VaultContext = createContext<VaultStore>();

export function useVault(): VaultStore {
  const store = useContext(VaultContext);
  if (!store) throw new Error("useVault must be used inside <VaultContext.Provider>");
  return store;
}
