import { readTags } from "./lib/tags";
import { Show, createEffect, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { hotkeys } from "@k2b/stdlib/solid";
import type { FieldView, ItemSummary, ScopeSummary } from "../../shared/contracts";
import { PasswordGeneratorPanel } from "./components/PasswordGenerator";
import { ShareVaultModal } from "./components/ShareVaultModal";
import { CommandPalette, buildActions } from "./features/CommandPalette";
import { CreateVaultModal, MoveItemModal, RecoveryExportModal, RenameItemModal } from "./features/EditorModals";
import { ItemEditor, ItemTypePicker, emptyDraft, type ItemDraft } from "./features/ItemEditor";
import { DetailNavigation } from "./features/DetailNavigation";
import { ItemDetail } from "./features/ItemDetail";
import { ItemList } from "./features/ItemList";
import { LargeType } from "./features/LargeType";
import { Onboarding } from "./features/Onboarding";
import { Rail } from "./features/Rail";
import { RecentlyDeleted } from "./features/RecentlyDeleted";
import { Settings } from "./features/Settings";
import { Shortcuts } from "./features/Shortcuts";
import { StartupRecovery } from "./features/StartupRecovery";
import { Support } from "./features/Support";
import { Titlebar } from "./features/Titlebar";
import { Unlock } from "./features/Unlock";
import { toAppError } from "./lib/errors";
import {
  isReadinessWarningSnoozed,
  readinessWarningReason,
  snoozeReadinessWarning,
} from "./lib/readiness-snooze";
import { VaultContext, createVaultStore } from "./lib/store";
import { activateTheme, storeTheme } from "./lib/theme";
import { ErrorStack, SafetyBanner, Toasts } from "./ui/Notices";

/** Below this width the list and the detail share one column. */
const NARROW_BREAKPOINT = 720;

function App(): JSX.Element {
  const vault = createVaultStore();
  if (window.location.hash === "#support") vault.setMainView("support");

  const [paletteOpen, setPaletteOpen] = createSignal(false);
  const [shortcutsOpen, setShortcutsOpen] = createSignal(false);
  const [typePickerOpen, setTypePickerOpen] = createSignal(false);
  const [draft, setDraft] = createSignal<ItemDraft | null>(null);
  const [newVaultOpen, setNewVaultOpen] = createSignal(false);
  const [recoveryOpen, setRecoveryOpen] = createSignal(false);
  const [shareScope, setShareScope] = createSignal<ScopeSummary | null>(null);
  const [movingItem, setMovingItem] = createSignal<ItemSummary | null>(null);
  const [renamingItem, setRenamingItem] = createSignal<ItemSummary | null>(null);
  const [largeType, setLargeType] = createSignal<{ field: FieldView; value: string } | null>(null);
  const [readinessClock, setReadinessClock] = createSignal(0);

  const [narrow, setNarrow] = createSignal(window.innerWidth < NARROW_BREAKPOINT);
  const [narrowPane, setNarrowPane] = createSignal<"list" | "detail">("list");

  const showingItems = () => vault.mainView() === "items";
  const readinessBannerReason = createMemo(() => {
    readinessClock();
    if (window.fd0.development) return null;
    const reason = readinessWarningReason(vault.status());
    return reason && !isReadinessWarningSnoozed(localStorage, reason) ? reason : null;
  });

  function snoozeReadiness(): void {
    const reason = readinessBannerReason();
    if (!reason) return;
    snoozeReadinessWarning(localStorage, reason);
    setReadinessClock((current) => current + 1);
    vault.notify("Reminder snoozed for 7 days");
  }

  let pendingPassword = "";

  /** Creating always starts by choosing a type, then opens the full editor. */
  function openAddItem(prefilledPassword = ""): void {
    pendingPassword = prefilledPassword;
    setTypePickerOpen(true);
  }

  function defaultScopeId(): string {
    const filtered = vault.filters().vault;
    const scopes = vault.inventory().scopes;
    return filtered && scopes.some((scope) => scope.id === filtered) ? filtered : scopes[0]?.id ?? "";
  }

  function openItem(item: ItemSummary): void {
    vault.jumpToItem(item);
    if (narrow()) setNarrowPane("detail");
  }

  function openEditor(): void {
    const item = vault.detail()?.item;
    if (!item) return;
    const ref = { scopeId: item.scopeId, name: item.recordName };
    const failed = (cause: unknown) => vault.pushError(toAppError(cause, `fd0 could not open ${item.title} for editing`));

    if (item.kind === "password") {
      void window.fd0
        .editPass(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("password", input.scopeId),
            recordName: input.recordName,
            authorization: input.authorization,
            title: input.item.title,
            urls: input.item.urls ?? [],
            tags: readTags(input.item.meta),
            fields: input.item.fields ?? [],
          });
        })
        .catch(failed);
      return;
    }
    if (item.kind === "secret") {
      void window.fd0
        .editSecret(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("secret", input.scopeId),
            recordName: input.oldName ?? input.name,
            authorization: input.authorization,
            title: input.name,
            value: input.value,
          });
        })
        .catch(failed);
      return;
    }
    if (item.kind === "ssh" && item.badge === "SSH HOST") {
      void window.fd0
        .editSSHHost(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("ssh", input.scopeId),
            recordName: input.oldName ?? `host:${input.host.Alias}`,
            authorization: input.authorization,
            title: input.host.Alias,
            host: {
              hostname: input.host.Hostname,
              user: input.host.User ?? "",
              port: input.host.Port || 22,
              keyName: input.host.KeyName ?? "",
              jumpHost: input.host.ProxyJump ?? "",
              notes: input.host.Description ?? "",
            },
          });
        })
        .catch(failed);
      return;
    }
    if (item.kind === "ssh" && item.badge === "SSH KEY") {
      void window.fd0
        .editSSHKey(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("ssh-key", input.scopeId),
            recordName: `ssh:${input.name}`,
            authorization: input.authorization,
            title: input.name,
            comment: input.comment ?? "",
          });
        })
        .catch(failed);
    }
  }

  function duplicateName(item: ItemSummary): string {
    const base = `${item.title} copy`;
    const recordName = (candidate: string): string => {
      if (item.kind === "password") return `pass:${candidate}`;
      if (item.kind === "ssh") return `host:${candidate}`;
      return candidate;
    };
    const taken = new Set(
      vault.inventory().items
        .filter((candidate) => candidate.scopeId === item.scopeId)
        .map((candidate) => candidate.recordName.toLocaleLowerCase()),
    );
    if (!taken.has(recordName(base).toLocaleLowerCase())) return base;
    for (let suffix = 2; suffix < 10_000; suffix += 1) {
      const candidate = `${base} ${suffix}`;
      if (!taken.has(recordName(candidate).toLocaleLowerCase())) return candidate;
    }
    return `${base} ${crypto.randomUUID().slice(0, 8)}`;
  }

  function openDuplicate(): void {
    const item = vault.detail()?.item;
    if (!item) return;
    const title = duplicateName(item);
    const ref = { scopeId: item.scopeId, name: item.recordName };
    const failed = (cause: unknown) => vault.pushError(toAppError(cause, `fd0 could not duplicate ${item.title}`));

    if (item.kind === "password") {
      void window.fd0.editPass(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("password", input.scopeId),
            title,
            urls: [...(input.item.urls ?? [])],
            tags: readTags(input.item.meta),
            fields: structuredClone(input.item.fields ?? []),
          });
        })
        .catch(failed);
      return;
    }
    if (item.kind === "secret") {
      void window.fd0.editSecret(ref)
        .then((input) => {
          if (!input) return;
          setDraft({ ...emptyDraft("secret", input.scopeId), title, value: input.value });
        })
        .catch(failed);
      return;
    }
    if (item.kind === "ssh" && item.badge === "SSH HOST") {
      void window.fd0.editSSHHost(ref)
        .then((input) => {
          if (!input) return;
          setDraft({
            ...emptyDraft("ssh", input.scopeId),
            title,
            host: {
              hostname: input.host.Hostname,
              user: input.host.User ?? "",
              port: input.host.Port || 22,
              keyName: input.host.KeyName ?? "",
              jumpHost: input.host.ProxyJump ?? "",
              notes: input.host.Description ?? "",
            },
          });
        })
        .catch(failed);
    }
  }

  /**
   * Large type opens as its own always-on-top window so the code stays readable
   * while the user works in another app. The in-window modal remains the
   * fallback for when that window cannot be created.
   */
  async function showLargeType(field: FieldView, value: string): Promise<void> {
    try {
      const result = await window.fd0.showLargeType(field.name, value);
      if (result.window) return;
    } catch {
      // Fall through to the modal below rather than losing the request.
    }
    setLargeType({ field, value });
  }

  function shareVaultById(scopeId: string): void {
    const scope = vault.inventory().scopes.find((candidate) => candidate.id === scopeId);
    if (scope) setShareScope(scope);
  }

  const paletteActions = () =>
    buildActions({
      newItem: () => openAddItem(),
      newVault: () => setNewVaultOpen(true),
      lock: () => void vault.lock(),
      sync: () => void vault.sync(),
      openView: (view) => vault.setMainView(view),
      filterType: (type) => vault.updateFilters({ view: "all", type: type as never }),
      filterVault: (id) => vault.updateFilters({ vault: id }),
      showFavorites: () => vault.updateFilters({ view: "favorites", type: "all" }),
      exportRecovery: () => setRecoveryOpen(true),
      shareVault: () => {
        const scope = vault.inventory().scopes.find((candidate) => candidate.id === vault.filters().vault) ?? vault.inventory().scopes[0];
        if (scope) setShareScope(scope);
        else vault.warn("There is no vault to share yet", "Create a vault first.");
      },
      vaults: vault.inventory().scopes,
    });

  function anyOverlayOpen(): boolean {
    return Boolean(
      paletteOpen() ||
        shortcutsOpen() ||
        typePickerOpen() ||
        draft() ||
        newVaultOpen() ||
        recoveryOpen() ||
        shareScope() ||
        movingItem() ||
        renamingItem() ||
        largeType(),
    );
  }

  createEffect(() => {
    localStorage.setItem("fd0.compactRows", vault.compactRows() ? "1" : "0");
  });

  createEffect(() => {
    const theme = vault.theme();
    const stopTheme = activateTheme(theme);
    onCleanup(stopTheme);
    storeTheme(localStorage, theme);
    void window.fd0.setTheme(theme).catch((cause: unknown) => {
      vault.fail(cause, "fd0 could not apply the appearance");
    });
  });

  createEffect(() => {
    void vault.loadDetail(vault.selectedItem());
  });

  onMount(() => {
    let startupTimer: ReturnType<typeof setTimeout> | undefined;

    const observeStartup = async (): Promise<void> => {
      const next = await window.fd0.startupStatus();
      vault.setStartup(next);
      if (next.state === "ready") {
        await vault.refresh();
        return;
      }
      if (next.state === "starting") startupTimer = setTimeout(() => void observeStartup(), 250);
    };
    void observeStartup().catch((cause) => {
      vault.setStartup({ state: "error", message: cause instanceof Error ? cause.message : String(cause) });
    });

    const statusTimer = setInterval(() => {
      if (vault.startup().state === "ready") {
        setReadinessClock((current) => current + 1);
        void vault.checkLockState();
      }
    }, 10_000);

    const refreshOnFocus = (): void => {
      if (vault.startup().state === "ready") void vault.refresh();
    };
    window.addEventListener("focus", refreshOnFocus);

    const onResize = (): void => {
      setNarrow(window.innerWidth < NARROW_BREAKPOINT);
    };
    window.addEventListener("resize", onResize);

    const shortcuts = hotkeys.create({
      "mod+k": {
        label: "Search and commands",
        run: () => {
          if (vault.status()?.unlocked) setPaletteOpen(true);
        },
        inInput: true,
      },
      "mod+f": {
        label: "Search",
        run: () => {
          if (vault.status()?.unlocked) setPaletteOpen(true);
        },
        inInput: true,
      },
      "mod+n": {
        label: "New item",
        run: () => {
          if (vault.status()?.unlocked) openAddItem();
        },
      },
      "mod+,": {
        label: "Settings",
        run: () => {
          if (vault.status()?.unlocked) vault.setMainView("settings");
        },
      },
      "mod+/": {
        label: "Shortcuts",
        run: () => {
          if (vault.status()?.unlocked) setShortcutsOpen(true);
        },
      },
      "mod+shift+l": { label: "Lock", run: () => void vault.lock() },
    });

    const unsubscribe = window.fd0.onCommand((command) => {
      if (command === "focus-search") setPaletteOpen(true);
      if (command === "new-item") openAddItem();
      if (command === "open-support") {
        vault.setMainView("support");
        void window.fd0.consumeUpdateRequest()
          .catch((cause) => vault.fail(cause, "fd0 could not acknowledge the update view"));
      }
      if (command === "open-settings") vault.setMainView("settings");
      if (command === "lock") void vault.lock();
      if (command === "refresh") void vault.refresh();
    });
    void window.fd0.consumeUpdateRequest()
      .then((requested) => {
        if (requested) vault.setMainView("support");
      })
      .catch((cause) => vault.fail(cause, "fd0 could not open the update view"));

    onCleanup(() => {
      shortcuts.dispose();
      unsubscribe();
      clearInterval(statusTimer);
      if (startupTimer) clearTimeout(startupTimer);
      window.removeEventListener("focus", refreshOnFocus);
      window.removeEventListener("resize", onResize);
      vault.disposeToasts();
    });
  });

  return (
    <VaultContext.Provider value={vault}>
      <Show
        when={vault.startup().state === "ready"}
        fallback={
          <StartupRecovery
            status={vault.startup()}
            onStatus={(next) => {
              vault.setStartup(next);
              if (next.state === "ready") void vault.refresh();
            }}
          />
        }
      >
        <Show
          when={!vault.loading()}
          fallback={
            <div class="boot-screen">
              <div class="logo" aria-label="fd0">
                <strong>fd0</strong>
              </div>
              <div class="boot-progress" role="status" aria-label="Starting fd0" />
            </div>
          }
        >
          <Show
            when={vault.status()?.unlocked}
            fallback={
              <Show
                when={vault.status()?.vaultExists !== false}
                fallback={
                  <Onboarding
                    onCreated={(next) => {
                      vault.setStatus(next);
                      vault.clearErrors();
                      void vault.refresh();
                    }}
                  />
                }
              >
                <Unlock
                  status={vault.status()}
                  onUnlock={(next) => {
                    vault.setStatus(next);
                    vault.clearErrors();
                    void vault.refresh();
                  }}
                />
              </Show>
            }
          >
            <div
              classList={{
                app: true,
                "is-mac": window.fd0.platform === "darwin",
                "is-narrow": narrow(),
                "is-compact": vault.compactRows(),
                [`pane-${narrowPane()}`]: narrow(),
              }}
            >
              <Titlebar
                onOpenPalette={() => setPaletteOpen(true)}
                onCreateItem={() => openAddItem()}
                onCreateVault={() => setNewVaultOpen(true)}
                onShareVault={shareVaultById}
              />

              <Rail />

              <main class="workspace">
                <Show
                  when={showingItems()}
                  fallback={
                    <>
                      <Show when={vault.mainView() === "generator"}>
                        <PasswordGeneratorPanel
                          onNotify={(message, countdown) => vault.notify(message, countdown)}
                          onError={(message) => vault.warn(message)}
                          onSaveAsItem={(value) => openAddItem(value)}
                        />
                      </Show>
                      <Show when={vault.mainView() === "support"}>
                        <Support />
                      </Show>
                      <Show when={vault.mainView() === "settings"}>
                        <Settings onExportRecovery={() => setRecoveryOpen(true)} onShowShortcuts={() => setShortcutsOpen(true)} />
                      </Show>
                      <Show when={vault.mainView() === "deleted"}>
                        <RecentlyDeleted />
                      </Show>
                    </>
                  }
                >
                  <ItemList
                    onCopyPassword={(item) => void vault.copyFromItem(item, "secret")}
                    onCopyUsername={(item) => void vault.copyFromItem(item, "username")}
                    onCopyTOTP={(item) => void vault.copyFromItem(item, "totp")}
                    onCreate={() => openAddItem()}
                  />
                  <div class="detail-pane">
                    <DetailNavigation narrow={narrow()} onShowList={() => setNarrowPane("list")} />
                    <ItemDetail
                      onEdit={openEditor}
                onDuplicate={openDuplicate}
                onRename={setRenamingItem}
                onMove={setMovingItem}
                      onOpenItem={openItem}
                      onLargeType={(field, value) => void showLargeType(field, value)}
                    />
                  </div>
                </Show>
              </main>

              <Show when={!anyOverlayOpen() && readinessBannerReason()}>
                {(reason) => (
                  <SafetyBanner
                    title={
                      reason() === "recovery"
                        ? "Your vault has no backup yet"
                        : "This device holds the only copy of your vault"
                    }
                    description={
                      reason() === "recovery"
                        ? "A recovery file restores your identity if you lose every device."
                        : "Syncing uploads an encrypted copy. Until it succeeds, nothing else has your data."
                    }
                    actionLabel={reason() === "recovery" ? "Create recovery file" : "Sync now"}
                    onAction={() => (reason() === "recovery" ? setRecoveryOpen(true) : void vault.sync())}
                    onSnooze={snoozeReadiness}
                  />
                )}
              </Show>
            </div>

            <ErrorStack errors={vault.errors()} onDismiss={vault.dismissError} />
            <Toasts toasts={vault.toasts()} />

            <Show when={paletteOpen()}>
              <CommandPalette
                open
                onClose={() => setPaletteOpen(false)}
                actions={paletteActions()}
                onOpenItem={openItem}
                onCopyPassword={(item) => void vault.copyFromItem(item, "secret")}
                onCopyTOTP={(item) => void vault.copyFromItem(item, "totp")}
              />
            </Show>

            <Show when={shortcutsOpen()}>
              <Shortcuts onClose={() => setShortcutsOpen(false)} />
            </Show>

            <Show when={typePickerOpen()}>
              <ItemTypePicker
                onClose={() => setTypePickerOpen(false)}
                onPick={(kind) => {
                  setTypePickerOpen(false);
                  setDraft(emptyDraft(kind, defaultScopeId(), pendingPassword));
                  pendingPassword = "";
                }}
              />
            </Show>

            <Show when={draft()}>
              {(current) => (
                <ItemEditor
                  draft={current()}
                  scopes={vault.inventory().scopes}
                  onClose={() => setDraft(null)}
                  onSaved={async (ref) => {
                    const wasCreate = !current().recordName;
                    setDraft(null);
                    vault.notify(wasCreate ? "Item created" : "Changes saved");
                    if (wasCreate && ref) {
                      vault.updateFilters({ view: "all", type: "all" });
                      vault.setQuery("");
                    }
                    await vault.refresh(ref);
                    await vault.loadDetail(vault.selectedItem());
                  }}
                />
              )}
            </Show>

            <Show when={newVaultOpen()}>
              <CreateVaultModal
                onClose={() => setNewVaultOpen(false)}
                onSaved={async () => {
                  setNewVaultOpen(false);
                  vault.notify("Vault created");
                  await vault.refresh();
                }}
              />
            </Show>

            <Show when={recoveryOpen()}>
              <RecoveryExportModal
                onClose={() => setRecoveryOpen(false)}
                onSaved={() => {
                  setRecoveryOpen(false);
                  vault.notify("Recovery file saved and verified");
                  void vault.refresh();
                }}
              />
            </Show>

            <Show when={shareScope()}>
              {(scope) => (
                <ShareVaultModal
                  scope={scope()}
                  onClose={() => setShareScope(null)}
                  onNotify={(message) => vault.notify(message)}
                  onChanged={async () => {
                    await vault.refresh();
                  }}
                />
              )}
            </Show>

            <Show when={movingItem()}>
              {(item) => (
                <MoveItemModal
                  item={item()}
                  scopes={vault.inventory().scopes}
                  onClose={() => setMovingItem(null)}
                  onMoved={async (targetScopeId) => {
                    const moved = item();
                    setMovingItem(null);
                    if (vault.filters().vault === moved.scopeId) {
                      vault.updateFilters({ vault: targetScopeId });
                    }
                    const selected = await vault.refresh({ scopeId: targetScopeId, name: moved.recordName });
                    await vault.loadDetail(selected);
                    vault.notify(`${moved.title} moved`);
                  }}
                />
              )}
            </Show>

            <Show when={renamingItem()}>
              {(item) => (
                <RenameItemModal
                  item={item()}
                  onClose={() => setRenamingItem(null)}
                  onRenamed={async (name) => {
                    const prefix = item().kind === "kubernetes" ? "kube:" : "talos:";
                    const selected = await vault.refresh({ scopeId: item().scopeId, name: `${prefix}${name}` });
                    await vault.loadDetail(selected);
                    vault.notify(`${item().title} renamed to ${name}`);
                    setRenamingItem(null);
                  }}
                />
              )}
            </Show>

            <Show when={largeType()}>
              {(current) => (
                <LargeType
                  label={current().field.name}
                  value={current().value}
                  onClose={() => setLargeType(null)}
                  onCopy={() => {
                    const item = vault.detail()?.item;
                    if (!item) return;
                    void vault.copyField(
                      { scopeId: item.scopeId, name: item.recordName, path: current().field.path },
                      current().field.name,
                    );
                  }}
                />
              )}
            </Show>
          </Show>
        </Show>
      </Show>
    </VaultContext.Provider>
  );
}

export default App;
