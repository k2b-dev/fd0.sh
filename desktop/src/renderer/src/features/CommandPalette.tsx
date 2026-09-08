import { For, Show, createEffect, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { Dynamic, Portal } from "solid-js/web";
import type { Component } from "solid-js";
import type { IconProps } from "@tabler/icons-solidjs";
import {
  IconDice5,
  IconHelp,
  IconLock,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconSettings,
  IconShieldLock,
  IconStar,
  IconTrash,
  IconUsers,
} from "@tabler/icons-solidjs";
import { fuzzy } from "@k2b/stdlib";
import type { ItemSummary } from "../../../shared/contracts";
import { kindIcon, kindMeta, kindTone, railKinds } from "../lib/items";
import { initials, plural } from "../lib/format";
import { useVault } from "../lib/store";
import { Kbd } from "../ui/Button";

export type PaletteAction = {
  id: string;
  label: string;
  /** Groups the row under a heading. */
  group: string;
  icon: Component<IconProps>;
  hint?: string;
  shortcut?: string;
  /** Extra words that should match this action without appearing in the label. */
  keywords?: string;
  run(): void;
};

type Row =
  | { kind: "item"; key: string; item: ItemSummary; ranges: ReadonlyArray<readonly [number, number]> }
  | { kind: "action"; key: string; action: PaletteAction };

/**
 * The command palette is the primary entry point of the app: it searches items
 * and runs commands in one surface.
 *
 * Enter opens the highlighted item. Cmd+Enter copies its password without ever
 * opening the detail pane — retrieving a credential is the highest-frequency
 * task in a password manager and it should cost one keystroke, not a click into
 * a detail view and a second click on a copy icon.
 */
export function CommandPalette(props: {
  open: boolean;
  onClose(): void;
  actions: PaletteAction[];
  onOpenItem(item: ItemSummary): void;
  onCopyPassword(item: ItemSummary): void;
  onCopyTOTP(item: ItemSummary): void;
}): JSX.Element {
  const vault = useVault();
  const [query, setQuery] = createSignal("");
  const [cursor, setCursor] = createSignal(0);
  let input: HTMLInputElement | undefined;
  let listElement: HTMLDivElement | undefined;
  let previouslyFocused: HTMLElement | null = null;

  const rows = createMemo<Row[]>(() => {
    const needle = query().trim();

    if (!needle) {
      return props.actions
        .filter((action) => action.group !== "Jump to")
        .map((action) => ({ kind: "action", key: `action:${action.id}`, action }));
    }

    const itemHits = fuzzy.filter(needle, vault.inventory().items, {
      key: (item) => `${item.title} ${item.subtitle ?? ""} ${item.vault} ${item.searchText ?? ""} ${(item.tags ?? []).join(" ")}`,
      limit: 8,
    });
    const actionHits = fuzzy.filter(needle, props.actions, {
      key: (action) => `${action.label} ${action.keywords ?? ""} ${action.group}`,
      limit: 6,
    });

    const itemRows: Row[] = itemHits.map((hit) => ({
      kind: "item",
      key: `item:${hit.item.id}`,
      item: hit.item,
      // Ranges are computed against the concatenated haystack; only keep the
      // ones that fall inside the title so highlighting stays truthful.
      ranges: hit.ranges.filter(([start]) => start < hit.item.title.length),
    }));
    const actionRows: Row[] = actionHits.map((hit) => ({ kind: "action", key: `action:${hit.item.id}`, action: hit.item }));
    return [...itemRows, ...actionRows];
  });

  const activeRow = createMemo(() => rows()[cursor()]);

  createEffect(() => {
    query();
    setCursor(0);
  });

  createEffect(() => {
    if (!props.open) return;
    const index = cursor();
    queueMicrotask(() => {
      listElement?.querySelectorAll<HTMLElement>("[data-row]")[index]?.scrollIntoView({ block: "nearest" });
    });
  });

  onMount(() => {
    previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    queueMicrotask(() => input?.focus());
    onCleanup(() => previouslyFocused?.focus());
  });

  function commit(row: Row | undefined, modifier: boolean, shift = false): void {
    if (!row) return;
    if (row.kind === "action") {
      props.onClose();
      row.action.run();
      return;
    }
    if (shift && row.item.hasTOTP) {
      props.onCopyTOTP(row.item);
      props.onClose();
      return;
    }
    if (modifier && row.item.kind === "password") {
      props.onCopyPassword(row.item);
      props.onClose();
      return;
    }
    props.onClose();
    props.onOpenItem(row.item);
  }

  function onKeyDown(event: KeyboardEvent): void {
    const total = rows().length;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setCursor((current) => (total === 0 ? 0 : (current + 1) % total));
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setCursor((current) => (total === 0 ? 0 : (current - 1 + total) % total));
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setCursor(0);
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      setCursor(Math.max(0, total - 1));
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      commit(activeRow(), event.metaKey || event.ctrlKey, event.shiftKey);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      props.onClose();
    }
  }

  const groupedActionHeading = (index: number): string | undefined => {
    const row = rows()[index];
    if (!row || row.kind !== "action") return undefined;
    const previous = rows()[index - 1];
    if (previous && previous.kind === "action" && previous.action.group === row.action.group) return undefined;
    return row.action.group;
  };

  const itemHeading = (index: number): string | undefined => {
    const row = rows()[index];
    if (!row || row.kind !== "item") return undefined;
    if (index > 0) return undefined;
    return "Items";
  };

  return (
    <Portal>
      <div class="palette-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
        <div class="palette" role="dialog" aria-modal="true" aria-label="Search and commands">
          <div class="palette-input">
            <IconSearch size={17} aria-hidden="true" />
            <input
              ref={input}
              type="text"
              role="combobox"
              aria-expanded="true"
              aria-controls="palette-list"
              aria-autocomplete="list"
              aria-activedescendant={activeRow() ? `palette-row-${cursor()}` : undefined}
              placeholder="Search items or type a command…"
              spellcheck={false}
              autocomplete="off"
              value={query()}
              onInput={(event) => setQuery(event.currentTarget.value)}
              onKeyDown={onKeyDown}
            />
            <Show when={query()}>
              <span class="palette-count">{plural(rows().length, "result")}</span>
            </Show>
          </div>

          <div id="palette-list" class="palette-list" role="listbox" aria-label="Results" ref={listElement}>
            <Show
              when={rows().length > 0}
              fallback={
                <div class="palette-empty">
                  <strong>No matches</strong>
                  <span>Try a different word, or press Escape to close.</span>
                </div>
              }
            >
              <For each={rows()}>
                {(row, index) => (
                  <>
                    <Show when={itemHeading(index()) ?? groupedActionHeading(index())}>
                      {(heading) => <div class="palette-heading">{heading()}</div>}
                    </Show>
                    <div
                      data-row
                      id={`palette-row-${index()}`}
                      classList={{ "palette-row": true, "is-active": index() === cursor() }}
                      role="option"
                      aria-selected={index() === cursor()}
                      onPointerMove={() => setCursor(index())}
                      onClick={(event) => commit(row, event.metaKey || event.ctrlKey, event.shiftKey)}
                    >
                      <Show
                        when={row.kind === "item" ? row : undefined}
                        fallback={
                          <Show when={row.kind === "action" ? row.action : undefined}>
                            {(action) => (
                              <>
                                <span class="palette-glyph">
                                  <Dynamic component={action().icon} size={16} strokeWidth={1.7} />
                                </span>
                                <span class="palette-copy">
                                  <strong>{action().label}</strong>
                                  <Show when={action().hint}>
                                    <small>{action().hint}</small>
                                  </Show>
                                </span>
                                <Show when={action().shortcut}>
                                  {(shortcut) => <Kbd keys={shortcut()} />}
                                </Show>
                              </>
                            )}
                          </Show>
                        }
                      >
                        {(itemRow) => (
                          <>
                            <span classList={{ "palette-avatar": true, [kindTone(itemRow().item.kind)]: true }} aria-hidden="true">
                              <Show
                                when={itemRow().item.kind === "password"}
                                fallback={<Dynamic component={kindIcon(itemRow().item.kind)} size={15} strokeWidth={1.7} />}
                              >
                                {initials(itemRow().item.title)}
                              </Show>
                            </span>
                            <span class="palette-copy">
                              <strong>
                                <Highlighted text={itemRow().item.title} ranges={itemRow().ranges} />
                              </strong>
                              <small>
                                {itemRow().item.subtitle || kindMeta[itemRow().item.kind].singular} · {itemRow().item.vault}
                              </small>
                            </span>
                            <Show when={index() === cursor()}>
                              <span class="palette-row-hint">
                                <Kbd keys="enter" /> open
                                <Show when={itemRow().item.kind === "password"}>
                                  <span class="palette-row-sep" />
                                  <Kbd keys="mod+enter" /> copy
                                </Show>
                                <Show when={itemRow().item.hasTOTP}>
                                  <span class="palette-row-sep" />
                                  <Kbd keys="shift+enter" /> one-time code
                                </Show>
                              </span>
                            </Show>
                          </>
                        )}
                      </Show>
                    </div>
                  </>
                )}
              </For>
            </Show>
          </div>

          <footer class="palette-footer">
            <span><Kbd keys="↑" /><Kbd keys="↓" /> navigate</span>
            <span><Kbd keys="enter" /> select</span>
            <span><Kbd keys="mod+enter" /> copy password</span>
            <span><Kbd keys="shift+enter" /> one-time code</span>
            <span><Kbd keys="esc" /> close</span>
          </footer>
        </div>
      </div>
    </Portal>
  );
}

/** Renders matched character ranges in bold so the reason for a hit is visible. */
function Highlighted(props: { text: string; ranges: ReadonlyArray<readonly [number, number]> }): JSX.Element {
  const parts = createMemo(() => {
    if (props.ranges.length === 0) return [{ text: props.text, match: false }];
    const output: Array<{ text: string; match: boolean }> = [];
    let cursor = 0;
    for (const [start, end] of props.ranges) {
      const from = Math.max(cursor, Math.min(start, props.text.length));
      const to = Math.max(from, Math.min(end, props.text.length));
      if (from > cursor) output.push({ text: props.text.slice(cursor, from), match: false });
      if (to > from) output.push({ text: props.text.slice(from, to), match: true });
      cursor = to;
    }
    if (cursor < props.text.length) output.push({ text: props.text.slice(cursor), match: false });
    return output;
  });
  return <For each={parts()}>{(part) => (part.match ? <mark>{part.text}</mark> : <>{part.text}</>)}</For>;
}

/** Builds the standing command list. Kept here so the palette owns its vocabulary. */
export function buildActions(handlers: {
  newItem(): void;
  newVault(): void;
  lock(): void;
  sync(): void;
  openView(view: "deleted" | "generator" | "support" | "settings"): void;
  filterType(type: string): void;
  filterVault(id: string): void;
  showFavorites(): void;
  exportRecovery(): void;
  shareVault(): void;
  vaults: Array<{ id: string; label: string }>;
}): PaletteAction[] {
  const actions: PaletteAction[] = [
    { id: "new-item", group: "Create", label: "New item", icon: IconPlus, shortcut: "mod+n", keywords: "add password secret ssh create", run: handlers.newItem },
    { id: "new-vault", group: "Create", label: "New vault", icon: IconUsers, keywords: "add scope group create", run: handlers.newVault },
    { id: "favorites", group: "Jump to", label: "Favorites", icon: IconStar, keywords: "starred", run: handlers.showFavorites },
  ];

  for (const kind of railKinds) {
    const meta = kindMeta[kind];
    actions.push({
      id: `type-${kind}`,
      group: "Jump to",
      label: meta.label,
      icon: meta.icon,
      hint: meta.blurb,
      keywords: meta.singular,
      run: () => handlers.filterType(kind),
    });
  }
  for (const vault of handlers.vaults) {
    actions.push({
      id: `vault-${vault.id}`,
      group: "Jump to",
      label: vault.label,
      icon: IconUsers,
      hint: "Vault",
      keywords: "vault scope",
      run: () => handlers.filterVault(vault.id),
    });
  }

  actions.push(
    { id: "generator", group: "Tools", label: "Password generator", icon: IconDice5, keywords: "random create strong", run: () => handlers.openView("generator") },
    { id: "deleted", group: "Tools", label: "Recently deleted", icon: IconTrash, keywords: "trash restore undo removed", run: () => handlers.openView("deleted") },
    { id: "share", group: "Tools", label: "Share a vault", icon: IconUsers, keywords: "invite people access member", run: handlers.shareVault },
    { id: "recovery", group: "Tools", label: "Create recovery file", icon: IconShieldLock, keywords: "backup export restore", run: handlers.exportRecovery },
    { id: "sync", group: "Vault", label: "Sync now", icon: IconRefresh, keywords: "refresh upload download", run: handlers.sync },
    { id: "lock", group: "Vault", label: "Lock fd0", icon: IconLock, shortcut: "mod+shift+l", keywords: "close secure", run: handlers.lock },
    { id: "settings", group: "App", label: "Settings", icon: IconSettings, shortcut: "mod+,", keywords: "preferences options", run: () => handlers.openView("settings") },
    { id: "support", group: "App", label: "Support and diagnostics", icon: IconHelp, keywords: "health logs update version help", run: () => handlers.openView("support") },
  );
  return actions;
}
