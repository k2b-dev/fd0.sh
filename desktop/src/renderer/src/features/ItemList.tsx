import { For, Show, createEffect, createMemo, createSignal, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import { IconCopy, IconKey, IconPlus, IconSearch, IconShieldCheck, IconStar, IconUser, IconX } from "@tabler/icons-solidjs";
import type { ItemSummary } from "../../../shared/contracts";
import { kindIcon, kindMeta, kindTone } from "../lib/items";
import { initials, plural, prettyURL } from "../lib/format";
import { useVault } from "../lib/store";
import { Button, IconButton } from "../ui/Button";
import { Switch } from "../ui/Fields";
import { OrganizeItems } from "./OrganizeItems";
import { TagFilter } from "./TagFilter";


/**
 * The item column.
 *
 * Two things differ from the previous list. Active filters are shown as
 * removable chips instead of being invisible, and each row carries its own copy
 * action so the most common task never requires opening the detail pane.
 */
export function ItemList(props: {
  onCopyPassword(item: ItemSummary): void;
  onCopyUsername(item: ItemSummary): void;
  onCopyTOTP(item: ItemSummary): void;
  onCreate(): void;
}): JSX.Element {
  const vault = useVault();
  const [organizing, setOrganizing] = createSignal(false);
  let listElement: HTMLDivElement | undefined;

  const heading = createMemo(() => {
    const filters = vault.filters();
    if (filters.vault) {
      const scope = vault.inventory().scopes.find((candidate) => candidate.id === filters.vault);
      if (scope) return scope.label;
    }
    if (filters.view === "favorites") return "Favorites";
    return kindMeta[filters.type].label;
  });

  const countLabel = createMemo(() => {
    const shown = vault.visibleItems().length;
    const total = vault.scopeTotal();
    if (vault.query().trim()) return `${plural(shown, "match", "matches")}`;
    if (vault.filters().vault && total > shown) return `${shown} of ${total}`;
    return plural(shown, "item");
  });

  const chips = createMemo(() => {
    const filters = vault.filters();
    const output: Array<{ id: string; label: string; tone?: string; clear(): void }> = [];
    for (const tag of filters.tags) output.push({ id: `tag:${tag}`, label: tag, clear: () => vault.updateFilters({ tags: filters.tags.filter((value) => value !== tag) }) });
    if (filters.untagged) output.push({ id: "untagged", label: "Without tags", clear: () => vault.updateFilters({ untagged: false }) });
    if (filters.view === "favorites") output.push({ id: "view", label: "Favorites", clear: () => vault.updateFilters({ view: "all" }) });
    if (filters.type !== "all") {
      output.push({ id: "type", label: kindMeta[filters.type].label, clear: () => vault.updateFilters({ type: "all" }) });
    }
    if (filters.vault) {
      const scope = vault.inventory().scopes.find((candidate) => candidate.id === filters.vault);
      output.push({ id: "vault", label: scope?.label ?? "Vault", tone: "vault", clear: () => vault.updateFilters({ vault: "" }) });
    }
    if (vault.query().trim()) output.push({ id: "query", label: `“${vault.query().trim()}”`, clear: () => vault.setQuery("") });
    return output;
  });

  const displayItems = createMemo(() => {
    const items = vault.visibleItems();
    if (vault.filters().type !== "ssh") return items;
    return [
      ...items.filter((item) => item.badge === "SSH HOST"),
      ...items.filter((item) => item.badge === "SSH KEY"),
    ];
  });

  const sshGroups = createMemo(() => {
    const items = displayItems();
    return [
      { id: "servers", label: "Servers", items: items.filter((item) => item.badge === "SSH HOST") },
      { id: "keys", label: "Keys", items: items.filter((item) => item.badge === "SSH KEY") },
    ];
  });

  // Keep the DOM selection in sync so arrow keys resume from the right place.
  createEffect(() => {
    const items = displayItems();
    if (items.length === 0) {
      if (vault.selectedID()) vault.setSelectedID("");
      return;
    }
    if (!items.some((item) => item.id === vault.selectedID())) vault.setSelectedID(items[0]!.id);
  });

  function moveSelection(delta: number): void {
    const items = displayItems();
    if (items.length === 0) return;
    const index = items.findIndex((item) => item.id === vault.selectedID());
    const next = index < 0 ? 0 : Math.min(items.length - 1, Math.max(0, index + delta));
    const target = items[next];
    if (!target) return;
    vault.selectItem(target);
    queueMicrotask(() => {
      listElement?.querySelector<HTMLElement>(`[data-item-id="${target.id}"]`)?.focus();
    });
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveSelection(1);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      moveSelection(-1);
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      moveSelection(-displayItems().length);
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      moveSelection(displayItems().length);
      return;
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "c") {
      const item = vault.selectedItem();
      if (!item || item.kind !== "password") return;
      event.preventDefault();
      props.onCopyPassword(item);
    }
  }

  function renderItem(item: ItemSummary): JSX.Element {
    return (
      <ItemRow
        item={item}
        selected={item.id === vault.selectedID()}
        compact={vault.compactRows()}
        onSelect={() => vault.selectItem(item)}
        onCopyPassword={() => props.onCopyPassword(item)}
        onCopyUsername={() => props.onCopyUsername(item)}
        onCopyTOTP={() => props.onCopyTOTP(item)}
      />
    );
  }

  return (
    <section class="item-column" aria-label="Items">
      <Show when={organizing()}><OrganizeItems items={vault.visibleItems()} onClose={() => setOrganizing(false)} /></Show>
      <header class="column-header">
        <div class="column-heading">
          <h1>{heading()}</h1>
          <span class="column-count">{countLabel()}</span>
        </div>
        <TagFilter />
        <Button size="sm" disabled={!vault.visibleItems().length || vault.rawSecrets()} onClick={() => setOrganizing(true)}>Organize</Button>
        <Show when={vault.filters().type === "secret"}>
          <Switch
            label="Show raw records"
            checked={vault.rawSecrets()}
            onChange={(value) => vault.setRawSecrets(value)}
          />
        </Show>
      </header>

      <Show when={chips().length > 0}>
        <div class="chip-bar" aria-label="Active filters">
          <For each={chips()}>
            {(chip) => (
              <button
                type="button"
                classList={{ chip: true, [`chip-${chip.tone ?? "default"}`]: true }}
                onClick={chip.clear}
                aria-label={`Remove filter ${chip.label}`}
              >
                <span>{chip.label}</span>
                <IconX size={12} />
              </button>
            )}
          </For>
          <Show when={vault.activeFilterCount() + (vault.query().trim() ? 1 : 0) > 1}>
            <button type="button" class="chip-clear" onClick={() => vault.resetFilters()}>
              Clear all
            </button>
          </Show>
        </div>
      </Show>

      <Show when={vault.rawSecrets() && vault.filters().type === "secret"}>
        <p class="inline-note">
          Showing every stored record as a raw secret. Editing and favorites are unavailable in this view.
        </p>
      </Show>

      <div
        class="item-list"
        role="listbox"
        aria-label={heading()}
        tabindex={-1}
        ref={listElement}
        onKeyDown={onKeyDown}
      >
        <Show when={displayItems().length > 0} fallback={<EmptyState onCreate={props.onCreate} />}>
          <Show
            when={vault.filters().type === "ssh"}
            fallback={<For each={displayItems()}>{renderItem}</For>}
          >
            <For each={sshGroups()}>
              {(group) => (
                <Show when={group.items.length > 0}>
                  <div class="item-group" role="group" aria-label={group.label}>
                    <div class="item-group-heading">
                      <span>{group.label}</span>
                      <span>{group.items.length}</span>
                    </div>
                    <For each={group.items}>{renderItem}</For>
                  </div>
                </Show>
              )}
            </For>
          </Show>
        </Show>
      </div>
    </section>
  );
}

function ItemRow(props: {
  item: ItemSummary;
  selected: boolean;
  compact: boolean;
  onSelect(): void;
  onCopyPassword(): void;
  onCopyUsername(): void;
  onCopyTOTP(): void;
}): JSX.Element {
  const isPassword = () => props.item.kind === "password";
  const subtitle = () => {
    const raw = props.item.subtitle;
    if (!raw) return kindMeta[props.item.kind].singular;
    return /^https?:\/\//.test(raw) ? prettyURL(raw) : raw;
  };

  return (
    <div
      data-item-id={props.item.id}
      classList={{
        "item-row": true,
        "is-selected": props.selected,
        "is-compact": props.compact,
        "is-ssh-key": props.item.badge === "SSH KEY",
      }}
      role="option"
      aria-selected={props.selected}
      tabindex={props.selected ? 0 : -1}
      onClick={props.onSelect}
      onFocus={props.onSelect}
      onKeyDown={(event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        props.onSelect();
      }}
    >
      <span classList={{ "item-avatar": true, [kindTone(props.item.kind)]: true }} aria-hidden="true">
        <Show
          when={isPassword()}
          fallback={
            <Dynamic
              component={props.item.badge === "SSH KEY" ? IconKey : kindIcon(props.item.kind)}
              size={16}
              strokeWidth={1.7}
            />
          }
        >
          {initials(props.item.title)}
        </Show>
      </span>

      <span class="item-copy">
        <span class="item-title">
          {props.item.title}
          <Show when={props.item.favorite}>
            <IconStar size={12} class="item-star" aria-label="Favorite" />
          </Show>
        </span>
        <span class="item-subtitle">{subtitle()}</span>
        <Show when={!props.compact && props.item.tags?.length}>
          <span class="item-tags">
            <For each={props.item.tags?.slice(0, 2)}>{(tag) => <span class="password-tag">{tag}</span>}</For>
            <Show when={(props.item.tags?.length ?? 0) > 2}><span class="tag-count">+{props.item.tags!.length - 2}</span></Show>
          </span>
        </Show>
      </span>

      {/* Quick actions: the reason a password manager exists is retrieving a
          credential, and that should not require opening the item first. */}
      <span class="item-actions">
        <Show when={isPassword()}>
          <Show when={props.item.hasTOTP}>
            <IconButton
              label={`Copy one-time code for ${props.item.title}`}
              size="sm"
              tabIndex={props.selected ? 0 : -1}
              onClick={(event) => {
                event.stopPropagation();
                props.onCopyTOTP();
              }}
            >
              <IconShieldCheck size={15} />
            </IconButton>
          </Show>
          <IconButton
            label={`Copy username for ${props.item.title}`}
            size="sm"
            tabIndex={props.selected ? 0 : -1}
            onClick={(event) => {
              event.stopPropagation();
              props.onCopyUsername();
            }}
          >
            <IconUser size={15} />
          </IconButton>
          <IconButton
            label={`Copy password for ${props.item.title}`}
            size="sm"
            emphasis
            tabIndex={props.selected ? 0 : -1}
            onClick={(event) => {
              event.stopPropagation();
              props.onCopyPassword();
            }}
          >
            <IconCopy size={15} />
          </IconButton>
        </Show>
      </span>
    </div>
  );
}

/**
 * Distinguishes an empty vault from a filtered-to-nothing list. The previous
 * copy said "Try another search or filter" even on a brand-new vault where
 * nothing had been searched or filtered.
 */
function EmptyState(props: { onCreate(): void }): JSX.Element {
  const vault = useVault();
  const searching = () => Boolean(vault.query().trim());
  const filtered = () => vault.activeFilterCount() > 0;

  return (
    <Show
      when={!vault.isEmptyVault()}
      fallback={
        <div class="empty-state">
          <span class="empty-glyph tone-password">
            <IconKey size={20} strokeWidth={1.6} />
          </span>
          <strong>Your vault is ready</strong>
          <span>Save your first password. fd0 encrypts it on this device right away.</span>
          <Button variant="primary" onClick={props.onCreate}>
            <IconPlus size={15} />
            Add your first password
          </Button>
        </div>
      }
    >
      <Show
        when={searching() || filtered()}
        fallback={
          <div class="empty-state">
            <span class="empty-glyph tone-password">
              <IconKey size={20} strokeWidth={1.6} />
            </span>
            <strong>Nothing here yet</strong>
            <span>Items you add will appear in this list.</span>
            <Button variant="primary" onClick={props.onCreate}>
              <IconPlus size={15} />
              Add an item
            </Button>
          </div>
        }
      >
        <div class="empty-state">
          <span class="empty-glyph">
            <IconSearch size={20} strokeWidth={1.6} />
          </span>
          <strong>{searching() ? "No items match your search" : "No items match these filters"}</strong>
          <span>
            {searching()
              ? "Check the spelling, or clear the search to see everything again."
              : "Remove a filter to widen the list."}
          </span>
          <Button onClick={() => vault.resetFilters()}>Clear filters</Button>
        </div>
      </Show>
    </Show>
  );
}
