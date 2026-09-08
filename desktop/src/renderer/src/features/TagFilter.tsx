import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import { tagCatalog, tagKey } from "../lib/tags";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Popover } from "../ui/Popover";

export function TagFilter() {
  const vault = useVault();
  const id = createUniqueId();
  let anchor: HTMLButtonElement | undefined;
  let search: HTMLInputElement | undefined;
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const options = createMemo(() => tagCatalog(vault.inventory().items, vault.filters().vault));
  const visible = createMemo(() => options().filter((option) => tagKey(option.tag).includes(tagKey(query()))));
  const selected = (tag: string) => vault.filters().tags.some((value) => tagKey(value) === tagKey(tag));
  return (
    <>
      <Button ref={anchor} size="sm" aria-expanded={open()} aria-controls={id} onClick={() => { setQuery(""); setOpen(!open()); if (open()) queueMicrotask(() => search?.focus()); }}>Tags</Button>
      <Popover anchor={anchor} open={open()} onClose={() => setOpen(false)} role="dialog" label="Filter password tags" class="tag-filter">
        <div id={id}>
          <p class="field-message">Match all selected tags</p>
          <input ref={search} class="input" type="search" aria-label="Search tags" placeholder="Search tags…" value={query()}
            onInput={(event) => setQuery(event.currentTarget.value)} />
          <label class="tag-filter-option">
            <input type="checkbox" checked={vault.filters().untagged}
              onChange={(event) => vault.updateFilters({ type: "password", untagged: event.currentTarget.checked })} />
            <span>Without tags</span>
          </label>
          <For each={visible()}>{(option) => (
            <label class="tag-filter-option">
              <input type="checkbox" checked={selected(option.tag)} onChange={() => vault.updateFilters({ type: "password",
                tags: selected(option.tag) ? vault.filters().tags.filter((tag) => tagKey(tag) !== tagKey(option.tag)) : [...vault.filters().tags, option.tag],
                untagged: false,
              })} />
              <span>{option.tag}</span><span class="tag-count">{option.count}</span>
            </label>
          )}</For>
          <Show when={visible().length === 0}><p class="field-message">{vault.filters().vault ? "No matching tags in this vault." : "No matching tags in your vaults."}</p></Show>
        </div>
      </Popover>
    </>
  );
}
