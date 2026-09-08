import { For, Show, createEffect, createMemo, createSignal, createUniqueId } from "solid-js";
import { IconX } from "@tabler/icons-solidjs";
import { addTag, suggestTags, tagKey, trimTag, type TagOption } from "../lib/tags";
import { Popover } from "../ui/Popover";

export function TagInput(props: {
  value: string[];
  pending: string;
  options: TagOption[];
  disabled?: boolean;
  onChange(tags: string[]): void;
  onPending(text: string): void;
}) {
  const id = createUniqueId();
  let input: HTMLInputElement | undefined;
  const [open, setOpen] = createSignal(false);
  const [active, setActive] = createSignal(-1);
  const suggestions = createMemo(() => suggestTags(props.options, props.value, props.pending));
  const error = createMemo(() => {
    try { addTag(props.value, props.pending, props.options); return ""; }
    catch (cause) { return cause instanceof Error ? cause.message : "Check this tag."; }
  });
  const newTag = () => trimTag(props.pending) && !props.options.some((option) => tagKey(option.tag) === tagKey(trimTag(props.pending)))
    && !props.value.some((tag) => tagKey(tag) === tagKey(trimTag(props.pending)));
  const choices = createMemo(() => [...suggestions().map((option) => option.tag), ...(newTag() && !error() ? [trimTag(props.pending)] : [])]);
  createEffect(() => { props.options; props.pending; props.value; setActive(-1); });
  createEffect(() => { if (active() >= 0) document.getElementById(`${id}-option-${active()}`)?.scrollIntoView({ block: "nearest" }); });

  function commit(text = props.pending): void {
    if (props.disabled) return;
    try {
      props.onChange(addTag(props.value, text, props.options));
      props.onPending("");
      setActive(-1);
    } catch { /* Keep invalid text visible with its field error. */ }
  }

  return (
    <div class="tag-field">
      <label class="field-label" for={id}>Tags <span class="field-optional">Optional</span></label>
      <div class="tag-input-wrap">
        <For each={props.value}>{(tag) => (
          <span class="password-tag tag-edit-chip">
            {tag}
            <button type="button" disabled={props.disabled} aria-label={`Remove tag ${tag}`}
              onClick={() => props.onChange(props.value.filter((value) => tagKey(value) !== tagKey(tag)))}>
              <IconX size={12} />
            </button>
          </span>
        )}</For>
        <input ref={input} id={id} role="combobox" aria-autocomplete="list" aria-expanded={open() && !props.disabled}
          aria-controls={`${id}-options`} aria-activedescendant={open() && active() >= 0 ? `${id}-option-${active()}` : undefined}
          aria-describedby={`${id}-hint${error() ? ` ${id}-error` : ""}`} aria-invalid={!!error()}
          autocomplete="off" placeholder="Add a tag…" disabled={props.disabled} value={props.pending}
          onFocus={() => setOpen(true)}
          onInput={(event) => { props.onPending(event.currentTarget.value); setOpen(true); }}
          onBlur={() => { commit(); setOpen(false); }}
          onKeyDown={(event) => {
            if (event.isComposing) return;
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
              event.preventDefault(); setOpen(true);
              const count = choices().length;
              if (count) setActive((current) => current < 0 ? (event.key === "ArrowDown" ? 0 : count - 1) : (current + (event.key === "ArrowDown" ? 1 : count - 1)) % count);
            } else if (event.key === "Enter") {
              event.preventDefault(); commit(open() && active() >= 0 ? choices()[active()] : props.pending);
            } else if (event.key === "Tab") {
              commit(); setOpen(false);
            }
          }} />
      </div>
      <span id={`${id}-hint`} class="field-message">Type a tag and press Enter. Suggestions come from this vault.</span>
      <Show when={error()}><span id={`${id}-error`} class="field-message is-error" role="alert">{error()}</span></Show>
      <Popover anchor={input} open={open() && !props.disabled} onClose={() => setOpen(false)} matchAnchorWidth class="tag-options" role="group">
        <div id={`${id}-options`} role="listbox" aria-label="Tags in this vault">
          <For each={choices()}>{(tag, index) => (
            <button type="button" role="option" id={`${id}-option-${index()}`} aria-selected={active() === index()} tabIndex={-1}
              classList={{ "tag-option": true, "is-active": active() === index() }}
              onPointerDown={(event) => event.preventDefault()}
              onClick={() => { commit(tag); input?.focus(); }}>
              <span>{newTag() && index() === suggestions().length ? `Add “${tag}”` : tag}</span>
            </button>
          )}</For>
          <Show when={choices().length === 0}><p class="tag-options-empty">{error() ? "Correct the tag to continue." : props.pending ? "This tag is already selected." : "Type to add a tag."}</p></Show>
        </div>
      </Popover>
    </div>
  );
}
