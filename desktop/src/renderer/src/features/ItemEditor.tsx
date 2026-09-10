import { For, Show, createMemo, createSignal, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import { IconChevronRight, IconFileImport, IconKey } from "@tabler/icons-solidjs";
import type { PassField, RecordRef, SavePassInput, ScopeSummary } from "../../../shared/contracts";
import { toAppError } from "../lib/errors";
import { itemKinds, type EditorKind } from "../lib/editorKinds";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Field, Input, Select, Textarea } from "../ui/Fields";
import { Modal } from "../ui/Modal";
import { MAX_FIELDS, PasswordCards } from "./PasswordCards";
import { readNotes, withoutNotes, writeNotes } from "../lib/notes";
import { TagInput } from "./TagInput";
import { addTag, tagCatalog } from "../lib/tags";
import { SSHKeyPicker } from "./SSHKeyPicker";

/**
 * Everything the editor needs to create or update one item.
 *
 * Create and edit share this shape so there is a single editor rather than two
 * modals that drift apart. `recordName` is absent only when creating.
 */
export type ItemDraft = {
  kind: EditorKind;
  scopeId: string;
  recordName?: string;
  authorization?: string;
  title: string;
  /**
   * Every website on the item, not just the first.
   *
   * The vault stores an unbounded list and the editor lets you add rows, so
   * collapsing this to a single string here silently destroyed every URL but
   * the first on the next save.
   */
  urls: string[];
  tags: string[];
  /** Password items only. Arbitrary, nestable fields. */
  fields: PassField[];
  /** Secret items only. */
  value: string;
  /** SSH host items only. */
  host: { hostname: string; user: string; port: number; keyName: string; jumpHost: string; notes: string };
  /** SSH key items only. */
  comment: string;
};

export function emptyDraft(kind: EditorKind, scopeId: string, initialPassword = ""): ItemDraft {
  const fields: PassField[] =
    kind === "password"
      ? [
          { type: "text", name: "username", value: "" },
          { type: "secret", name: "password", value: initialPassword },
        ]
      : [];
  return {
    kind,
    scopeId,
    title: "",
    urls: [],
    tags: [],
    fields,
    value: "",
    host: { hostname: "", user: "", port: 22, keyName: "", jumpHost: "", notes: "" },
    comment: "",
  };
}

/** A small first step: pick what you are adding, then edit it in full. */
export function ItemTypePicker(props: { onPick(kind: EditorKind): void; onClose(): void }): JSX.Element {
  return (
    <Modal title="What do you want to add?" size="small" onClose={props.onClose}>
      <div class="type-choice-list">
        <For each={itemKinds}>
          {(option) => (
            <button class="type-choice" type="button" onClick={() => props.onPick(option.id)}>
              <span classList={{ "type-choice-glyph": true, [option.tone]: true }} aria-hidden="true">
                <Dynamic component={option.icon} size={18} strokeWidth={1.7} />
              </span>
              <span class="type-choice-copy">
                <strong>{option.label}</strong>
                <small>{option.description}</small>
              </span>
              <IconChevronRight size={15} aria-hidden="true" />
            </button>
          )}
        </For>
      </div>
    </Modal>
  );
}

export function ItemEditor(props: {
  draft: ItemDraft;
  scopes: ScopeSummary[];
  onClose(): void;
  onSaved(ref?: RecordRef): Promise<void>;
}): JSX.Element {
  const vault = useVault();
  const isCreate = () => !props.draft.recordName;

  const [scopeID, setScopeID] = createSignal(props.draft.scopeId);
  const [title, setTitle] = createSignal(props.draft.title);
  const [urls, setURLs] = createSignal<string[]>([...props.draft.urls]);
  const [tags, setTags] = createSignal([...props.draft.tags]);
  const [pendingTag, setPendingTag] = createSignal("");
  const tagOptions = createMemo(() => scopeID() ? tagCatalog(vault.inventory().items, scopeID()) : []);
  // The reserved note is edited on its own and folded back in on save, so the
  // field tree never shows it as one more ordinary row.
  const [fields, setFields] = createSignal<PassField[]>(withoutNotes(structuredClone(props.draft.fields)));
  const [notes, setNotes] = createSignal(readNotes(props.draft.fields));
  const [value, setValue] = createSignal(props.draft.value);
  const [host, setHost] = createSignal({ ...props.draft.host });
  const [comment, setComment] = createSignal(props.draft.comment);
  const [keyPickerOpen, setKeyPickerOpen] = createSignal(false);
  const [savedRefs, setSavedRefs] = createSignal<RecordRef[]>([]);
  const [busy, setBusy] = createSignal(false);
  const [invalid, setInvalid] = createSignal<Set<string>>(new Set());

  const meta = createMemo(() => itemKinds.find((option) => option.id === props.draft.kind)!);
  const imports = () => props.draft.kind === "kubernetes" || props.draft.kind === "talos";
  const isPassword = () => props.draft.kind === "password";
  const tagCaseSensitive = () => ["ssh", "kubernetes", "talos"].includes(props.draft.kind);

  const original = JSON.stringify({
    tags: props.draft.tags,
    title: props.draft.title,
    urls: [...props.draft.urls],
    fields: withoutNotes(props.draft.fields),
    notes: readNotes(props.draft.fields),
    value: props.draft.value,
    host: props.draft.host,
    comment: props.draft.comment,
  });
  const dirty = (): boolean =>
    !!pendingTag() || scopeID() !== props.draft.scopeId || JSON.stringify({ tags: tags(), title: title(), urls: urls(), fields: fields(), notes: notes(), value: value(), host: host(), comment: comment() }) !== original;

  const titleLabel = () => (props.draft.kind === "password" ? "Title" : "Name");

  const canSave = createMemo(() => {
    if (!scopeID()) return false;
    try { addTag(tags(), pendingTag(), tagOptions(), tagCaseSensitive(), props.draft.kind === "ssh"); } catch { return false; }
    if (imports()) return true;
    if (!title().trim()) return false;
    if (invalid().size > 0) return false;
    if (props.draft.kind === "secret" && !value()) return false;
    if (props.draft.kind === "ssh" && !host().hostname.trim()) return false;
    return true;
  });

  function setValidity(id: string, valid: boolean): void {
    setInvalid((current) => {
      const next = new Set(current);
      if (valid) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function persist(): Promise<RecordRef | undefined> {
    const name = title().trim();
    const scope = scopeID();

    switch (props.draft.kind) {
      case "password": {
        const nextTags = addTag(tags(), pendingTag(), tagOptions());
        setTags(nextTags);
        setPendingTag("");
        const tagsChanged = isCreate() || JSON.stringify(nextTags) !== JSON.stringify(props.draft.tags);
        const input: SavePassInput = {
          scopeId: scope,
          recordName: props.draft.recordName ?? name,
          create: isCreate(),
          authorization: props.draft.authorization,
          item: {
            title: name,
            urls: urls().map((entry) => entry.trim()).filter(Boolean),
            fields: writeNotes(fields(), notes()),
            ...(tagsChanged ? { meta: { tags: nextTags } } : {}),
          },
        };
        await window.fd0.savePass(input);
        return { scopeId: scope, name: `pass:${name}` };
      }
      case "secret": {
        await window.fd0.saveSecret({
          scopeId: scope,
          name,
          value: value(),
          oldName: props.draft.recordName,
          create: isCreate(),
          authorization: props.draft.authorization,
        });
        return { scopeId: scope, name };
      }
      case "ssh": {
        const current = host();
        await window.fd0.saveSSHHost({
          scopeId: scope,
          oldName: props.draft.recordName,
          authorization: props.draft.authorization,
          host: {
            Alias: name,
            Tags: addTag(tags(), pendingTag(), tagOptions(), true),
            Hostname: current.hostname.trim(),
            User: current.user.trim(),
            Port: current.port,
            KeyName: current.keyName.trim(),
            ProxyJump: current.jumpHost.trim(),
            Description: current.notes.trim(),
          },
        });
        return { scopeId: scope, name: `host:${name}` };
      }
      case "ssh-key": {
        if (isCreate()) {
          await window.fd0.generateSSHKey({ scopeId: scope, name, comment: comment().trim() });
        } else {
          await window.fd0.saveSSHKey({
            scopeId: scope,
            name,
            comment: comment().trim(),
            authorization: props.draft.authorization,
          });
        }
        return { scopeId: scope, name: `ssh:${name}` };
      }
      default: {
        const kind = props.draft.kind === "kubernetes" ? "kubernetes" : "talos";
        const imported = await window.fd0.importConfig(kind, scope);
        if (!imported) {
          vault.notify("Import cancelled");
          return undefined;
        }
        if (!imported.imported[0]) {
          vault.warn("Nothing was imported", "That file did not contain anything fd0 can read.");
          return undefined;
        }
        vault.notify(
          imported.imported.length === 1 ? `Imported ${imported.imported[0]}` : `Imported ${imported.imported.length} entries`,
        );
        setSavedRefs(imported.imported.map(name => ({ scopeId: scope, name: `${kind === "kubernetes" ? "kube" : "talos"}:${name}` })));
        return savedRefs()[0];
      }
    }
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!canSave()) return;
    setBusy(true);
    try {
      const nextTags = addTag(tags(), pendingTag(), tagOptions(), tagCaseSensitive(), props.draft.kind === "ssh");
      const saved = savedRefs()[0] ?? await persist();
      if (saved && !savedRefs().length) setSavedRefs([saved]);
      if (saved && !isPassword() && (isCreate() || JSON.stringify(nextTags) !== JSON.stringify(props.draft.tags))) {
        for (const ref of savedRefs()) await window.fd0.setItemTags(ref, nextTags);
      }
      if (saved || !imports()) await props.onSaved(saved);
    } catch (cause) {
      vault.pushError(toAppError(cause, `fd0 could not save ${title().trim() || "this item"}`));
    } finally {
      setBusy(false);
    }
  }

  const saveLabel = () => {
    if (savedRefs().length && !busy()) return "Retry saving tags";
    if (busy()) return imports() ? "Importing…" : "Saving…";
    if (imports()) return "Choose file…";
    return isCreate() ? "Create item" : "Save changes";
  };

  return (
    <Modal
      title={isCreate() ? `New ${meta().label.toLowerCase()}` : title() || `Edit ${meta().label.toLowerCase()}`}
      description={meta().description}
      size={isPassword() ? "wide" : "default"}
      dirty={dirty()}
      onClose={props.onClose}
      footer={
        <div class="editor-footer">
          <Show when={isCreate()}>
            <div class="editor-footer-vault">
              <span class="editor-footer-label">Vault</span>
              <Select
                label="Vault"
                value={scopeID()}
                onChange={setScopeID}
                options={props.scopes.map((scope) => ({ value: scope.id, label: scope.label }))}
              />
            </div>
          </Show>
          <div class="editor-footer-actions">
            <Button onClick={props.onClose}>Cancel</Button>
            <Button variant="primary" type="submit" form="item-editor-form" disabled={busy() || !canSave()}>
              {saveLabel()}
            </Button>
          </div>
        </div>
      }
    >
      <Show when={savedRefs().length}><p role="status">Item content is saved. Retry to finish saving tags, or close and edit tags later.</p></Show>
      <form id="item-editor-form" class="field-stack item-editor-form" onSubmit={save}>
      <fieldset class="item-editor-fields" disabled={busy() || savedRefs().length > 0}>
        <Show when={!imports()}>
          <div classList={{ "form-grid": true, "is-single": true }}>
            <Field
              label={titleLabel()}
              hint={props.draft.kind === "ssh-key" && !isCreate() ? "A key’s name stays fixed so server assignments cannot break." : undefined}
            >
              {(field) => (
                <Show
                  when={props.draft.kind === "ssh-key" && !isCreate()}
                  fallback={
                    <Input
                      id={field.id}
                      autofocus
                      required
                      placeholder={`Enter ${titleLabel().toLowerCase()}`}
                      value={title()}
                      onInput={(event) => setTitle(event.currentTarget.value)}
                    />
                  }
                >
                  <Input id={field.id} class="ssh-key-fixed-name" readOnly value={title()} />
                </Show>
              )}
            </Field>
          </div>
        </Show>

        <TagInput value={tags()} pending={pendingTag()} options={tagOptions()} caseSensitive={tagCaseSensitive()} rejectCommas={props.draft.kind === "ssh"} disabled={busy() || savedRefs().length > 0} onChange={setTags} onPending={setPendingTag} />
        <Show when={isPassword()}>
          <PasswordCards
            fields={fields()}
            urls={urls()}
            notes={notes()}
            onFields={setFields}
            onURLs={setURLs}
            onNotes={setNotes}
            onError={(message) => vault.warn(message)}
            onValidity={setValidity}
          />
        </Show>

        <Show when={props.draft.kind === "secret"}>
          <Field label="Value">
            {(field) => (
              <Textarea
                id={field.id}
                required
                rows={6}
                spellcheck={false}
                value={value()}
                onInput={(event) => setValue(event.currentTarget.value)}
              />
            )}
          </Field>
        </Show>

        <Show when={props.draft.kind === "ssh"}>
          <div class="form-grid">
            <div class="form-grid-full">
              <Field label="Address">
                {(field) => (
                  <Input
                    id={field.id}
                    required
                    placeholder="server.example.com"
                    value={host().hostname}
                    onInput={(event) => setHost({ ...host(), hostname: event.currentTarget.value })}
                  />
                )}
              </Field>
            </div>
            <Field label="User" optional>
              {(field) => (
                <Input
                  id={field.id}
                  autocomplete="username"
                  value={host().user}
                  onInput={(event) => setHost({ ...host(), user: event.currentTarget.value })}
                />
              )}
            </Field>
            <Field label="Port">
              {(field) => (
                <Input
                  id={field.id}
                  type="number"
                  min="1"
                  max="65535"
                  value={host().port}
                  onInput={(event) => setHost({ ...host(), port: Number(event.currentTarget.value) })}
                />
              )}
            </Field>
            <Field label="Key" optional hint="Choose a key from this server’s vault.">
              {(field) => (
                <button
                  id={field.id}
                  class="ssh-key-select"
                  type="button"
                  aria-label={`SSH key: ${host().keyName || "No fd0 key"}`}
                  onClick={() => setKeyPickerOpen(true)}
                >
                  <span class="ssh-key-select-glyph" aria-hidden="true">
                    <IconKey size={15} />
                  </span>
                  <span class="ssh-key-select-copy">
                    <strong>{host().keyName || "No fd0 key"}</strong>
                  </span>
                  <span class="ssh-key-select-action">Choose…</span>
                </button>
              )}
            </Field>
            <Field label="Connect through" optional hint="Another server to route through.">
              {(field) => (
                <Input
                  id={field.id}
                  value={host().jumpHost}
                  onInput={(event) => setHost({ ...host(), jumpHost: event.currentTarget.value })}
                />
              )}
            </Field>
            <div class="form-grid-full">
              <Field label="Notes" optional>
                {(field) => (
                  <Textarea
                    id={field.id}
                    rows={3}
                    value={host().notes}
                    onInput={(event) => setHost({ ...host(), notes: event.currentTarget.value })}
                  />
                )}
              </Field>
            </div>
          </div>
        </Show>

        <Show when={props.draft.kind === "ssh-key"}>
          <Field label="Comment" optional hint="Helps you recognise this key on a server.">
            {(field) => (
              <Input
                id={field.id}
                placeholder="you@example.com"
                value={comment()}
                onInput={(event) => setComment(event.currentTarget.value)}
              />
            )}
          </Field>
        </Show>

        <Show when={imports()}>
          <div class="callout">
            <IconFileImport size={19} aria-hidden="true" />
            <div>
              <strong>{props.draft.kind === "kubernetes" ? "Choose a kubeconfig file" : "Choose a talosconfig file"}</strong>
              <p>fd0 reads what it recognises and keeps every credential encrypted in the vault you picked.</p>
            </div>
          </div>
        </Show>

        <Show when={isPassword() && fields().length >= MAX_FIELDS}>
          <p class="field-message is-error" role="alert">
            This item has reached the {MAX_FIELDS} field limit.
          </p>
        </Show>
      </fieldset>
      </form>

      <Show when={keyPickerOpen()}>
        <SSHKeyPicker
          scopeId={scopeID()}
          current={host().keyName}
          onSelect={(key) => setHost({ ...host(), keyName: key?.name ?? "" })}
          onClose={() => setKeyPickerOpen(false)}
        />
      </Show>
    </Modal>
  );
}
