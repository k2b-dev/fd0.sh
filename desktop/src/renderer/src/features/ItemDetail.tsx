import { For, Show, createEffect, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import {
  IconAdjustmentsHorizontal,
  IconArrowRight,
  IconCopy,
  IconDots,
  IconDownload,
  IconCopyPlus,
  IconExternalLink,
  IconEye,
  IconEyeOff,
  IconFolder,
  IconKey,
  IconStar,
  IconTextSize,
  IconTrash,
  IconTransfer,
  IconTerminal2,
} from "@tabler/icons-solidjs";
import type { FieldView, ItemDetail as ItemDetailData, ItemSummary } from "../../../shared/contracts";
import { editability, kindIcon, kindMeta, kindTone, vaultTone } from "../lib/items";
import { absoluteDate, flattenFieldViews, formatBytes, initials, prettyURL, relativeDate } from "../lib/format";
import { useVault } from "../lib/store";
import { IconButton } from "../ui/Button";
import { MenuButton, type MenuSection } from "../ui/Menu";
import { ItemHistory } from "./ItemHistory";

const REVEAL_SECONDS = 15;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

export function ItemDetail(props: {
  onEdit(): void;
  onDuplicate(): void;
  onRename(item: ItemSummary): void;
  onMove(item: ItemSummary): void;
  onOpenItem(item: ItemSummary): void;
  onLargeType(field: FieldView, value: string): void;
}): JSX.Element {
  const vault = useVault();
  const raw = () => vault.filters().type === "secret" && vault.rawSecrets();

  return (
    <article class="detail-panel" aria-label="Item details">
      <Show
        when={vault.detail()?.item.id}
        keyed
        fallback={
          <div class="empty-state detail-empty">
            <span class="empty-glyph">
              <IconKey size={20} strokeWidth={1.6} />
            </span>
            <strong>Select an item</strong>
            <span>Choose an item on the left to see what it stores.</span>
          </div>
        }
      >
        {(_id) => (
          <DetailContent
            detail={vault.detail()!}
            raw={raw()}
            onEdit={props.onEdit}
            onDuplicate={props.onDuplicate}
            onRename={props.onRename}
            onMove={props.onMove}
            onOpenItem={props.onOpenItem}
            onLargeType={props.onLargeType}
          />
        )}
      </Show>
    </article>
  );
}

function DetailContent(props: {
  detail: ItemDetailData;
  raw: boolean;
  onEdit(): void;
  onDuplicate(): void;
  onRename(item: ItemSummary): void;
  onMove(item: ItemSummary): void;
  onOpenItem(item: ItemSummary): void;
  onLargeType(field: FieldView, value: string): void;
}): JSX.Element {
  const vault = useVault();
  const [revealed, setRevealed] = createSignal<Record<string, { value: string; expiresAt: number }>>({});
  const [now, setNow] = createSignal(Date.now());
  let disposed = false;
  onCleanup(() => { disposed = true; });

  const item = () => props.detail.item;
  const allFields = createMemo(() => props.detail.fields.flatMap(flattenFieldViews));

  const sections = createMemo(() => {
    const groups = new Map<string, FieldView[]>();
    for (const field of props.detail.fields) {
      const section = field.section || (props.raw ? "Stored record" : "Details");
      groups.set(section, [...(groups.get(section) ?? []), field]);
    }
    return [...groups.entries()];
  });

  const primaryField = createMemo(() => {
    if (props.raw || item().kind !== "password") return undefined;
    return (
      allFields().find((field) => field.type === "secret" && /^(password|pass|pin)$/i.test(field.name)) ??
      allFields().find((field) => field.type === "secret")
    );
  });

  const websiteField = createMemo(() => allFields().find((field) => field.type === "url" && field.value));
  const edit = createMemo(() => editability(item().kind, item().badge, props.raw));
  const usages = createMemo(() => props.detail.relations?.filter((relation) => relation.kind === "used-by") ?? []);

  function linkedSSHKey(field: FieldView): ItemSummary | undefined {
    if (item().badge !== "SSH HOST" || field.path !== "key" || !field.value) return undefined;
    return vault.inventory().items.find(
      (candidate) =>
        candidate.scopeId === item().scopeId &&
        candidate.recordName === `ssh:${field.value}` &&
        candidate.badge === "SSH KEY",
    );
  }

  // A single ticking clock drives every countdown in the panel.
  createEffect(() => {
    if (Object.keys(revealed()).length === 0) return;
    const timer = setInterval(() => setNow(Date.now()), 250);
    onCleanup(() => clearInterval(timer));
  });

  // Drop reveals whose window has elapsed.
  createEffect(() => {
    const current = now();
    const entries = Object.entries(revealed());
    if (entries.length === 0) return;
    const survivors = entries.filter(([, entry]) => entry.expiresAt > current);
    if (survivors.length !== entries.length) setRevealed(Object.fromEntries(survivors));
  });

  // Refresh the detail shortly after the shortest-lived TOTP rolls over.
  createEffect(() => {
    const remaining = allFields()
      .map((field) => field.remaining ?? 0)
      .filter((value) => value > 0);
    if (remaining.length === 0) return;
    const timer = setTimeout(() => void vault.loadDetail(vault.selectedItem()), Math.min(...remaining) * 1000 + 250);
    onCleanup(() => clearTimeout(timer));
  });

  // The parent remounts on item changes, but keeps this state across focus and
  // TOTP refreshes of the same item. Switching projections still hides values.
  createEffect(() => {
    props.raw;
    setRevealed({});
  });

  const revealedOf = (path: string): string | undefined => revealed()[path]?.value;
  const secondsLeftOf = (path: string): number | undefined => {
    const entry = revealed()[path];
    return entry ? Math.max(0, Math.ceil((entry.expiresAt - now()) / 1000)) : undefined;
  };

  async function toggleReveal(field: FieldView): Promise<void> {
    if (revealed()[field.path]) {
      setRevealed((current) => {
        const next = { ...current };
        delete next[field.path];
        return next;
      });
      return;
    }
    try {
      const result = await window.fd0.reveal({ scopeId: item().scopeId, name: item().recordName, path: field.path });
      if (!result || disposed) return;
      setNow(Date.now());
      setRevealed((current) => ({
        ...current,
        [field.path]: { value: result.value, expiresAt: Date.now() + REVEAL_SECONDS * 1000 },
      }));
    } catch (cause) {
      vault.fail(cause, `fd0 could not reveal ${field.name}`);
    }
  }

  async function largeType(field: FieldView): Promise<void> {
    try {
      const needsReveal = field.sensitive || field.value === undefined;
      const result = needsReveal
        ? await window.fd0.reveal({ scopeId: item().scopeId, name: item().recordName, path: field.path })
        : null;
      const value = field.value ?? result?.value;
      if (!value) return;
      props.onLargeType(field, value);
    } catch (cause) {
      vault.fail(cause, `fd0 could not show ${field.name}`);
    }
  }

  function openSSHHost(): void {
    void window.fd0
      .openSSHHost({ scopeId: item().scopeId, name: item().recordName })
      .then(() => vault.notify("SSH session opened"))
      .catch((cause) =>
        vault.fail(cause, "fd0 could not open that SSH host", {
          label: "Terminal settings",
          run: () => {
            vault.setMainView("settings");
          },
        }),
      );
  }

  function openSSHFiles(): void {
    void window.fd0
      .openSSHFiles({ scopeId: item().scopeId, name: item().recordName })
      .then(() => vault.notify("Remote files opened"))
      .catch((cause) => vault.fail(cause, "fd0 could not open remote files"));
  }

  const menuSections = createMemo<MenuSection[]>(() => {
    const primary = primaryField();
    const website = websiteField();
    return [
      {
        id: "edit",
        items: [
          {
            id: "edit-item",
            label: "Edit item",
            icon: IconAdjustmentsHorizontal,
            disabled: !edit().canEdit,
            disabledReason: edit().reason,
            run: props.onEdit,
          },
          {
            id: "move-item",
            label: "Move to vault…",
            icon: IconTransfer,
            disabled: props.raw || vault.inventory().scopes.length < 2,
            disabledReason: props.raw ? "Raw records cannot be moved here." : "Create another vault first.",
            run: () => props.onMove(item()),
          },
          {
            id: "duplicate-item",
            label: "Duplicate…",
            icon: IconCopyPlus,
            disabled: props.raw || !(
              item().kind === "password" ||
              item().kind === "secret" ||
              (item().kind === "ssh" && item().badge === "SSH HOST")
            ),
            disabledReason:
              item().badge === "SSH KEY"
                ? "Create a new key instead of copying private key material."
                : "Imported configurations are duplicated by importing another file.",
            run: props.onDuplicate,
          },
          ...(item().kind === "kubernetes" || item().kind === "talos"
            ? [{
                id: "rename-item",
                label: "Rename…",
                icon: IconAdjustmentsHorizontal,
                disabled: props.raw,
                disabledReason: "Raw records cannot be renamed here.",
                run: () => props.onRename(item()),
              }]
            : []),
          ...(primary
            ? [
                {
                  id: "large-type",
                  label: `Show ${primary.name} in large type`,
                  icon: IconTextSize,
                  run: () => void largeType(primary),
                },
              ]
            : []),
          ...(website
            ? [
                {
                  id: "open-website",
                  label: "Open website",
                  icon: IconExternalLink,
                  hint: prettyURL(website.value!),
                  run: () => {
                    void window.fd0
                      .openItemURL({ scopeId: item().scopeId, name: item().recordName })
                      .catch((cause) => vault.fail(cause, "fd0 could not open that website"));
                  },
                },
              ]
            : []),
          ...(item().badge === "SSH HOST"
            ? [
                {
                  id: "open-ssh-host",
                  label: "Open in terminal",
                  icon: IconTerminal2,
                  run: openSSHHost,
                },
                {
                  id: "open-ssh-files",
                  label: "Browse files",
                  icon: IconFolder,
                  run: openSSHFiles,
                },
                {
                  id: "copy-ssh-command",
                  label: "Copy SSH command",
                  icon: IconTerminal2,
                  hint: `fd0 ssh connect --scope ${item().vault} ${item().title}`,
                  run: () => {
                    void window.fd0.copyText(
                      `fd0 ssh connect --scope ${shellQuote(item().scopeId)} ${shellQuote(item().title)}`,
                    )
                      .then((result) => vault.notify("SSH command copied — clears in", result.clearAfterSeconds))
                      .catch((cause) => vault.fail(cause, "fd0 could not copy the SSH command"));
                  },
                },
              ]
            : []),
        ],
      },
      {
        id: "danger",
        items: [
          {
            id: "remove",
            label: "Remove item",
            icon: IconTrash,
            danger: true,
            run: () => void vault.removeItem(item()),
          },
        ],
      },
    ];
  });

  return (
    <>
      <header class="detail-header">
        <span classList={{ "detail-avatar": true, [kindTone(item().kind)]: true }} aria-hidden="true">
          <Show when={item().kind === "password"} fallback={<Dynamic component={kindIcon(item().kind)} size={19} strokeWidth={1.7} />}>
            {initials(item().title)}
          </Show>
        </span>
        <div class="detail-title">
          <h1>{item().title}</h1>
          <p>{props.raw ? "Raw stored record" : item().subtitle || kindMeta[item().kind].singular}</p>
        </div>
        <div class="detail-header-actions">
          <Show when={item().badge === "SSH HOST" && !props.raw}>
            <IconButton label="Open in terminal" onClick={openSSHHost}>
              <IconTerminal2 size={17} />
            </IconButton>
            <IconButton label="Browse files" onClick={openSSHFiles}>
              <IconFolder size={17} />
            </IconButton>
          </Show>
          <Show when={item().kind === "password" && !props.raw}>
            <IconButton
              label={item().favorite ? "Remove from favorites" : "Add to favorites"}
              active={item().favorite}
              onClick={() => void vault.toggleFavorite(item())}
            >
              <IconStar size={17} fill={item().favorite ? "currentColor" : "none"} />
            </IconButton>
          </Show>
          <MenuButton label="More actions" sections={menuSections()}>
            <IconDots size={18} />
          </MenuButton>
        </div>
      </header>

      <div classList={{ "detail-body": true, "is-loading": vault.detailLoading() }}>
        <div class="detail-column">
          <For each={sections()}>
            {([section, fields]) => (
              <section class="field-section">
                <h2 class="section-heading">{section}</h2>
                <For each={fields}>
                  {(field) => (
                    <FieldRow
                      field={field}
                      depth={0}
                      revealedOf={revealedOf}
                      secondsLeftOf={secondsLeftOf}
                      linkedItem={linkedSSHKey(field)}
                      allowLargeType={item().kind === "password" && !props.raw}
                      onOpenItem={props.onOpenItem}
                      onReveal={(next) => void toggleReveal(next)}
                      onLargeType={(next) => void largeType(next)}
                      onCopy={(next) =>
                        void vault.copyField({ scopeId: item().scopeId, name: item().recordName, path: next.path }, next.name)
                      }
                      onSaveFile={(next) => {
                        void window.fd0
                          .saveAttachment({ scopeId: item().scopeId, name: item().recordName, path: next.path })
                          .then((result) => vault.notify(result.saved ? "File saved" : "Nothing was saved"))
                          .catch((cause) => vault.fail(cause, `fd0 could not save ${next.name}`));
                      }}
                      onOpenURL={() => {
                        void window.fd0
                          .openItemURL({ scopeId: item().scopeId, name: item().recordName })
                          .catch((cause) => vault.fail(cause, "fd0 could not open that website"));
                      }}
                    />
                  )}
                </For>
              </section>
            )}
          </For>

          <Show when={usages().length > 0}>
            <section class="field-section relation-section">
              <h2 class="section-heading">Used by {usages().length === 1 ? "1 server" : `${usages().length} servers`}</h2>
              <div class="relation-list">
                <For each={usages()}>
                  {(relation) => (
                    <button class="relation-row" type="button" onClick={() => props.onOpenItem(relation.item)}>
                      <span>
                        <strong>{relation.item.title}</strong>
                        <small>{relation.item.subtitle}</small>
                      </span>
                      <span>Open</span>
                    </button>
                  )}
                </For>
              </div>
            </section>
          </Show>

          {/* Raw mode projects arbitrary records, so there is no single item
              whose history would be meaningful. */}
          <Show when={!props.raw}>
            <ItemHistory item={item()} />
          </Show>

          <footer class="detail-meta">
            <span class="vault-pill">
              <span classList={{ "vault-dot": true, [vaultTone(item().scopeId)]: true }} aria-hidden="true" />
              {item().vault}
            </span>
            <Show when={item().updatedAt} fallback={<span class="detail-meta-muted">No change recorded</span>}>
              {(updated) => (
                <span title={absoluteDate(updated())}>Updated {relativeDate(updated())}</span>
              )}
            </Show>
          </footer>
        </div>
      </div>
    </>
  );
}

function FieldRow(props: {
  field: FieldView;
  depth: number;
  linkedItem?: ItemSummary;
  revealedOf(path: string): string | undefined;
  secondsLeftOf(path: string): number | undefined;
  allowLargeType: boolean;
  onOpenItem(item: ItemSummary): void;
  onReveal(field: FieldView): void;
  onCopy(field: FieldView): void;
  onLargeType(field: FieldView): void;
  onSaveFile(field: FieldView): void;
  onOpenURL(field: FieldView): void;
}): JSX.Element {
  const isTOTP = () => props.field.type === "totp";
  const isNotes = () => props.field.type === "notes";
  const revealed = () => props.revealedOf(props.field.path);
  const secondsLeft = () => props.secondsLeftOf(props.field.path);
  const shown = () => {
    if (revealed() !== undefined) return revealed()!;
    if (props.field.sensitive) return "••••••••••••";
    return props.field.value || "Not set";
  };

  return (
    <>
      <Show when={isNotes()}>
        <div class="notes-block">
          <p class="notes-text">{props.field.value}</p>
          <span class="field-actions">
            <IconButton label="Copy notes" size="sm" onClick={() => props.onCopy(props.field)}>
              <IconCopy size={15} />
            </IconButton>
          </span>
        </div>
      </Show>

      <div classList={{ "field-row": true, "is-nested": props.depth > 0 }} style={isNotes() ? { display: "none" } : undefined}>
        <span class="field-name">{props.field.name}</span>

        <span class="field-value-slot">
          <Show
            when={props.field.file}
            fallback={
              <Show
                when={props.linkedItem}
                fallback={
                  <Show
                    when={props.field.type === "url" && props.field.value}
                    fallback={
                      <span
                        classList={{
                          "field-value": true,
                          "is-secret": props.field.sensitive && revealed() === undefined,
                          "is-revealed": revealed() !== undefined,
                          "is-totp": isTOTP(),
                          "is-unset": !props.field.value && !props.field.sensitive,
                        }}
                      >
                        {shown()}
                      </span>
                    }
                  >
                    <button class="link-value" type="button" onClick={() => props.onOpenURL(props.field)}>
                      {prettyURL(props.field.value!)}
                      <IconExternalLink size={13} />
                    </button>
                  </Show>
                }
              >
                {(linked) => (
                  <button
                    class="link-value"
                    type="button"
                    aria-label={`Open SSH key ${linked().title}`}
                    onClick={() => props.onOpenItem(linked())}
                  >
                    {shown()}
                    <IconArrowRight size={13} />
                  </button>
                )}
              </Show>
            }
          >
            {(file) => (
              <span class="file-value">
                {file().name}
                <small>{formatBytes(file().size)}</small>
              </span>
            )}
          </Show>

          {/* Countdowns replace silent timers: reveals used to simply flip back
              after 15s and TOTP codes rolled over with no warning. */}
          <Show when={secondsLeft() !== undefined}>
            <span class="field-countdown" aria-live="off">
              hides in {secondsLeft()}s
            </span>
          </Show>
          <Show when={isTOTP() && props.field.remaining}>
            <span classList={{ "field-countdown": true, "is-urgent": (props.field.remaining ?? 0) <= 5 }}>
              {props.field.remaining}s
            </span>
          </Show>
        </span>

        <span class="field-actions">
          <Show when={props.field.file}>
            <IconButton label={`Save ${props.field.name}`} size="sm" onClick={() => props.onSaveFile(props.field)}>
              <IconDownload size={15} />
            </IconButton>
          </Show>
          <Show when={props.allowLargeType && ["text", "secret", "totp"].includes(props.field.type)}>
            <IconButton label={`Show ${props.field.name} in large type`} size="sm" onClick={() => props.onLargeType(props.field)}>
              <IconTextSize size={15} />
            </IconButton>
          </Show>
          <Show when={props.field.sensitive}>
            <IconButton
              label={`${revealed() !== undefined ? "Hide" : "Reveal"} ${props.field.name}`}
              size="sm"
              onClick={() => props.onReveal(props.field)}
            >
              {revealed() !== undefined ? <IconEyeOff size={15} /> : <IconEye size={15} />}
            </IconButton>
          </Show>
          <Show when={props.field.copyable}>
            <IconButton label={`Copy ${props.field.name}`} size="sm" onClick={() => props.onCopy(props.field)}>
              <IconCopy size={15} />
            </IconButton>
          </Show>
        </span>
      </div>

      <Show when={props.field.children?.length}>
        <div class="field-children">
          <For each={props.field.children}>
            {(child) => (
              <FieldRow
                field={child}
                depth={props.depth + 1}
                linkedItem={undefined}
                revealedOf={props.revealedOf}
                secondsLeftOf={props.secondsLeftOf}
                allowLargeType={props.allowLargeType}
                onOpenItem={props.onOpenItem}
                onReveal={props.onReveal}
                onCopy={props.onCopy}
                onLargeType={props.onLargeType}
                onSaveFile={props.onSaveFile}
                onOpenURL={props.onOpenURL}
              />
            )}
          </For>
        </div>
      </Show>
    </>
  );
}
