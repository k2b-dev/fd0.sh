import { For, Show, createMemo, createSignal, onMount, type JSX } from "solid-js";
import { IconArrowLeft, IconCopy, IconLogout, IconShieldCheck, IconUserMinus, IconUserPlus } from "@tabler/icons-solidjs";
import type { IdentityCardInfo, ScopeRole, ScopeShareInfo, ScopeSummary, TrustedContact } from "../../../shared/contracts";
import { errorText } from "../lib/errors";
import { initials, plural } from "../lib/format";
import { Button, IconButton } from "../ui/Button";
import { Field, Input, Select, Textarea } from "../ui/Fields";
import { Modal } from "../ui/Modal";

/**
 * Vault access, told as "who can open this" rather than as a key exchange.
 *
 * The cryptography is unchanged: fd0 still exports a signed card, still pins on
 * first contact, and still requires the safety number to be compared out of
 * band. What changed is that a person is identified by their name and trust
 * state, and the fingerprint only appears inside the verification step where it
 * is the thing actually being checked.
 */
export function ShareVaultModal(props: {
  scope: ScopeSummary;
  onClose(): void;
  onChanged(): Promise<void>;
  onNotify(message: string): void;
}): JSX.Element {
  const [mode, setMode] = createSignal<"access" | "new-contact">("access");
  const [info, setInfo] = createSignal<ScopeShareInfo>({ scopeLabel: props.scope.label, contacts: [], members: [], selfRole: "reader" });
  const [newRole, setNewRole] = createSignal<ScopeRole>("admin");
  const [ownCard, setOwnCard] = createSignal<IdentityCardInfo | null>(null);
  const [cardURL, setCardURL] = createSignal("");
  const [contactLabel, setContactLabel] = createSignal("");
  const [cardPreview, setCardPreview] = createSignal<IdentityCardInfo | null>(null);
  const [reviewedURL, setReviewedURL] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const [vaultName, setVaultName] = createSignal(props.scope.label);

  const available = createMemo(() => info().contacts.filter((contact) => !contact.shared));
  const isAdmin = createMemo(() => info().selfRole === "admin");
  const canTrust = createMemo(() => Boolean(cardPreview() && reviewedURL() === cardURL().trim() && contactLabel().trim()));
  const isNewContact = (): boolean => mode() === "new-contact";

  async function loadInfo(showLoading = true): Promise<void> {
    if (showLoading) setLoading(true);
    try {
      setInfo(await window.fd0.scopeShareInfo(props.scope.id));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  onMount(() => void loadInfo());

  async function finishMembershipChange(message: string): Promise<void> {
    let syncError = "";
    if (!window.fd0.development) {
      try {
        await window.fd0.sync();
      } catch (cause) {
        syncError = `The change is saved on this device, but it could not reach your other devices yet. ${errorText(cause)}`;
      }
    }
    await loadInfo(false);
    await props.onChanged();
    props.onNotify(message);
    if (syncError) setError(syncError);
  }

  async function shareContact(contact: TrustedContact): Promise<void> {
    setBusy(`add:${contact.label}`);
    setError("");
    try {
      const added = await window.fd0.addScopeMember(props.scope.id, contact.label, newRole());
      if (!added.ok) return;
      await finishMembershipChange(`${contact.label} can now open ${props.scope.label} as ${newRole()}`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function removeMember(memberID: string, label: string): Promise<void> {
    setBusy(`remove:${memberID}`);
    setError("");
    try {
      const result = await window.fd0.removeScopeMember(props.scope.id, memberID);
      if (!result.ok) {
        props.onNotify("Nothing was changed");
        return;
      }
      await finishMembershipChange(`${label} no longer has access to ${props.scope.label}`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function changeRole(memberID: string, label: string, role: ScopeRole): Promise<void> {
    setBusy(`role:${memberID}`);
    setError("");
    try {
      const result = await window.fd0.setScopeMemberRole(props.scope.id, memberID, role);
      if (!result.ok) {
        await loadInfo(false);
        return;
      }
      await finishMembershipChange(`${label} is now ${role} in ${props.scope.label}`);
    } catch (cause) {
      setError(errorText(cause));
      await loadInfo(false);
    } finally {
      setBusy("");
    }
  }

  async function renameVault(): Promise<void> {
    const label = vaultName().trim();
    if (!label || label === info().scopeLabel) return;
    setBusy("rename-vault");
    setError("");
    try {
      await window.fd0.renameScope(props.scope.id, label);
      setInfo((current) => ({ ...current, scopeLabel: label }));
      await finishMembershipChange(`Vault renamed to ${label}`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function leaveVault(): Promise<void> {
    setBusy("leave-vault");
    setError("");
    try {
      const result = await window.fd0.leaveScope(props.scope.id);
      if (!result.ok) return;
      if (!result.hidden && !window.fd0.development) await window.fd0.sync();
      await props.onChanged();
      props.onNotify(result.hidden ? `${info().scopeLabel} hidden on this device` : `Left ${info().scopeLabel}`);
      props.onClose();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function copyOwnCard(): Promise<void> {
    setBusy("own-card");
    setError("");
    try {
      const card = ownCard() ?? (await window.fd0.exportIdentityCard());
      setOwnCard(card);
      if (!card.url) throw new Error("fd0 could not prepare your invite.");
      await window.fd0.copyText(card.url);
      props.onNotify(`Invite copied. It stops working ${formatExpiry(card.expiresAt)}.`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function reviewCard(): Promise<void> {
    const url = cardURL().trim();
    if (!url) return;
    setBusy("review-card");
    setError("");
    try {
      const preview = await window.fd0.inspectIdentityCard(url);
      setCardPreview(preview);
      setReviewedURL(url);
      if (!contactLabel().trim()) setContactLabel(preview.shortId);
    } catch (cause) {
      setCardPreview(null);
      setReviewedURL("");
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  async function trustAndShare(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const label = contactLabel().trim();
    const url = cardURL().trim();
    if (!canTrust()) return;
    setBusy("import-card");
    setError("");
    try {
      const imported = await window.fd0.importIdentityCard(url, label);
      if (!imported.ok) {
        props.onNotify("Nothing was added");
        return;
      }
      const added = await window.fd0.addScopeMember(props.scope.id, label, newRole());
      if (!added.ok) return;
      await finishMembershipChange(`${label} can now open ${props.scope.label} as ${newRole()}`);
      setMode("access");
      setCardURL("");
      setContactLabel("");
      setCardPreview(null);
      setReviewedURL("");
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy("");
    }
  }

  return (
    <Modal
      title={isNewContact() ? "Add someone new" : `Manage ${info().scopeLabel}`}
      description={
        isNewContact()
          ? "Swap invites, then check the security code together so you both know it is really them."
          : "Everyone here can open every item in this vault, now and in the future."
      }
      dirty={isNewContact() && Boolean(cardURL() || contactLabel())}
      onClose={props.onClose}
      headerActions={
        <Show when={isNewContact()}>
          <IconButton
            label="Back to vault access"
            onClick={() => {
              setMode("access");
              setError("");
            }}
          >
            <IconArrowLeft size={17} />
          </IconButton>
        </Show>
      }
      footer={
        <Show
          when={isNewContact()}
          fallback={
            <>
              <Button disabled={busy() === "own-card"} onClick={() => void copyOwnCard()}>
                <IconCopy size={15} />
                {busy() === "own-card" ? "Preparing…" : "Copy my invite"}
              </Button>
              <Button variant="primary" onClick={props.onClose}>
                Done
              </Button>
            </>
          }
        >
          <>
            <Button
              onClick={() => {
                setMode("access");
                setError("");
              }}
            >
              Cancel
            </Button>
            <Button variant="primary" type="submit" form="share-form" disabled={!canTrust() || busy() === "import-card"}>
              {busy() === "import-card" ? "Sharing…" : "Confirm and share"}
            </Button>
          </>
        </Show>
      }
    >
      <Show when={error()}>
        <p class="inline-error" role="alert">
          {error()}
        </p>
      </Show>

      <Show
        when={isNewContact()}
        fallback={
          <Show when={!loading()} fallback={<p class="share-loading">Loading…</p>}>
            <section class="share-section">
              <div class="share-section-heading">
                <div>
                  <strong>People with access</strong>
                  <small>{plural(info().members.length, "person", "people")}</small>
                </div>
              </div>
              <div class="access-list">
                <For each={info().members}>
                  {(member) => (
                    <div class="access-row">
                      <span class="access-avatar tone-password" aria-hidden="true">
                        {initials(member.label)}
                      </span>
                      <span class="access-person">
                        <strong>{member.self ? "You" : member.label}</strong>
                        <small classList={{ "is-verified": Boolean(member.trusted) && !member.self }}>
                          {member.self
                            ? `${roleLabels[member.role]} · this device`
                            : member.trusted
                              ? `${roleLabels[member.role]} · identity confirmed`
                              : `${roleLabels[member.role]} · added before you saved them as a contact`}
                        </small>
                      </span>
                      <Show when={isAdmin() && !member.self}>
                        <Select
                          class="access-role-select"
                          label={`Role of ${member.label}`}
                          value={member.role}
                          options={roleOptions}
                          disabled={busy() === `role:${member.id}`}
                          onChange={(value) => void changeRole(member.id, member.label, value as ScopeRole)}
                        />
                      </Show>
                      <Show when={isAdmin() && !member.self}>
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={busy() === `remove:${member.id}`}
                          onClick={() => void removeMember(member.id, member.label)}
                        >
                          <IconUserMinus size={14} />
                          {busy() === `remove:${member.id}` ? "Removing…" : "Remove"}
                        </Button>
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            </section>

            <Show when={!isAdmin()}>
              <p class="share-loading">You are {roleLabels[info().selfRole].toLowerCase()} in this vault. Only admins can change who has access.</p>
            </Show>
            <Show when={isAdmin()}>
            <section class="share-section">
              <div class="share-section-heading">
                <div>
                  <strong>People you know</strong>
                  <small>Anyone whose identity you have already confirmed.</small>
                </div>
                <Select label="Role for people you add" value={newRole()} options={roleOptions} onChange={(value) => setNewRole(value as ScopeRole)} />
                <Button
                  size="sm"
                  onClick={() => {
                    setMode("new-contact");
                    setError("");
                  }}
                >
                  <IconUserPlus size={14} />
                  Add someone
                </Button>
              </div>
              <Show
                when={available().length > 0}
                fallback={
                  <div class="share-empty">
                    <strong>Nobody left to add</strong>
                    <span>Everyone you know already has access to this vault.</span>
                  </div>
                }
              >
                <div class="access-list">
                  <For each={available()}>
                    {(contact) => (
                      <div class="access-row">
                        <span class="access-avatar tone-secret" aria-hidden="true">
                          {initials(contact.label)}
                        </span>
                        <span class="access-person">
                          <strong>{contact.label}</strong>
                          <small class="is-verified">Identity confirmed</small>
                        </span>
                        <Button size="sm" disabled={busy() === `add:${contact.label}`} onClick={() => void shareContact(contact)}>
                          <IconUserPlus size={14} />
                          {busy() === `add:${contact.label}` ? "Adding…" : "Give access"}
                        </Button>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </section>

            </Show>

            <section class="share-section">
              <div class="share-section-heading">
                <div>
                  <strong>Vault settings</strong>
                  <small>The name is shared with every member.</small>
                </div>
              </div>
              <Show when={info().selfRole !== "reader"}>
              <div class="vault-settings-row">
                <Input
                  aria-label="Vault name"
                  value={vaultName()}
                  onInput={(event) => setVaultName(event.currentTarget.value)}
                />
                <Button
                  size="sm"
                  disabled={!vaultName().trim() || vaultName().trim() === info().scopeLabel || busy() === "rename-vault"}
                  onClick={() => void renameVault()}
                >
                  {busy() === "rename-vault" ? "Renaming…" : "Rename"}
                </Button>
              </div>
              </Show>
              <div class="vault-danger-row">
                <span>
                  <strong>{isAdmin() ? "Leave this vault" : "Hide this vault"}</strong>
                  <small>{isAdmin()
                    ? "Its items disappear from this device after the change syncs."
                    : "Its items disappear from this device. You stay a member until an admin removes you."}</small>
                </span>
                <Button
                  size="sm"
                  variant="danger"
                  disabled={busy() === "leave-vault"}
                  onClick={() => void leaveVault()}
                >
                  <IconLogout size={14} />
                  {busy() === "leave-vault" ? (isAdmin() ? "Leaving…" : "Hiding…") : (isAdmin() ? "Leave…" : "Hide…")}
                </Button>
              </div>
            </section>
          </Show>
        }
      >
        <form id="share-form" class="new-contact-fields" onSubmit={trustAndShare}>
          <section class="share-section">
            <div class="share-section-heading">
              <div>
                <strong>1 · Send them your invite</strong>
                <small>They paste it into their copy of fd0. Invites stop working after 24 hours.</small>
              </div>
              <Button size="sm" disabled={busy() === "own-card"} onClick={() => void copyOwnCard()}>
                <IconCopy size={14} />
                {busy() === "own-card" ? "Preparing…" : "Copy my invite"}
              </Button>
            </div>
          </section>

          <section class="share-section">
            <div class="share-section-heading">
              <div>
                <strong>2 · Paste their invite</strong>
                <small>Then check the security code with them on a call or in person.</small>
              </div>
            </div>

            <Field label="Their invite">
              {(field) => (
                <Textarea
                  id={field.id}
                  required
                  rows={3}
                  spellcheck={false}
                  placeholder="fd0://card/…"
                  value={cardURL()}
                  onInput={(event) => {
                    setCardURL(event.currentTarget.value);
                    setCardPreview(null);
                    setReviewedURL("");
                  }}
                />
              )}
            </Field>

            <Field label="What should fd0 call them?">
              {(field) => (
                <Input
                  id={field.id}
                  required
                  maxlength="80"
                  placeholder="Benny"
                  value={contactLabel()}
                  onInput={(event) => setContactLabel(event.currentTarget.value)}
                />
              )}
            </Field>

            <Button disabled={!cardURL().trim() || busy() === "review-card"} onClick={() => void reviewCard()}>
              <IconShieldCheck size={15} />
              {busy() === "review-card" ? "Checking…" : "Check this invite"}
            </Button>

            <Show when={cardPreview()}>
              {(preview) => (
                <div class="callout callout-warn" role="status">
                  <IconShieldCheck size={17} aria-hidden="true" />
                  <div>
                    <strong>Read this code out to them</strong>
                    <p>You must both see exactly the same code. If it differs, stop — someone else may be in the middle.</p>
                    <code class="safety-number">{preview().safetyNumber}</code>
                    <p>This invite stops working {formatExpiry(preview().expiresAt)}.</p>
                  </div>
                </div>
              )}
            </Show>
          </section>
        </form>
      </Show>
    </Modal>
  );
}

const roleLabels: Record<ScopeRole, string> = { admin: "Admin", writer: "Writer", reader: "Reader" };

const roleOptions = [
  { value: "admin", label: "Admin" },
  { value: "writer", label: "Writer" },
  { value: "reader", label: "Reader" },
];

function formatExpiry(raw: string): string {
  const date = new Date(raw);
  if (Number.isNaN(date.valueOf())) return "soon";
  return `on ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date)}`;
}
