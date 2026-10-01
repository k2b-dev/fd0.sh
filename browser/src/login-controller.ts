import { findCredentialFields } from "./form";
import {
  mountLoginPicker,
  mountLoginPrompt,
  mountLoginTrigger,
  type LoginMatch,
  type LoginPicker,
  type LoginPrompt,
  type LoginTrigger,
} from "./picker";

export type LoginLookup = {
  origin: string;
  credentials: LoginMatch[];
};

export type LoginController = {
  open: () => Promise<boolean>;
  invalidate: () => void;
  dispose: () => void;
};

export function installLoginController(
  document: Document,
  lookup: () => Promise<LoginLookup>,
  select: (
    origin: string,
    credentialId: string,
    anchor: HTMLInputElement,
    signal: AbortSignal,
  ) => Promise<void>,
  openTools?: (anchor: HTMLInputElement, lookup: LoginLookup) => void,
): LoginController {
  let cachedLookup: LoginLookup | undefined;
  let pendingLookup: Promise<LoginLookup> | undefined;
  let picker: LoginPicker | undefined;
  let prompt: LoginPrompt | undefined;
  let trigger: LoginTrigger | undefined;
  let anchor: HTMLInputElement | undefined;
  let triggerKind: "login" | "tools" | undefined;
  let suppressFocus: HTMLInputElement | undefined;
  let disposed = false;
  let openSequence = 0;
  let cachedAt = 0;

  async function credentials(): Promise<LoginLookup> {
    if (cachedLookup && Date.now() - cachedAt < 5_000) return cachedLookup;
    cachedLookup = undefined;
    pendingLookup ??= lookup();
    try {
      cachedLookup = await pendingLookup;
      cachedAt = Date.now();
      return cachedLookup;
    } finally {
      pendingLookup = undefined;
    }
  }

  function loginAnchor(preferred?: EventTarget | null): HTMLInputElement | undefined {
    const preferredElement =
      preferred &&
      typeof preferred === "object" &&
      "tagName" in preferred
        ? (preferred as Element)
        : undefined;
    const fields = findCredentialFields(document, preferredElement);
    if (!fields.currentPassword) return undefined;
    const candidates = [fields.username, fields.currentPassword].filter(
      (field): field is HTMLInputElement => Boolean(field),
    );
    if (candidates.length === 0) return undefined;
    if (
      preferred &&
      typeof preferred === "object" &&
      "tagName" in preferred &&
      (preferred as Element).tagName === "INPUT" &&
      candidates.includes(preferred as HTMLInputElement)
    ) {
      return preferred as HTMLInputElement;
    }
    if (preferred) return undefined;
    return fields.username ?? fields.currentPassword;
  }

  function toolsAnchor(preferred?: EventTarget | null): HTMLInputElement | undefined {
    if (!openTools) return undefined;
    const preferredElement =
      preferred &&
      typeof preferred === "object" &&
      "tagName" in preferred
        ? (preferred as Element)
        : undefined;
    const fields = findCredentialFields(document, preferredElement);
    if (!fields.newPassword) return undefined;
    const candidates = [
      fields.currentPassword ? undefined : fields.username,
      fields.newPassword,
      fields.confirmPassword,
    ].filter((field): field is HTMLInputElement => Boolean(field));
    if (
      preferredElement instanceof HTMLInputElement &&
      candidates.includes(preferredElement)
    ) {
      return preferredElement;
    }
    if (preferred) return undefined;
    return fields.newPassword;
  }

  function mountTrigger(
    nextAnchor: HTMLInputElement,
    kind: "login" | "tools",
  ): void {
    if (
      anchor === nextAnchor &&
      triggerKind === kind &&
      trigger?.host.isConnected
    ) {
      return;
    }
    trigger?.close();
    anchor = nextAnchor;
    triggerKind = kind;
    trigger = mountLoginTrigger(document, nextAnchor, () => {
      if (kind === "login") {
        void openFor(nextAnchor, true);
      } else {
        void openToolsFor(nextAnchor, true);
      }
    });
  }

  function showLookupError(
    error: unknown,
    nextAnchor: HTMLInputElement,
    retry: () => void,
  ): void {
    picker?.close(false);
    picker = undefined;
    prompt?.close(false);
    const code = errorCode(error);
    const locked =
      code === "locked" ||
      (error instanceof Error &&
        error.message.toLocaleLowerCase().includes("unlock fd0"));
    const incompatible = code === "invalid_response";
    prompt = mountLoginPrompt(
      document,
      nextAnchor,
      locked
        ? "Vault locked"
        : incompatible
          ? "Update fd0"
          : "fd0 unavailable",
      locked
        ? "Unlock fd0 in the desktop app, then try again."
        : incompatible
          ? "The browser extension and fd0 need the same version."
          : error instanceof Error && error.message
            ? error.message
            : "Open fd0 and try again.",
      () => {
        prompt = undefined;
        retry();
      },
      (restoredFocus) => {
        prompt = undefined;
        // Only the focus fd0 hands back is suppressed; a later user focus
        // on the same field shows suggestions again.
        if (restoredFocus) suppressFocus = nextAnchor;
      },
    );
  }

  async function openToolsFor(
    nextAnchor: HTMLInputElement,
    explicit = false,
  ): Promise<boolean> {
    if (!openTools) return false;
    const sequence = ++openSequence;
    mountTrigger(nextAnchor, "tools");
    if (!explicit) return false;
    trigger?.setBusy(true);
    try {
      const result = await credentials();
      if (disposed || sequence !== openSequence || !nextAnchor.isConnected) return false;
      picker?.close(false);
      picker = undefined;
      prompt?.close(false);
      prompt = undefined;
      openTools(nextAnchor, result);
      return true;
    } catch (error) {
      if (!disposed && sequence === openSequence && explicit) {
        showLookupError(error, nextAnchor, () => {
          void openToolsFor(nextAnchor, true);
        });
      }
      return false;
    } finally {
      if (explicit) trigger?.setBusy(false);
    }
  }

  async function openFor(
    nextAnchor: HTMLInputElement,
    explicit = false,
  ): Promise<boolean> {
    const sequence = ++openSequence;
    mountTrigger(nextAnchor, "login");
    if (explicit) trigger?.setBusy(true);
    let result: LoginLookup;
    try {
      result = await credentials();
    } catch (error) {
      if (disposed || sequence !== openSequence) return false;
      if (explicit) {
        showLookupError(error, nextAnchor, () => {
          void openFor(nextAnchor, true);
        });
      }
      return false;
    } finally {
      if (explicit) trigger?.setBusy(false);
    }
    if (disposed || sequence !== openSequence || !nextAnchor.isConnected) {
      return false;
    }
    if (result.credentials.length === 0) {
      if (openTools) {
        if (explicit) openTools(nextAnchor, result);
      } else {
        trigger?.close();
        trigger = undefined;
        anchor = undefined;
        triggerKind = undefined;
      }
      return false;
    }

    prompt?.close(false);
    prompt = undefined;
    picker?.close(false);
    picker = mountLoginPicker(
      document,
      nextAnchor,
      result.credentials,
      (credentialId, signal) => select(result.origin, credentialId, nextAnchor, signal),
      (restoredFocus) => {
        picker = undefined;
        if (restoredFocus) suppressFocus = nextAnchor;
      },
      openTools
        ? () => {
            picker = undefined;
            openTools(nextAnchor, result);
          }
        : undefined,
      explicit,
    );
    return true;
  }

  function onFocus(event: FocusEvent): void {
    const preferred = event.composedPath().find(
      (target): target is HTMLInputElement =>
        Boolean(
          target &&
            typeof target === "object" &&
            "tagName" in target &&
            (target as Element).tagName === "INPUT",
        ),
    );
    const target = preferred ?? event.target;
    const nextToolsAnchor = toolsAnchor(target);
    const nextAnchor = nextToolsAnchor ?? loginAnchor(target);
    if (!nextAnchor) {
      if (![picker?.host, prompt?.host, trigger?.host].some(
        (host) => host && event.composedPath().includes(host),
      )) openSequence += 1;
      return;
    }
    if (suppressFocus === nextAnchor) {
      suppressFocus = undefined;
      return;
    }
    if (nextToolsAnchor) {
      void openToolsFor(nextToolsAnchor);
    } else {
      void openFor(nextAnchor);
    }
  }

  async function open(): Promise<boolean> {
    const activeTools = toolsAnchor(document.activeElement);
    if (activeTools) return openToolsFor(activeTools, true);
    const activeLogin = loginAnchor(document.activeElement);
    if (activeLogin) return openFor(activeLogin, true);
    const nextLogin = loginAnchor();
    if (nextLogin) return openFor(nextLogin, true);
    const nextTools = toolsAnchor();
    return nextTools ? openToolsFor(nextTools, true) : false;
  }

  function onFieldInput(event: Event): void {
    if (!anchor || !event.composedPath().includes(anchor)) return;
    openSequence += 1;
    picker?.close(false);
    picker = undefined;
    prompt?.close(false);
    prompt = undefined;
  }

  function onFocusOut(event: FocusEvent): void {
    if (!anchor || !event.composedPath().includes(anchor)) return;
    openSequence += 1;
    // Moving into fd0 is intentional; moving elsewhere dismisses suggestions.
    const related = event.relatedTarget;
    const relatedHost = related instanceof Node && related.getRootNode() instanceof ShadowRoot
      ? (related.getRootNode() as ShadowRoot).host
      : related;
    if ([picker?.host, prompt?.host, trigger?.host].some(
      (host) => host && relatedHost === host,
    )) return;
    picker?.close(false);
    picker = undefined;
    prompt?.close(false);
    prompt = undefined;
  }

  function onFieldKeyDown(event: KeyboardEvent): void {
    // Dismiss passive suggestions without consuming the page's Escape key.
    if (event.key === "Escape") onFieldInput(event);
    // ArrowDown moves from the field into passive suggestions, like the
    // browser's own autofill, so keyboard users can reach them.
    if (event.key === "ArrowDown" && picker && anchor && event.composedPath().includes(anchor)) {
      event.preventDefault();
      picker.focusFirst();
    }
  }

  function invalidate(): void {
    cachedLookup = undefined;
    cachedAt = 0;
    pendingLookup = undefined;
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    openSequence += 1;
    document.removeEventListener("focusin", onFocus, true);
    document.removeEventListener("focusout", onFocusOut, true);
    document.removeEventListener("input", onFieldInput, true);
    document.removeEventListener("change", onFieldInput, true);
    document.removeEventListener("keydown", onFieldKeyDown, true);
    picker?.close(false);
    prompt?.close(false);
    trigger?.close();
    triggerKind = undefined;
  }

  document.addEventListener("focusin", onFocus, true);
  document.addEventListener("focusout", onFocusOut, true);
  document.addEventListener("input", onFieldInput, true);
  document.addEventListener("change", onFieldInput, true);
  document.addEventListener("keydown", onFieldKeyDown, true);
  return { open, invalidate, dispose };
}

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}
