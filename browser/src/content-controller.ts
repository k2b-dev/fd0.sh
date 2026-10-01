import {
  fillGeneratedPassword,
  fillLogin,
  fillOTP,
  findCredentialFields,
  findLoginFields,
  readLoginCandidate,
} from "./form";
import {
  mountCredentialActionPanel,
  type ActionLoginMatch,
  type CredentialActionPanel,
  type VaultChoice,
} from "./action-panel";
import type { LoginCandidate, LoginFields } from "./form";
import {
  installLoginController,
  type LoginController,
  type LoginLookup,
} from "./login-controller";
import { mountLoginNotice, type LoginNotice } from "./picker";

type NativeError = { code: string; message: string };
type Response<T = unknown> = { ok: boolean; result?: T; error?: NativeError };
type FillRequest = {
  type: "fd0.fill";
  selectionId: string;
  credential: { username?: string; password: string; hasTotp?: boolean };
};
type OpenPickerRequest = { type: "fd0.openPicker" };
type ShowNoticeRequest = {
  type: "fd0.showNotice";
  message: string;
  tone?: "neutral" | "error";
};
type PingRequest = { type: "fd0.ping" };
type FD0ContentGlobal = typeof globalThis & { __fd0Dispose?: () => void };

export function installContentScript(document: Document): () => void {
  const contentGlobal = globalThis as FD0ContentGlobal;
  document.dispatchEvent(new CustomEvent("fd0:dispose-content-context"));
  contentGlobal.__fd0Dispose?.();
  for (const element of document.querySelectorAll<HTMLElement>(
    [
      "[data-fd0-login-trigger]",
      "[data-fd0-login-prompt]",
      "[data-fd0-login-picker]",
      "[data-fd0-login-notice]",
      "[data-fd0-credential-actions]",
    ].join(","),
  )) {
    element.remove();
  }

  let recentLogin:
    | { origin: string; credentialId: string; expiresAt: number }
    | undefined;
  type PendingFill = {
    anchor: HTMLInputElement;
    fields: LoginFields;
    username: string | undefined;
    password: string;
    usernameRevision: number;
    passwordRevision: number;
    signal: AbortSignal;
    applied: boolean;
  };
  const pendingFills = new Map<string, PendingFill>();
  const revisions = new WeakMap<HTMLInputElement, number>();
  const editedOTP = new WeakSet<HTMLInputElement>();
  let intentRevision = 0;
  let loginRevision = 0;
  let allowRecentOTP = true;
  let controller: LoginController | undefined;
  let notice: LoginNotice | undefined;
  let actionPanel: CredentialActionPanel | undefined;
  let otpObserver: MutationObserver | undefined;
  let otpRequest: Promise<boolean> | undefined;
  let otpRetryTimer: number | undefined;
  let otpMutationTimer: number | undefined;
  let otpExpiryTimer: number | undefined;
  const lifecycle = new AbortController();

  async function send<T>(message: Record<string, unknown>): Promise<T> {
    if (lifecycle.signal.aborted) throw new Error("fd0 action was cancelled.");
    let response: Response<T>;
    try {
      response = await chrome.runtime.sendMessage<Response<T>>(message);
    } catch (error) {
      if (!isInvalidatedContext(error)) throw error;
      dispose();
      const unavailable = new Error(
        "fd0 was updated. Click its Chrome toolbar icon to reconnect.",
      ) as Error & { code?: string };
      unavailable.code = "extension_reloaded";
      throw unavailable;
    }
    if (lifecycle.signal.aborted) throw new Error("fd0 action was cancelled.");
    if (!response?.ok || response.result === undefined) {
      const error = new Error(response?.error?.message || "fd0 could not complete this action.") as Error & {
        code?: string;
      };
      error.code = response?.error?.code;
      throw error;
    }
    return response.result;
  }

  function dispose(): void {
    if (lifecycle.signal.aborted) return;
    lifecycle.abort();
    pendingFills.clear();
    loginRevision += 1;
    controller?.dispose();
    notice?.close();
    actionPanel?.close(false);
    otpObserver?.disconnect();
    if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
    if (otpMutationTimer !== undefined) clearTimeout(otpMutationTimer);
    if (otpExpiryTimer !== undefined) clearTimeout(otpExpiryTimer);
    try {
      chrome.runtime.onMessage.removeListener(onRuntimeMessage);
    } catch {
      // The previous extension context may already be invalidated.
    }
    if (contentGlobal.__fd0Dispose === dispose) {
      delete contentGlobal.__fd0Dispose;
    }
  }

  contentGlobal.__fd0Dispose = dispose;
  document.addEventListener("fd0:dispose-content-context", dispose, {
    signal: lifecycle.signal,
  });

  function isInvalidatedContext(error: unknown): boolean {
    return (
      error instanceof Error &&
      error.message.toLocaleLowerCase().includes("extension context invalidated")
    );
  }

  async function lookup(): Promise<LoginLookup> {
    return send<LoginLookup>({ type: "fd0.requestMatches" });
  }

  async function select(
    origin: string,
    credentialId: string,
    anchor: HTMLInputElement,
    signal: AbortSignal,
  ): Promise<void> {
    const fields = findLoginFields(document, anchor);
    if (!fields || signal.aborted || lifecycle.signal.aborted) return;
    const revision = ++loginRevision;
    allowRecentOTP = false;
    recentLogin = undefined;
    otpObserver?.disconnect();
    otpRequest = undefined;
    if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
    const selectionId = crypto.randomUUID();
    const pending: PendingFill = {
      anchor, fields, signal, applied: false,
      username: fields.username?.value, password: fields.password.value,
      usernameRevision: fields.username ? revisions.get(fields.username) ?? 0 : 0,
      passwordRevision: revisions.get(fields.password) ?? 0,
    };
    pendingFills.clear();
    pendingFills.set(selectionId, pending);
    const cancel = () => pendingFills.delete(selectionId);
    signal.addEventListener("abort", cancel, { once: true });
    try {
      const result = await send<{ hasTotp?: boolean }>({
        type: "fd0.selectCredential", origin, credentialId, selectionId,
      });
      if (!pending.applied || revision !== loginRevision) return;
      if (result.hasTotp) {
        recentLogin = { origin, credentialId, expiresAt: Date.now() + 5 * 60 * 1000 };
        watchForOTP();
      }
    } finally {
      cancel();
      signal.removeEventListener("abort", cancel);
    }
  }

  // A staged save offer after navigation is passive: page interaction does
  // not cancel it and it never takes focus. User-opened tools follow intent.
  async function openTools(
    anchor: HTMLElement,
    currentLookup: LoginLookup,
    staged?: LoginCandidate,
  ): Promise<void> {
    actionPanel?.close(false);
    const intent = ++intentRevision;
    const current = () => staged !== undefined || intent === intentRevision;
    let scopes: VaultChoice[];
    try {
      const result = await send<{ scopes: VaultChoice[] }>({ type: "fd0.requestScopes" });
      scopes = result.scopes;
    } catch (error) {
      if (current()) showNotice(messageOf(error), "error");
      return;
    }
    if (!current() || !anchor.isConnected || lifecycle.signal.aborted) return;
    const matches = currentLookup.credentials.filter(
      (match): match is ActionLoginMatch =>
        typeof match.revision === "string" &&
        typeof match.scopeId === "string" &&
        typeof match.scope === "string",
    );
    actionPanel = mountCredentialActionPanel(
      document,
      anchor,
      currentLookup.origin,
      staged ?? readLoginCandidate(document, anchor),
      matches,
      scopes,
      {
        useGenerated(password) {
          const result = fillGeneratedPassword(document, password, anchor);
          if (!result.passwordFilled) {
            throw new Error("No visible password field was found.");
          }
        },
        async save(input) {
          await send({
            type: "fd0.saveLogin",
            origin: currentLookup.origin,
            ...input,
          });
          controller?.invalidate();
        },
        async update(input) {
          await send({
            type: "fd0.updateLogin",
            origin: currentLookup.origin,
            ...input,
          });
          controller?.invalidate();
        },
        async addTOTP(input) {
          await send({
            type: "fd0.addTOTP",
            origin: currentLookup.origin,
            totpUri: input.uri,
            credentialId: input.credentialId,
            revision: input.revision,
          });
          controller?.invalidate();
        },
      },
      staged === undefined,
    );
  }

  function onInteraction(event: Event): void {
    intentRevision += 1;
    if (event.type !== "input" && event.type !== "change") return;
    const field = event.composedPath().find(isInput);
    if (!field) return;
    revisions.set(field, (revisions.get(field) ?? 0) + 1);
    if (findCredentialFields(document, field).otp === field) editedOTP.add(field);
  }
  for (const type of ["focusin", "pointerdown", "keydown", "input", "change"]) {
    document.addEventListener(type, onInteraction, { capture: true, signal: lifecycle.signal });
  }
  document.defaultView?.addEventListener("blur", onInteraction, { signal: lifecycle.signal });

  controller = installLoginController(
    document,
    lookup,
    select,
    (anchor, currentLookup) => void openTools(anchor, currentLookup),
  );

  document.addEventListener("focusin", onOTPFocus, {
    capture: true,
    signal: lifecycle.signal,
  });
  if (findCredentialFields(document).otp) void fillRecentTOTP();

  document.addEventListener("submit", onSubmit, {
    capture: true,
    signal: lifecycle.signal,
  });
  void consumeStagedLogin();

  function onRuntimeMessage(
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ): boolean | void {
    if (lifecycle.signal.aborted || sender.id !== chrome.runtime.id) return;
    if (isPingRequest(message)) {
      sendResponse({ ok: true });
      return;
    }
    if (isFillRequest(message)) {
      const pending = pendingFills.get(message.selectionId);
      const fields = pending && findLoginFields(document, pending.anchor);
      if (!pending || pending.signal.aborted || !fields ||
        fields.password !== pending.fields.password || fields.username !== pending.fields.username ||
        fields.password.value !== pending.password || fields.username?.value !== pending.username ||
        (revisions.get(fields.password) ?? 0) !== pending.passwordRevision ||
        (fields.username ? revisions.get(fields.username) ?? 0 : 0) !== pending.usernameRevision
      ) {
        sendResponse({ ok: false });
        return;
      }
      try {
        pendingFills.delete(message.selectionId);
        const result = fillLogin(document, message.credential, pending.anchor);
        pending.applied = result.passwordFilled;
        sendResponse({ ok: true, ...result });
      } catch {
        sendResponse({ ok: false });
      }
      return;
    }
    if (isShowNoticeRequest(message)) {
      showNotice(message.message, message.tone);
      sendResponse({ ok: true });
      return;
    }
    if (isOpenPickerRequest(message)) {
      void controller?.open().then((ok) => sendResponse({ ok }));
      return true;
    }
  }

  chrome.runtime.onMessage.addListener(onRuntimeMessage);

  function onOTPFocus(event: FocusEvent): void {
    const input = event.composedPath().find(isInput);
    if (!input) return;
    const otp = findCredentialFields(document, input).otp;
    if (otp === input) void fillRecentTOTP(input);
  }

  function onSubmit(event: SubmitEvent): void {
    const form = event.composedPath().find(isForm);
    const candidate = readLoginCandidate(document, form);
    if (!candidate) return;
    queueMicrotask(() => {
      if (event.defaultPrevented || lifecycle.signal.aborted) return;
      void send<{ staged: boolean }>({
        type: "fd0.stageLogin",
        candidate,
      }).catch(() => { /* Optional save suggestion; leave the page submission alone. */ });
    });
  }

  function watchForOTP(): void {
    otpObserver?.disconnect();
    void fillRecentTOTP();
    otpObserver = new MutationObserver(() => {
      if (otpMutationTimer !== undefined) clearTimeout(otpMutationTimer);
      otpMutationTimer = document.defaultView?.setTimeout(() => void fillRecentTOTP(), 120);
    });
    otpObserver.observe(document.documentElement, { childList: true, subtree: true });
    if (otpExpiryTimer !== undefined) clearTimeout(otpExpiryTimer);
    const remaining = (recentLogin?.expiresAt ?? Date.now()) - Date.now();
    otpExpiryTimer = document.defaultView?.setTimeout(() => {
      if (!recentLogin || recentLogin.expiresAt <= Date.now()) {
        recentLogin = undefined;
        otpObserver?.disconnect();
      }
    }, Math.max(remaining, 0) + 50);
  }

  async function fillRecentTOTP(anchor?: Element): Promise<boolean> {
    if (lifecycle.signal.aborted || (!recentLogin && !allowRecentOTP)) return false;
    if (otpRequest) return otpRequest;
    const request = fillRecentTOTPOnce(anchor).finally(() => {
      if (otpRequest === request) otpRequest = undefined;
    });
    otpRequest = request;
    return request;
  }

  async function fillRecentTOTPOnce(anchor?: Element): Promise<boolean> {
    const selected = recentLogin;
    if (selected && selected.expiresAt <= Date.now()) {
      recentLogin = undefined;
      otpObserver?.disconnect();
      return false;
    }
    const field = findCredentialFields(document, anchor).otp;
    if (field && editedOTP.has(field)) {
      // The user entered their own code; stop watching for this login.
      otpObserver?.disconnect();
      return false;
    }
    if (!field || field.value) return false;
    const fieldRevision = revisions.get(field) ?? 0;
    const selectionRevision = loginRevision;
    const current = () => !lifecycle.signal.aborted && selectionRevision === loginRevision &&
      field.isConnected && !field.value && !editedOTP.has(field) &&
      (revisions.get(field) ?? 0) === fieldRevision &&
      findCredentialFields(document, anchor).otp === field;
    try {
      const result = await send<{ available?: boolean; code?: string; remaining?: number }>(
        selected
          ? { type: "fd0.requestTOTP", origin: selected.origin, credentialId: selected.credentialId }
          : { type: "fd0.requestRecentTOTP" },
      );
      if (!current() || result.available === false || !result.code || result.remaining === undefined) return false;
      if (result.remaining <= 2) {
        if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
        otpRetryTimer = document.defaultView?.setTimeout(() => {
          if (current()) void fillRecentTOTP(anchor);
        }, (result.remaining + 1) * 1000);
        return false;
      }
      if (fillOTP(document, result.code, field)) {
        showNotice("One-time code filled.");
        otpObserver?.disconnect();
        return true;
      }
    } catch (error) {
      if (selected && current()) showNotice(messageOf(error), "error");
      otpObserver?.disconnect();
    }
    return false;
  }

  async function consumeStagedLogin(): Promise<void> {
    try {
      const result = await send<{
        available: boolean;
        candidate?: LoginCandidate;
      }>({ type: "fd0.consumeStagedLogin" });
      if (!result.available || !result.candidate) return;
      const currentLookup = await lookup();
      if (lifecycle.signal.aborted) return;
      const fields = findCredentialFields(document);
      const anchor =
        fields.username ??
        fields.currentPassword ??
        fields.newPassword ??
        fields.otp ??
        document.documentElement;
      await openTools(anchor, currentLookup, result.candidate);
    } catch {
      // Save/update is an optional follow-up. Autofill remains usable if the
      // native host is temporarily unavailable after navigation.
    }
  }

  function showNotice(
    message: string,
    tone: "neutral" | "error" = "neutral",
  ): void {
    if (lifecycle.signal.aborted) return;
    notice?.close();
    notice = mountLoginNotice(document, message, tone);
  }

  function messageOf(error: unknown): string {
    return error instanceof Error && error.message
      ? error.message
      : "fd0 could not complete this action.";
  }

  function isFillRequest(message: unknown): message is FillRequest {
    if (!message || typeof message !== "object") return false;
    const request = message as Partial<FillRequest>;
    return (
      request.type === "fd0.fill" &&
      typeof request.selectionId === "string" &&
      request.selectionId.length > 0 &&
      Boolean(request.credential) &&
      typeof request.credential?.password === "string" &&
      (request.credential.username === undefined ||
        typeof request.credential.username === "string") &&
      (request.credential.hasTotp === undefined ||
        typeof request.credential.hasTotp === "boolean")
    );
  }

  function isOpenPickerRequest(message: unknown): message is OpenPickerRequest {
    return Boolean(
      message &&
        typeof message === "object" &&
        (message as Partial<OpenPickerRequest>).type === "fd0.openPicker",
    );
  }

  function isShowNoticeRequest(message: unknown): message is ShowNoticeRequest {
    if (!message || typeof message !== "object") return false;
    const request = message as Partial<ShowNoticeRequest>;
    return (
      request.type === "fd0.showNotice" &&
      typeof request.message === "string" &&
      request.message.length > 0 &&
      (request.tone === undefined ||
        request.tone === "neutral" ||
        request.tone === "error")
    );
  }

  function isPingRequest(message: unknown): message is PingRequest {
    return Boolean(
      message &&
        typeof message === "object" &&
        (message as Partial<PingRequest>).type === "fd0.ping",
    );
  }

  function isInput(value: unknown): value is HTMLInputElement {
    return value instanceof HTMLInputElement;
  }

  function isForm(value: unknown): value is HTMLFormElement {
    return value instanceof HTMLFormElement;
  }

  return dispose;
}
