import { afterEach, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { installContentScript } from "./content-controller";

type Reply = { ok: boolean; result?: unknown; error?: { code: string; message: string } };
type Listener = Parameters<typeof chrome.runtime.onMessage.addListener>[0];
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0)) await cleanup(); });

function fixture(markup = '<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form>') {
  const window = new Window({ url: "https://example.com/login" });
  const document = window.document as unknown as Document;
  Object.assign(globalThis, {
    Node: window.Node, HTMLElement: window.HTMLElement,
    HTMLInputElement: window.HTMLInputElement, HTMLFormElement: window.HTMLFormElement,
    ShadowRoot: window.ShadowRoot, Event: window.Event, CustomEvent: window.CustomEvent, KeyboardEvent: window.KeyboardEvent,
    MutationObserver: window.MutationObserver, AbortController: window.AbortController,
    getComputedStyle: window.getComputedStyle.bind(window),
  });
  const roots = new Map<HTMLElement, ShadowRoot>();
  const prototype = window.HTMLElement.prototype;
  const attach = prototype.attachShadow;
  prototype.attachShadow = function (options) {
    const root = attach.call(this, options);
    roots.set(this as unknown as HTMLElement, root as unknown as ShadowRoot);
    return root;
  };
  const visible = (input: HTMLInputElement) => {
    input.style.cssText = "display:block;visibility:visible;opacity:1";
    input.getBoundingClientRect = () => new window.DOMRect(20, 20, 200, 40);
    return input;
  };
  document.body.innerHTML = markup;
  document.querySelectorAll("input").forEach(visible);
  const requests: Record<string, unknown>[] = [];
  const replies = new Map<string, Promise<Reply>>();
  const listeners = new Set<Listener>();
  Object.defineProperty(globalThis, "chrome", { configurable: true, writable: true, value: {
    runtime: {
      id: "test-extension",
      onMessage: {
        addListener(listener: Listener) { listeners.add(listener); },
        removeListener(listener: Listener) { listeners.delete(listener); },
      },
      async sendMessage(message: Record<string, unknown>): Promise<Reply> {
        requests.push(message);
        const queued = replies.get(String(message.type));
        if (queued) return queued;
        if (message.type === "fd0.requestMatches") return { ok: true, result: {
          origin: "https://example.com", credentials: [{ id: "demo", title: "Demo", username: "demo", revision: "1", scopeId: "s", scope: "Test" }],
        } };
        if (message.type === "fd0.requestScopes") return { ok: true, result: { scopes: [{ id: "s", label: "Test" }] } };
        return { ok: true, result: { available: false } };
      },
    },
  } });
  const root = (selector: string) => {
    const host = document.querySelector<HTMLElement>(selector);
    const result = host && roots.get(host);
    if (!result) throw new Error(`Missing test UI: ${selector}`);
    return result;
  };
  const message = (value: unknown): Promise<unknown> => new Promise((resolve) => {
    for (const listener of listeners) listener(value, { id: "test-extension" }, resolve);
  });
  let dispose: (() => void) | undefined;
  const start = () => { dispose = installContentScript(document); };
  cleanups.push(async () => { dispose?.(); await window.close(); });
  return { window, document, visible, requests, replies, listeners, root, message, start, dispose: () => dispose?.() };
}

async function settle() { for (let i = 0; i < 20; i += 1) await Promise.resolve(); }

describe("content script lifecycle", () => {
  for (const action of ["close", "escape", "edit", "edit-and-clear", "replace", "replace-password", "dispose"] as const) {
    test(`rejects a pending fill after ${action}`, async () => {
      const page = fixture();
      const pending = Promise.withResolvers<Reply>();
      page.replies.set("fd0.selectCredential", pending.promise);
      page.start();
      const username = page.document.querySelector<HTMLInputElement>("input")!;
      const password = page.document.querySelector<HTMLInputElement>('input[type="password"]')!;
      username.focus();
      await settle();
      const picker = page.root("[data-fd0-login-picker]");
      picker.querySelector<HTMLButtonElement>(".option")!.click();
      const selection = page.requests.find((request) => request.type === "fd0.selectCredential")!;
      expect(selection).toBeDefined();
      let target = password;
      if (action === "close") picker.querySelector<HTMLButtonElement>(".close")!.click();
      if (action === "escape") picker.querySelector(".option")!.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      if (action === "edit" || action === "edit-and-clear") {
        password.value = "manual";
        password.dispatchEvent(new Event("input", { bubbles: true }));
        if (action === "edit-and-clear") password.value = "";
      }
      if (action === "replace" || action === "replace-password") {
        if (action === "replace") username.remove();
        password.remove();
        target = page.visible(page.document.createElement("input"));
        target.type = "password";
        target.autocomplete = "current-password";
        page.document.querySelector("form")!.append(target);
      }
      if (action === "dispose") page.dispose();
      else expect(await page.message({ type: "fd0.fill", selectionId: selection.selectionId, credential: { username: "demo", password: "synthetic-secret" } })).toEqual({ ok: false });
      pending.resolve({ ok: true, result: { hasTotp: true } });
      await settle();
      expect(target.value).not.toBe("synthetic-secret");
      expect(page.requests.some((request) => request.type === "fd0.requestTOTP")).toBe(false);
    });
  }

  test("fills unchanged fields once and then fills an empty OTP field", async () => {
    const page = fixture('<form><input autocomplete="username"><input type="password" autocomplete="current-password"><input autocomplete="one-time-code"></form>');
    const pending = Promise.withResolvers<Reply>();
    page.replies.set("fd0.selectCredential", pending.promise);
    page.replies.set("fd0.requestTOTP", Promise.resolve({ ok: true, result: { code: "123456", remaining: 20 } }));
    page.start();
    await settle();
    page.document.querySelector<HTMLInputElement>("input")!.focus();
    await settle();
    page.root("[data-fd0-login-picker]").querySelector<HTMLButtonElement>(".option")!.click();
    const selection = page.requests.find((request) => request.type === "fd0.selectCredential")!;
    const fill = { type: "fd0.fill", selectionId: selection.selectionId, credential: { username: "demo", password: "synthetic-secret" } };
    expect(await page.message(fill)).toEqual({ ok: true, usernameFilled: true, passwordFilled: true });
    expect(await page.message(fill)).toEqual({ ok: false });
    pending.resolve({ ok: true, result: { hasTotp: true } });
    await settle();
    expect(page.document.querySelector<HTMLInputElement>('input[type="password"]')!.value).toBe("synthetic-secret");
    expect(page.document.querySelector<HTMLInputElement>('[autocomplete="one-time-code"]')!.value).toBe("123456");
  });

  for (const action of ["edit", "edit-and-clear", "replace", "dispose"] as const) {
    test(`ignores an OTP response after ${action}`, async () => {
      const page = fixture('<input autocomplete="one-time-code">');
      const pending = Promise.withResolvers<Reply>();
      page.replies.set("fd0.requestRecentTOTP", pending.promise);
      page.start();
      let field = page.document.querySelector<HTMLInputElement>("input")!;
      if (action === "edit" || action === "edit-and-clear") {
        field.value = "654321";
        field.dispatchEvent(new Event("input", { bubbles: true }));
        if (action === "edit-and-clear") field.value = "";
      }
      if (action === "replace") {
        field.remove();
        field = page.visible(page.document.createElement("input"));
        field.autocomplete = "one-time-code";
        page.document.body.append(field);
      }
      if (action === "dispose") page.dispose();
      pending.resolve({ ok: true, result: { available: true, code: "123456", remaining: 20 } });
      await settle();
      expect(field.value).not.toBe("123456");
      expect(page.document.querySelector("[data-fd0-login-notice]")).toBeNull();
    });
  }

  for (const action of ["focus", "dispose", "reinstall"] as const) {
    test(`does not mount delayed tools after ${action}`, async () => {
      const page = fixture('<input type="password" autocomplete="new-password"><button>Elsewhere</button>');
      const pending = Promise.withResolvers<Reply>();
      page.replies.set("fd0.requestScopes", pending.promise);
      page.start();
      page.document.querySelector<HTMLInputElement>("input")!.focus();
      expect(await page.message({ type: "fd0.openPicker" })).toEqual({ ok: true });
      if (action === "focus") page.document.querySelector<HTMLButtonElement>("button")!.focus();
      if (action === "dispose") page.dispose();
      if (action === "reinstall") page.start();
      pending.resolve({ ok: true, result: { scopes: [{ id: "s", label: "Test" }] } });
      await settle();
      expect(page.document.querySelector("[data-fd0-credential-actions]")).toBeNull();
      expect(page.document.querySelector("[data-fd0-login-notice]")).toBeNull();
      expect(page.listeners.size).toBe(action === "dispose" ? 0 : 1);
    });
  }

  test("explicit tools still open when the request stays current", async () => {
    const page = fixture('<input type="password" autocomplete="new-password">');
    page.start();
    page.document.querySelector<HTMLInputElement>("input")!.focus();
    expect(await page.message({ type: "fd0.openPicker" })).toEqual({ ok: true });
    await settle();
    expect(page.document.querySelector("[data-fd0-credential-actions]")).not.toBeNull();
  });

  test("shows suggestions again when the user refocuses after an outside dismissal", async () => {
    const page = fixture('<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form><button>Elsewhere</button>');
    page.start();
    const username = page.document.querySelector<HTMLInputElement>("input")!;
    username.focus();
    await settle();
    expect(page.document.querySelector("[data-fd0-login-picker]")).not.toBeNull();
    page.document.querySelector<HTMLButtonElement>("button")!.dispatchEvent(new Event("pointerdown", { bubbles: true, composed: true }));
    page.document.querySelector<HTMLButtonElement>("button")!.focus();
    await settle();
    expect(page.document.querySelector("[data-fd0-login-picker]")).toBeNull();
    username.focus();
    await settle();
    expect(page.document.querySelector("[data-fd0-login-picker]")).not.toBeNull();
  });

  test("keeps a staged save offer passive when the user interacts while it loads", async () => {
    const page = fixture();
    const scopes = Promise.withResolvers<Reply>();
    page.replies.set("fd0.consumeStagedLogin", Promise.resolve({ ok: true, result: {
      available: true, candidate: { username: "demo", password: "synthetic-secret", kind: "login" },
    } }));
    page.replies.set("fd0.requestMatches", Promise.resolve({ ok: true, result: { origin: "https://example.com", credentials: [] } }));
    page.replies.set("fd0.requestScopes", scopes.promise);
    page.start();
    await settle();
    expect(page.requests.some((request) => request.type === "fd0.requestScopes")).toBe(true);
    const password = page.document.querySelector<HTMLInputElement>('input[type="password"]')!;
    password.focus();
    page.document.dispatchEvent(new KeyboardEvent("keydown", { key: "a", bubbles: true }));
    scopes.resolve({ ok: true, result: { scopes: [{ id: "s", label: "Test" }] } });
    await settle();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(page.document.querySelector("[data-fd0-credential-actions]")).not.toBeNull();
    expect(page.document.activeElement).toBe(password);
  });

  test("stops watching for an OTP field once the selected login expires", async () => {
    const page = fixture();
    let disconnects = 0;
    const Base = globalThis.MutationObserver;
    globalThis.MutationObserver = class extends Base {
      disconnect() { disconnects += 1; super.disconnect(); }
    } as typeof MutationObserver;
    const pending = Promise.withResolvers<Reply>();
    page.replies.set("fd0.selectCredential", pending.promise);
    page.start();
    page.document.querySelector<HTMLInputElement>("input")!.focus();
    await settle();
    page.root("[data-fd0-login-picker]").querySelector<HTMLButtonElement>(".option")!.click();
    const selection = page.requests.find((request) => request.type === "fd0.selectCredential")!;
    await page.message({ type: "fd0.fill", selectionId: selection.selectionId, credential: { username: "demo", password: "synthetic-secret" } });
    pending.resolve({ ok: true, result: { hasTotp: true } });
    await settle();
    const realNow = Date.now;
    Date.now = () => realNow() + 6 * 60 * 1000;
    try {
      const before = disconnects;
      page.document.body.append(page.document.createElement("div"));
      await new Promise((resolve) => setTimeout(resolve, 200));
      await settle();
      expect(disconnects).toBeGreaterThan(before);
    } finally {
      Date.now = realNow;
      globalThis.MutationObserver = Base;
    }
  });

  test("moves from the field into passive suggestions with ArrowDown", async () => {
    const page = fixture();
    page.start();
    const username = page.document.querySelector<HTMLInputElement>("input")!;
    username.focus();
    await settle();
    const host = page.document.querySelector<HTMLElement>("[data-fd0-login-picker]")!;
    expect(page.document.activeElement).toBe(username);
    username.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, composed: true }));
    expect(page.document.activeElement).toBe(host);
  });
});
