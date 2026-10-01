import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";

import { installLoginController, type LoginLookup } from "./login-controller";

function loginPage(): {
  window: Window;
  document: Document;
  username: HTMLInputElement;
  password: HTMLInputElement;
} {
  const window = new Window({ url: "https://example.com/login" });
  const document = window.document as unknown as Document;
  const username = document.createElement("input");
  username.autocomplete = "username";
  const password = document.createElement("input");
  password.type = "password";
  password.autocomplete = "current-password";
  for (const input of [username, password]) {
    input.style.display = "block";
    input.style.visibility = "visible";
    input.style.opacity = "1";
    input.getBoundingClientRect = () =>
      ({
        x: 40,
        y: 40,
        top: 40,
        left: 40,
        right: 340,
        bottom: 80,
        width: 300,
        height: 40,
        toJSON: () => ({}),
      }) as DOMRect;
    document.body.append(input);
  }
  Object.assign(globalThis, {
    Node: window.Node,
    getComputedStyle: window.getComputedStyle.bind(window),
    HTMLInputElement: window.HTMLInputElement,
    HTMLFormElement: window.HTMLFormElement,
    ShadowRoot: window.ShadowRoot,
  });
  return { window, document, username, password };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("login controller", () => {
  for (const action of ["leave", "input", "change", "remove", "escape"] as const) {
    test(`ignores a delayed lookup after ${action}`, async () => {
      const { window, document, username } = loginPage();
      const lookup = Promise.withResolvers<LoginLookup>();
      const controller = installLoginController(document, () => lookup.promise, async () => {});
      username.focus();
      const other = document.createElement("button");
      document.body.append(other);
      if (action === "leave") other.focus();
      else if (action === "remove") username.remove();
      else if (action === "escape") {
        const event = new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
        username.dispatchEvent(event as unknown as Event);
        expect(event.defaultPrevented).toBe(false);
      }
      else {
        username.value = "entered elsewhere";
        username.dispatchEvent(new window.Event(action, { bubbles: true }) as unknown as Event);
      }
      lookup.resolve({ origin: "https://example.com", credentials: [{ id: "fake", title: "Demo" }] });
      await settle();
      expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
      if (action === "leave") expect(document.activeElement).toBe(other);
      if (action === "input" || action === "change") {
        expect(document.activeElement).toBe(username);
        expect(username.value).toBe("entered elsewhere");
      }
      controller.dispose();
      await window.close();
    });
  }

  test("ignores an explicit lookup after moving from the toolbar target to another control", async () => {
    const { window, document } = loginPage();
    const lookup = Promise.withResolvers<LoginLookup>();
    const controller = installLoginController(document, () => lookup.promise, async () => {});
    const opened = controller.open();
    const other = document.createElement("button");
    document.body.append(other);
    other.focus();
    lookup.resolve({ origin: "https://example.com", credentials: [{ id: "fake", title: "Demo" }] });
    expect(await opened).toBe(false);
    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.activeElement).toBe(other);
    controller.dispose();
    await window.close();
  });

  test("dismisses suggestions on typing and focuses the picker only when explicitly reopened", async () => {
    const { window, document, username } = loginPage();
    const controller = installLoginController(document, async () => ({
      origin: "https://example.com", credentials: [{ id: "fake", title: "Demo" }],
    }), async () => {});
    username.focus();
    await settle();
    expect(document.querySelector("[data-fd0-login-picker]")).not.toBeNull();
    username.value = "manual";
    username.dispatchEvent(new window.Event("input", { bubbles: true }) as unknown as Event);
    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.activeElement).toBe(username);
    await controller.open();
    expect(document.activeElement).toBe(document.querySelector("[data-fd0-login-picker]"));
    expect(username.value).toBe("manual");
    controller.dispose();
    await window.close();
  });

  test("shows automatic suggestions without moving focus out of the login field", async () => {
    const { window, document, username } = loginPage();
    let lookups = 0;
    const controller = installLoginController(
      document,
      async () => {
        lookups += 1;
        return {
          origin: "https://example.com",
          credentials: [{ id: "opaque", title: "Example", username: "user" }],
        };
      },
      async () => {},
    );

    username.focus();
    await settle();

    expect(lookups).toBe(1);
    expect(document.activeElement).toBe(username);
    expect(document.querySelectorAll("[data-fd0-login-picker]")).toHaveLength(1);
    expect(document.querySelectorAll("[data-fd0-login-trigger]")).toHaveLength(1);
    controller.dispose();
    await window.close();
  });

  test("stays quiet when the current origin has no fd0 login", async () => {
    const { window, document, password } = loginPage();
    const controller = installLoginController(
      document,
      async () => ({ origin: "https://example.com", credentials: [] }),
      async () => {},
    );

    password.focus();
    await settle();

    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-trigger]")).toBeNull();
    controller.dispose();
    await window.close();
  });

  test("keeps a retry affordance when fd0 is locked", async () => {
    const { window, document, username } = loginPage();
    const controller = installLoginController(
      document,
      async () => {
        throw new Error("Unlock fd0 to fill this login.");
      },
      async () => {},
    );

    username.focus();
    await settle();

    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-trigger]")).not.toBeNull();
    controller.dispose();
    await window.close();
  });

  test("shows a locked state after an explicit retry and succeeds after unlock", async () => {
    const { window, document, username } = loginPage();
    let unlocked = false;
    const controller = installLoginController(
      document,
      async () => {
        if (!unlocked) throw new Error("Unlock fd0 to fill this login.");
        return {
          origin: "https://example.com",
          credentials: [{ id: "opaque", title: "Example", username: "user" }],
        };
      },
      async () => {},
    );

    username.focus();
    await settle();
    expect(document.querySelector("[data-fd0-login-trigger]")).not.toBeNull();
    await controller.open();
    await settle();

    const promptHost = document.querySelector<HTMLElement>("[data-fd0-login-prompt]");
    expect(promptHost).not.toBeNull();
    unlocked = true;
    await controller.open();
    await settle();

    expect(document.querySelector("[data-fd0-login-prompt]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-picker]")).not.toBeNull();
    controller.dispose();
    await window.close();
  });

  test("routes signup password fields to Password tools instead of the login picker", async () => {
    const { window, document } = loginPage();
    document.body.replaceChildren();
    const form = document.createElement("form");
    const username = document.createElement("input");
    username.autocomplete = "username";
    const password = document.createElement("input");
    password.type = "password";
    password.autocomplete = "new-password";
    for (const input of [username, password]) {
      input.style.display = "block";
      input.style.visibility = "visible";
      input.style.opacity = "1";
      input.getBoundingClientRect = () =>
        ({ width: 200, height: 40 }) as DOMRect;
    }
    form.append(username, password);
    document.body.append(form);
    let tools = 0;
    const controller = installLoginController(
      document,
      async () => ({
        origin: "https://example.com",
        credentials: [{ id: "opaque", title: "Existing" }],
      }),
      async () => {},
      () => {
        tools += 1;
      },
    );

    password.focus();
    await settle();

    expect(tools).toBe(0);
    expect(document.activeElement).toBe(password);
    expect(document.querySelector("[data-fd0-login-trigger]")).not.toBeNull();
    await controller.open();
    expect(tools).toBe(1);
    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    controller.dispose();
    await window.close();
  });

  test("leaves OTP-only fields to the dedicated TOTP flow", async () => {
    const { window, document } = loginPage();
    document.body.replaceChildren();
    const otp = document.createElement("input");
    otp.autocomplete = "one-time-code";
    otp.style.display = "block";
    otp.getBoundingClientRect = () => ({ width: 200, height: 40 }) as DOMRect;
    document.body.append(otp);
    let lookups = 0;
    const controller = installLoginController(
      document,
      async () => {
        lookups += 1;
        return { origin: "https://example.com", credentials: [] };
      },
      async () => {},
      () => {},
    );

    otp.dispatchEvent(
      new window.FocusEvent("focusin", { bubbles: true }) as unknown as Event,
    );
    await settle();

    expect(lookups).toBe(0);
    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-trigger]")).toBeNull();
    controller.dispose();
    await window.close();
  });
});
