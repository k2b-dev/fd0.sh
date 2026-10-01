import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";

import { mountCredentialActionPanel } from "./action-panel";

function page(): { window: Window; document: Document; anchor: HTMLInputElement } {
  const window = new Window({ url: "https://example.com/register" });
  const document = window.document as unknown as Document;
  const anchor = document.createElement("input");
  anchor.getBoundingClientRect = () =>
    ({
      top: 20,
      left: 20,
      right: 320,
      bottom: 60,
      width: 300,
      height: 40,
      x: 20,
      y: 20,
      toJSON: () => ({}),
    }) as DOMRect;
  document.body.append(anchor);
  return { window, document, anchor };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

function pointerEvent(
  window: Window,
  type: string,
  init: PointerEventInit,
): Event {
  return new window.PointerEvent(type, init as never) as unknown as Event;
}

describe("credential action panel", () => {
  test("outside dismissal does not steal focus or refocus on the next frame", async () => {
    const { window, document, anchor } = page();
    const panel = mountCredentialActionPanel(document, anchor, "https://example.com", undefined, [], [], {
      useGenerated() {}, async save() {}, async update() {}, async addTOTP() {},
    });
    const other = document.createElement("input");
    document.body.append(other);
    other.focus();
    let restored = false;
    anchor.addEventListener("focus", () => { restored = true; });
    other.dispatchEvent(pointerEvent(window, "pointerdown", { bubbles: true }));
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    expect(panel.host.isConnected).toBe(false);
    expect(restored).toBe(false);
    expect(document.activeElement).toBe(other);
    await window.close();
  });

  test("opens top-right and keeps a dragged panel inside the viewport", async () => {
    const { window, document, anchor } = page();
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 1000,
    });
    Object.defineProperty(window, "innerHeight", {
      configurable: true,
      value: 800,
    });
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      undefined,
      [],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save() {},
        async update() {},
        async addTOTP() {},
      },
    );

    const dialog = panel.root.querySelector<HTMLElement>(".panel")!;
    const header = panel.root.querySelector<HTMLElement>("header")!;
    expect(dialog.style.left).toBe("598px");
    expect(dialog.style.top).toBe("12px");

    dialog.getBoundingClientRect = () => {
      const left = Number.parseFloat(dialog.style.left);
      const top = Number.parseFloat(dialog.style.top);
      return {
        top,
        left,
        right: left + 390,
        bottom: top + 620,
        width: 390,
        height: 620,
        x: left,
        y: top,
        toJSON: () => ({}),
      } as DOMRect;
    };
    header.dispatchEvent(
      pointerEvent(window, "pointerdown", {
        bubbles: true,
        button: 0,
        clientX: 618,
        clientY: 32,
        composed: true,
        pointerId: 1,
      }),
    );
    header.dispatchEvent(
      pointerEvent(window, "pointermove", {
        bubbles: true,
        clientX: -100,
        clientY: -100,
        composed: true,
        pointerId: 1,
      }),
    );
    expect(dialog.style.left).toBe("12px");
    expect(dialog.style.top).toBe("12px");

    header.dispatchEvent(
      pointerEvent(window, "pointermove", {
        bubbles: true,
        clientX: 1200,
        clientY: 1000,
        composed: true,
        pointerId: 1,
      }),
    );
    expect(dialog.style.left).toBe("598px");
    expect(dialog.style.top).toBe("168px");

    header.dispatchEvent(
      pointerEvent(window, "pointerup", {
        bubbles: true,
        composed: true,
        pointerId: 1,
      }),
    );
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 600,
    });
    window.dispatchEvent(new window.Event("resize"));
    expect(dialog.style.left).toBe("198px");

    panel.close();
    await window.close();
  });

  test("shows a generated password beside the login fields without storing it", async () => {
    const { window, document, anchor } = page();
    let used = "";
    let saves = 0;
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      undefined,
      [],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated(password) {
          used = password;
        },
        async save() {
          saves += 1;
        },
        async update() {},
        async addTOTP() {},
      },
    );

    const fields = [
      ...panel.root.querySelectorAll<HTMLElement>(".login > .field"),
    ];
    expect(fields.slice(0, 3).map((element) => element.className)).toEqual([
      "field field-title",
      "field field-username",
      "field field-password",
    ]);
    const password = panel.root.querySelector<HTMLInputElement>(
      ".field-password input",
    );
    expect(password?.type).toBe("text");
    expect(password?.value).toHaveLength(24);
    expect(panel.root.querySelector(".generator-options")).not.toBeNull();

    panel.root
      .querySelector<HTMLButtonElement>("button.use")
      ?.click();
    expect(saves).toBe(0);
    expect(used).toBe(password!.value);
    expect(saves).toBe(0);

    panel.root
      .querySelector<HTMLButtonElement>('button[data-mode="pin"]')
      ?.click();
    expect(password?.value).toMatch(/^\d{6}$/);
    expect(
      panel.root.querySelector<HTMLDivElement>(".strength")?.classList.contains(
        "is-hidden",
      ),
    ).toBe(true);
    panel.close();
    await window.close();
  });

  test("supports the ARIA radio keyboard pattern for password modes", async () => {
    const { window, document, anchor } = page();
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      undefined,
      [],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save() {},
        async update() {},
        async addTOTP() {},
      },
    );
    const modes = [
      ...panel.root.querySelectorAll<HTMLButtonElement>('[role="radio"]'),
    ];
    expect(modes.map((mode) => mode.tabIndex)).toEqual([0, -1, -1]);
    modes[0].focus();
    modes[0].dispatchEvent(
      new window.KeyboardEvent("keydown", {
        key: "ArrowRight",
        bubbles: true,
      }) as unknown as Event,
    );

    expect(modes[1].getAttribute("aria-checked")).toBe("true");
    expect(modes.map((mode) => mode.tabIndex)).toEqual([-1, 0, -1]);
    expect(panel.root.activeElement).toBe(modes[1]);
    panel.close();
    await window.close();
  });

  test("binds update and TOTP actions to the selected opaque revision", async () => {
    const { window, document, anchor } = page();
    const calls: unknown[] = [];
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      { username: "user", password: "new-secret", kind: "login" },
      [{
        id: "opaque",
        title: "<img src=x>",
        username: "user",
        revision: "7",
        scopeId: "s_personal",
        scope: "Personal",
      }],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save(input) {
          calls.push(["save", input]);
        },
        async update(input) {
          calls.push(["update", input]);
        },
        async addTOTP(input) {
          calls.push(["totp", input]);
        },
      },
    );

    const buttons = [...panel.root.querySelectorAll<HTMLButtonElement>("button")];
    buttons.find((button) => button.textContent === "Update login")?.click();
    await settle();
    expect(calls[0]).toEqual([
      "update",
      {
        credentialId: "opaque",
        revision: "7",
        title: "<img src=x>",
        username: "user",
        password: "new-secret",
      },
    ]);
    expect(panel.root.querySelector("img")).toBeNull();
    panel.close();
    await window.close();
  });

  test("selects only the account matching the submitted username", async () => {
    const { window, document, anchor } = page();
    const updates: unknown[] = [];
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      { username: "bob", password: "bob-new", kind: "login" },
      [
        {
          id: "alice-id",
          title: "Alice",
          username: "alice",
          revision: "1",
          scopeId: "s_personal",
          scope: "Personal",
        },
        {
          id: "bob-id",
          title: "Bob",
          username: "bob",
          revision: "4",
          scopeId: "s_personal",
          scope: "Personal",
        },
      ],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save() {},
        async update(input) {
          updates.push(input);
        },
        async addTOTP() {},
      },
    );

    expect(panel.root.querySelector<HTMLSelectElement>(".field-match select")?.value).toBe(
      "bob-id",
    );
    [...panel.root.querySelectorAll<HTMLButtonElement>("button")]
      .find((button) => button.textContent === "Update login")
      ?.click();
    await settle();
    expect(updates).toEqual([
      {
        credentialId: "bob-id",
        revision: "4",
        title: "Bob",
        username: "bob",
        password: "bob-new",
      },
    ]);
    panel.close();
    await window.close();
  });

  test("requires an explicit account choice when the username is ambiguous", async () => {
    const { window, document, anchor } = page();
    let updates = 0;
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      { username: "", password: "new-secret", kind: "password-change" },
      [
        {
          id: "first",
          title: "First",
          revision: "1",
          scopeId: "s_personal",
          scope: "Personal",
        },
        {
          id: "second",
          title: "Second",
          revision: "2",
          scopeId: "s_personal",
          scope: "Personal",
        },
      ],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save() {},
        async update() {
          updates += 1;
        },
        async addTOTP() {},
      },
    );

    const update = [...panel.root.querySelectorAll<HTMLButtonElement>("button")].find(
      (button) => button.textContent === "Update login",
    );
    expect(panel.root.querySelector<HTMLSelectElement>(".field-match select")?.value).toBe("");
    expect(update?.disabled).toBe(true);
    update?.click();
    await settle();
    expect(updates).toBe(0);
    panel.close();
    await window.close();
  });

  test("does not infer the only saved account when the username differs", async () => {
    const { window, document, anchor } = page();
    let updates = 0;
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      { username: "new-account", password: "new-secret", kind: "login" },
      [{
        id: "existing",
        title: "Existing",
        username: "someone-else",
        revision: "3",
        scopeId: "s_personal",
        scope: "Personal",
      }],
      [{ id: "s_personal", label: "Personal" }],
      {
        useGenerated() {},
        async save() {},
        async update() {
          updates += 1;
        },
        async addTOTP() {},
      },
    );

    const update = [...panel.root.querySelectorAll<HTMLButtonElement>("button")].find(
      (button) => button.textContent === "Update login",
    );
    expect(panel.root.querySelector<HTMLSelectElement>(".field-match select")?.value).toBe("");
    expect(update?.disabled).toBe(true);
    update?.click();
    await settle();
    expect(updates).toBe(0);
    panel.close();
    await window.close();
  });

  test("returns focus to the field after a successful save", async () => {
    const { window, document, anchor } = page();
    anchor.focus();
    const panel = mountCredentialActionPanel(
      document,
      anchor,
      "https://example.com",
      { username: "demo", password: "synthetic-secret", kind: "login" },
      [],
      [{ id: "s_personal", label: "Personal" }],
      { useGenerated() {}, async save() {}, async update() {}, async addTOTP() {} },
    );
    const save = [...panel.root.querySelectorAll<HTMLButtonElement>("button")]
      .find((element) => element.textContent?.trim() === "Save login");
    expect(save).toBeDefined();
    save!.focus();
    save!.click();
    await settle();
    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(document.querySelector("[data-fd0-credential-actions]")).toBeNull();
    expect(document.activeElement).toBe(anchor);
    await window.close();
  });
});
