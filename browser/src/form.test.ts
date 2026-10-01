import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";

import {
  fillGeneratedPassword,
  fillLogin,
  fillOTP,
  findCredentialFields,
  findLoginFields,
  passwordScore,
  readLoginCandidate,
  usernameScore,
} from "./form";

function visible(input: HTMLInputElement): HTMLInputElement {
  input.style.display = "block";
  input.style.visibility = "visible";
  input.style.opacity = "1";
  input.getBoundingClientRect = () =>
    ({
      top: 10,
      left: 10,
      right: 210,
      bottom: 50,
      width: 200,
      height: 40,
      x: 10,
      y: 10,
      toJSON: () => ({}),
    }) as DOMRect;
  return input;
}

function page(): { window: Window; document: Document } {
  const window = new Window({ url: "https://example.com/register" });
  Object.assign(globalThis, {
    Node: window.Node,
    getComputedStyle: window.getComputedStyle.bind(window),
    HTMLInputElement: window.HTMLInputElement,
    HTMLFormElement: window.HTMLFormElement,
    ShadowRoot: window.ShadowRoot,
    Event: window.Event,
  });
  return { window, document: window.document as unknown as Document };
}

describe("login field scoring", () => {
  test("prefers explicit username metadata", () => {
    expect(
      usernameScore({
        type: "text",
        autocomplete: "username",
        name: "",
        id: "",
      }),
    ).toBeGreaterThan(
      usernameScore({
        type: "email",
        autocomplete: "",
        name: "",
        id: "",
      }),
    );
  });

  test("rejects new-password fields for login fill", () => {
    expect(
      passwordScore({
        type: "password",
        autocomplete: "new-password",
        name: "password",
        id: "",
      }),
    ).toBe(-1);
  });

  test("does not treat unrelated fields as credentials", () => {
    expect(
      usernameScore({
        type: "search",
        autocomplete: "",
        name: "query",
        id: "site-search",
      }),
    ).toBe(0);
    expect(
      passwordScore({
        type: "text",
        autocomplete: "",
        name: "password",
        id: "",
      }),
    ).toBe(0);
  });
});

describe("credential form engine", () => {
  test("respects autocomplete token lists for signup, usernames and OTP", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<form><input autocomplete="section-signup username webauthn"><input type="password" autocomplete="section-signup new-password"><input type="password" autocomplete="section-signup new-password"><input autocomplete="section-signup one-time-code"></form>';
    document.querySelectorAll("input").forEach(visible);
    const inputs = document.querySelectorAll("input");
    expect(findCredentialFields(document)).toEqual({ username: inputs[0], currentPassword: undefined, newPassword: inputs[1], confirmPassword: inputs[2], otp: inputs[3] });
    expect(fillLogin(document, { username: "demo", password: "existing" }, inputs[0]).passwordFilled).toBe(false);
    expect(inputs[1].value).toBe("");
    await window.close();
  });

  test("keeps old, new and repeated passwords separate without autocomplete", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<form><input type="password" name="old_password"><input type="password" name="newPassword"><input type="password" name="confirm_password"></form>';
    document.querySelectorAll("input").forEach(visible);
    const inputs = document.querySelectorAll("input");
    expect(fillLogin(document, { password: "old-demo" }, inputs[0]).passwordFilled).toBe(true);
    expect(inputs[0].value).toBe("old-demo");
    expect(inputs[1].value).toBe("");
    expect(fillGeneratedPassword(document, "new-demo", inputs[1])).toEqual({ passwordFilled: true, confirmationFilled: true });
    expect(inputs[0].value).toBe("old-demo");
    expect(inputs[2].value).toBe("new-demo");
    expect(readLoginCandidate(document, inputs[1])?.kind).toBe("password-change");
    await window.close();
  });

  test("fills numbered confirmation pairs without guessing unrelated password fields", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<form><input type="password" name="password"><input type="password" name="password2"></form>';
    document.querySelectorAll("input").forEach(visible);
    const inputs = document.querySelectorAll("input");
    expect(fillGeneratedPassword(document, "new-demo")).toEqual({ passwordFilled: true, confirmationFilled: true });
    expect(inputs[1].value).toBe("new-demo");
    inputs[0].name = "primary";
    inputs[1].name = "secondary";
    expect(fillGeneratedPassword(document, "do-not-guess").passwordFilled).toBe(false);
    expect(inputs[1].value).toBe("new-demo");
    await window.close();
  });

  test("includes externally associated fields and excludes fields owned by another form", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<form id="signin"><input type="password" autocomplete="current-password"></form><input form="signin" autocomplete="username"><form id="other"><input form="other" autocomplete="username" value="unrelated"></form>';
    document.querySelectorAll("input").forEach(visible);
    const username = document.querySelector<HTMLInputElement>('[form="signin"]')!;
    expect(fillLogin(document, { username: "demo", password: "secret" }, username)).toEqual({ usernameFilled: true, passwordFilled: true });
    expect(username.value).toBe("demo");
    expect(document.querySelector<HTMLInputElement>('[form="other"]')!.value).toBe("unrelated");
    await window.close();
  });

  test("does not fill another form for a detached anchor", async () => {
    const { window, document } = page();
    const anchor = visible(document.createElement("input"));
    const password = visible(document.createElement("input"));
    password.type = "password";
    document.body.append(password);
    expect(fillLogin(document, { password: "secret" }, anchor).passwordFilled).toBe(false);
    expect(fillGeneratedPassword(document, "secret", anchor).passwordFilled).toBe(false);
    expect(password.value).toBe("");
    await window.close();
  });

  test("stops if a page replaces the password field in its username input handler", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form>';
    document.querySelectorAll("input").forEach(visible);
    const username = document.querySelector<HTMLInputElement>("input")!;
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    const replacement = visible(document.createElement("input"));
    replacement.type = "password";
    username.addEventListener("input", () => password.replaceWith(replacement));
    expect(fillLogin(document, { username: "demo", password: "secret" }, username)).toEqual({ usernameFilled: true, passwordFilled: false });
    expect(password.value).toBe("");
    expect(replacement.value).toBe("");
    await window.close();
  });

  test("keeps an existing OTP and recognizes underscore-separated OTP names", async () => {
    const { window, document } = page();
    const field = visible(document.createElement("input"));
    field.name = "otp_code";
    field.value = "654321";
    document.body.append(field);
    expect(fillOTP(document, "123456")).toBe(false);
    expect(field.value).toBe("654321");
    field.value = "";
    expect(fillOTP(document, "123456")).toBe(true);
    await window.close();
  });

  test("finds login fields inside open shadow roots", async () => {
    const { window, document } = page();
    const host = document.createElement("login-form");
    const root = host.attachShadow({ mode: "open" });
    const username = visible(document.createElement("input"));
    username.autocomplete = "username";
    const password = visible(document.createElement("input"));
    password.type = "password";
    password.autocomplete = "current-password";
    root.append(username, password);
    document.body.append(host);

    expect(findLoginFields(document)).toEqual({ username, password });
    await window.close();
  });

  test("classifies signup fields and fills password confirmation", async () => {
    const { window, document } = page();
    const username = visible(document.createElement("input"));
    username.autocomplete = "username";
    username.value = "person@example.com";
    const password = visible(document.createElement("input"));
    password.type = "password";
    password.autocomplete = "new-password";
    const confirmation = visible(document.createElement("input"));
    confirmation.type = "password";
    confirmation.autocomplete = "new-password";
    confirmation.name = "confirm-password";
    document.body.append(username, password, confirmation);

    expect(findCredentialFields(document)).toMatchObject({
      username,
      newPassword: password,
      confirmPassword: confirmation,
    });
    expect(fillGeneratedPassword(document, "a strong generated password")).toEqual({
      passwordFilled: true,
      confirmationFilled: true,
    });
    expect(password.value).toBe("a strong generated password");
    expect(confirmation.value).toBe("a strong generated password");
    expect(readLoginCandidate(document)).toEqual({
      username: "person@example.com",
      password: "a strong generated password",
      kind: "signup",
    });
    await window.close();
  });

  test("uses the first unlabelled signup password before its confirmation", async () => {
    const { window, document } = page();
    const password = visible(document.createElement("input"));
    password.type = "password";
    password.name = "password";
    const confirmation = visible(document.createElement("input"));
    confirmation.type = "password";
    confirmation.name = "password_confirmation";
    document.body.append(password, confirmation);

    const fields = findCredentialFields(document);
    expect(fields.newPassword).toBe(password);
    expect(fields.confirmPassword).toBe(confirmation);
    expect(fillGeneratedPassword(document, "generated-secret")).toEqual({
      passwordFilled: true,
      confirmationFilled: true,
    });
    expect(password.value).toBe("generated-secret");
    expect(confirmation.value).toBe("generated-secret");
    await window.close();
  });

  test("fills a visible OTP field but ignores readonly decoys", async () => {
    const { window, document } = page();
    const decoy = visible(document.createElement("input"));
    decoy.autocomplete = "one-time-code";
    decoy.readOnly = true;
    const otp = visible(document.createElement("input"));
    otp.name = "verification-code";
    otp.type = "text";
    document.body.append(decoy, otp);

    expect(fillOTP(document, "123456")).toBe(true);
    expect(decoy.value).toBe("");
    expect(otp.value).toBe("123456");
    await window.close();
  });

  test("never combines credentials from separate forms", async () => {
    const { window, document } = page();
    const first = document.createElement("form");
    const firstUsername = visible(document.createElement("input"));
    firstUsername.autocomplete = "username";
    firstUsername.value = "alice";
    const firstPassword = visible(document.createElement("input"));
    firstPassword.type = "password";
    firstPassword.autocomplete = "current-password";
    firstPassword.value = "alice-secret";
    first.append(firstUsername, firstPassword);

    const second = document.createElement("form");
    const secondUsername = visible(document.createElement("input"));
    secondUsername.autocomplete = "username";
    secondUsername.value = "bob";
    const secondPassword = visible(document.createElement("input"));
    secondPassword.type = "password";
    secondPassword.autocomplete = "new-password";
    secondPassword.value = "bob-secret";
    second.append(secondUsername, secondPassword);
    document.body.append(first, second);

    expect(readLoginCandidate(document, first)).toEqual({
      username: "alice",
      password: "alice-secret",
      kind: "login",
    });
    expect(readLoginCandidate(document, secondPassword)).toEqual({
      username: "bob",
      password: "bob-secret",
      kind: "signup",
    });
    await window.close();
  });

  test("prefers the field before the password over a later email field", async () => {
    const { window, document } = page();
    document.body.innerHTML = '<input name="username"><input type="password" autocomplete="new-password"><input type="email" autocomplete="email" name="recovery">';
    const inputs = [...document.querySelectorAll("input")].map(visible);
    expect(findCredentialFields(document).username).toBe(inputs[0]);
    await window.close();
  });

  test("recognizes confirmation fields named again, verify and retype", async () => {
    for (const name of ["passwordAgain", "verify_password", "retype-password"]) {
      const { window, document } = page();
      document.body.innerHTML = `<form><input name="user"><input type="password" name="password"><input type="password" name="${name}"></form>`;
      const inputs = [...document.querySelectorAll("input")].map(visible);
      const fields = findCredentialFields(document);
      expect(fields.newPassword).toBe(inputs[1]);
      expect(fields.confirmPassword).toBe(inputs[2]);
      await window.close();
    }
  });
});
