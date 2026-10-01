export type InputMetadata = {
  type: string;
  autocomplete: string;
  name: string;
  id: string;
};

export type LoginFields = {
  username?: HTMLInputElement;
  password: HTMLInputElement;
};

export type CredentialFields = {
  username?: HTMLInputElement;
  currentPassword?: HTMLInputElement;
  newPassword?: HTMLInputElement;
  confirmPassword?: HTMLInputElement;
  otp?: HTMLInputElement;
};

export type LoginCandidate = {
  username: string;
  password: string;
  kind: "login" | "signup" | "password-change";
};

type FormAnchor = Element | ShadowRoot | undefined;
type InputRoot = Document | ShadowRoot | HTMLFormElement;

function autocompleteTokens(value: string): string[] {
  return value.toLowerCase().trim().split(/\s+/);
}

export function usernameScore(field: InputMetadata): number {
  if (!["text", "email", "tel"].includes(field.type)) return 0;
  const autocomplete = autocompleteTokens(field.autocomplete);
  if (autocomplete.includes("username")) return 120;
  if (autocomplete.includes("email")) return 110;

  const identity = `${field.name} ${field.id}`.toLowerCase();
  if (/\b(user(name)?|login|email)\b/.test(identity)) return 90;
  if (field.type === "email") return 80;
  if (field.type === "text") return 20;
  return 0;
}

export function passwordScore(field: InputMetadata): number {
  if (field.type !== "password") return 0;
  const autocomplete = autocompleteTokens(field.autocomplete);
  if (autocomplete.includes("new-password")) return -1;
  if (autocomplete.includes("current-password")) return 120;
  return 60;
}

export function findLoginFields(
  document: Document,
  anchor?: FormAnchor,
): LoginFields | undefined {
  const fields = findCredentialFields(document, anchor);
  return fields.currentPassword
    ? { username: fields.username, password: fields.currentPassword }
    : undefined;
}

export function findCredentialFields(
  document: Document,
  anchor?: FormAnchor,
): CredentialFields {
  if (anchor && !anchor.isConnected) return {};
  const inputs = collectInputs(inputRoot(document, anchor)).filter(isFillable);
  const passwordInputs = inputs.filter((input) => input.type.toLowerCase() === "password");
  const currentPassword = passwordInputs.find(
    (input) => autocompleteTokens(input.autocomplete).includes("current-password"),
  ) ?? passwordInputs.find((input) =>
    !autocompleteTokens(input.autocomplete).includes("new-password") &&
    /\b(old|current|existing)\b/i.test(passwordIdentity(input)),
  ) ??
    (passwordInputs.length === 1 &&
    !autocompleteTokens(passwordInputs[0].autocomplete).includes("new-password") &&
    !/\b(new|create|signup|register|confirm|confirmation|repeat|again|verify|retype)\b/i.test(passwordIdentity(passwordInputs[0]))
      ? passwordInputs[0]
      : undefined);
  const confirmationInputs = passwordInputs.filter((input) =>
    /\b(confirm|confirmation|repeat|again|verify|retype)\b|\b(password|passwd|pwd|pass)\s*2\b/i.test(
      passwordIdentity(input),
    ),
  );
  const explicitNewPasswords = passwordInputs.filter(
    (input) => autocompleteTokens(input.autocomplete).includes("new-password"),
  );
  const namedNewPasswords = passwordInputs.filter(
    (input) =>
      input !== currentPassword && !confirmationInputs.includes(input) &&
      /\b(new|create|signup|register)\b/i.test(
        passwordIdentity(input),
      ),
  );
  const newPassword =
    explicitNewPasswords.find((input) => !confirmationInputs.includes(input)) ??
    namedNewPasswords[0] ??
    (confirmationInputs.length === 1 && passwordInputs.length <= 3
      ? passwordInputs.find(
          (input) => input !== currentPassword && !confirmationInputs.includes(input),
        )
      : undefined);
  const confirmPassword =
    confirmationInputs.find((input) => input !== newPassword) ??
    explicitNewPasswords.find((input) => input !== newPassword);
  const passwordAnchor = currentPassword ?? newPassword;
  const beforePassword = passwordAnchor
    ? inputs.filter(
        (input) =>
          input !== passwordAnchor &&
          Boolean(input.compareDocumentPosition(passwordAnchor) & Node.DOCUMENT_POSITION_FOLLOWING),
      )
    : inputs;
  // An explicit autocomplete=username wins wherever it sits, e.g. an input
  // associated via form=. Otherwise the username precedes the password, so a
  // later email field (newsletter, recovery address) is not mistaken for it.
  const username = inputs.find((input) => autocompleteTokens(input.autocomplete).includes("username")) ??
    bestInput(beforePassword, usernameScore) ??
    bestInput(inputs.filter((input) => input.type.toLowerCase() !== "password"), usernameScore);
  const otp = bestInput(inputs, otpScore);
  return { username, currentPassword, newPassword, confirmPassword, otp };
}

function passwordIdentity(input: HTMLInputElement): string {
  return `${input.name} ${input.id} ${input.getAttribute("aria-label") ?? ""}`.replace(/([a-z])([A-Z])/g, "$1 $2").replace(
    /[_-]+/g,
    " ",
  );
}

export function readLoginCandidate(
  document: Document,
  anchor?: FormAnchor,
): LoginCandidate | undefined {
  const fields = findCredentialFields(document, anchor);
  const password = fields.newPassword?.value || fields.currentPassword?.value || "";
  if (!password) return undefined;
  const kind = fields.newPassword
    ? fields.currentPassword
      ? "password-change"
      : "signup"
    : "login";
  return {
    username: fields.username?.value.trim() ?? "",
    password,
    kind,
  };
}

export function fillGeneratedPassword(
  document: Document,
  password: string,
  anchor?: FormAnchor,
): { passwordFilled: boolean; confirmationFilled: boolean } {
  const fields = findCredentialFields(document, anchor);
  const target = fields.newPassword ?? fields.currentPassword;
  if (!target) return { passwordFilled: false, confirmationFilled: false };
  setInputValue(target, password);
  let confirmationFilled = false;
  if (fields.confirmPassword && fields.confirmPassword !== target) {
    setInputValue(fields.confirmPassword, password);
    confirmationFilled = true;
  }
  return { passwordFilled: true, confirmationFilled };
}

export function fillOTP(
  document: Document,
  code: string,
  anchor?: FormAnchor,
): boolean {
  const field = findCredentialFields(document, anchor).otp;
  if (!field || field.value !== "") return false;
  setInputValue(field, code);
  return true;
}

export function otpScore(field: InputMetadata): number {
  const autocomplete = autocompleteTokens(field.autocomplete);
  if (autocomplete.includes("one-time-code")) return 140;
  const identity = `${field.name} ${field.id}`.toLowerCase().replace(/[_-]+/g, " ");
  if (/\b(otp|totp|one.?time|verification.?code|auth.?code|2fa|mfa)\b/.test(identity)) {
    return field.type === "text" || field.type === "tel" || field.type === "number" ? 100 : 0;
  }
  return 0;
}

export function fillLogin(
  document: Document,
  credential: { username?: string; password: string },
  anchor?: FormAnchor,
): { usernameFilled: boolean; passwordFilled: boolean } {
  const fields = findLoginFields(document, anchor);
  if (!fields) return { usernameFilled: false, passwordFilled: false };

  let usernameFilled = false;
  if (fields.username && credential.username) {
    setInputValue(fields.username, credential.username);
    usernameFilled = true;
  }
  // Page input handlers can synchronously replace or disable the password field.
  if (!fields.password.isConnected || !isFillable(fields.password) ||
    findLoginFields(document, anchor)?.password !== fields.password) {
    return { usernameFilled, passwordFilled: false };
  }
  setInputValue(fields.password, credential.password);
  return { usernameFilled, passwordFilled: true };
}

function bestInput(
  inputs: HTMLInputElement[],
  score: (metadata: InputMetadata) => number,
): HTMLInputElement | undefined {
  let best: { input: HTMLInputElement; score: number } | undefined;
  for (const input of inputs) {
    const current = score({
      type: input.type.toLowerCase(),
      autocomplete: input.autocomplete,
      name: input.name,
      id: input.id,
    });
    if (current > 0 && (!best || current > best.score)) {
      best = { input, score: current };
    }
  }
  return best?.input;
}

export function collectInputs(root: InputRoot): HTMLInputElement[] {
  const inputs = root instanceof HTMLFormElement
    ? [...root.elements].filter((element): element is HTMLInputElement => element instanceof HTMLInputElement)
    : [...root.querySelectorAll<HTMLInputElement>("input")];
  for (const element of root.querySelectorAll<HTMLElement>("*")) {
    if (element.shadowRoot) {
      inputs.push(...collectInputs(element.shadowRoot));
    }
  }
  return inputs;
}

function inputRoot(document: Document, anchor: FormAnchor): InputRoot {
  if (!anchor) return document;
  if (anchor instanceof ShadowRoot) return anchor;
  if (anchor instanceof HTMLFormElement) return anchor;
  if (anchor instanceof HTMLInputElement && anchor.form) return anchor.form;
  const form = anchor.closest("form");
  if (form) return form;
  const root = anchor.getRootNode();
  return root instanceof ShadowRoot ? root : document;
}

export function isFillable(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || input.type === "hidden") return false;
  const style = getComputedStyle(input);
  if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
    return false;
  }
  const rect = input.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

function setInputValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) throw new Error("Browser does not expose the input value setter.");
  setter.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}
