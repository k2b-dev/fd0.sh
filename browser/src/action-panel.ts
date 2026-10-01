import type { LoginCandidate } from "./form";
import {
  defaultGeneratorSettings,
  generatePassword,
  passwordStrength,
  type GeneratorMode,
  type GeneratorSettings,
} from "./password-generator";
import type { LoginMatch } from "./picker";

export type VaultChoice = {
  id: string;
  label: string;
};

export type CredentialActions = {
  useGenerated(password: string): void;
  save(input: {
    title: string;
    username: string;
    password: string;
    scopeId: string;
  }): Promise<void>;
  update(input: {
    credentialId: string;
    revision: string;
    title: string;
    username: string;
    password: string;
  }): Promise<void>;
  addTOTP(input: {
    credentialId: string;
    revision: string;
    uri: string;
  }): Promise<void>;
};

export type ActionLoginMatch = LoginMatch & {
  revision: string;
  hasTotp?: boolean;
  scopeId: string;
  scope: string;
};

export type CredentialActionPanel = {
  host: HTMLElement;
  root: ShadowRoot;
  close(restoreFocus?: boolean): void;
};

export function mountCredentialActionPanel(
  document: Document,
  anchor: HTMLElement,
  origin: string,
  candidate: LoginCandidate | undefined,
  matches: ActionLoginMatch[],
  scopes: VaultChoice[],
  actions: CredentialActions,
  focusOnOpen = true,
): CredentialActionPanel {
  const host = document.createElement("div");
  host.dataset.fd0CredentialActions = "";
  host.style.cssText =
    "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = styles;
  const panel = document.createElement("section");
  panel.className = "panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-label", "fd0 login editor");

  const header = document.createElement("header");
  const brand = document.createElement("strong");
  brand.textContent = "fd0";
  const heading = document.createElement("span");
  heading.textContent = matches.length > 0 ? "Update login" : "Save login";
  const closeButton = button(document, "×", "close");
  closeButton.setAttribute("aria-label", "Close fd0");
  header.append(brand, heading, closeButton);

  const body = document.createElement("div");
  body.className = "body";
  const loginSection = document.createElement("section");
  loginSection.className = "login";

  const normalizedCandidateUsername = candidate?.username.trim().toLocaleLowerCase();
  const usernameMatches = normalizedCandidateUsername
    ? matches.filter(
        (match) =>
          match.username?.trim().toLocaleLowerCase() === normalizedCandidateUsername,
      )
    : [];
  const initialMatch =
    usernameMatches.length === 1 ? usernameMatches[0] : undefined;
  const selected = select(
    document,
    "Login",
    [
      ...(matches.length > 0 && !initialMatch
        ? [{ value: "", label: "Choose the login to update" }]
        : []),
      ...matches.map((match) => ({
        value: match.id,
        label: `${match.title}${match.username ? ` · ${match.username}` : ""}`,
      })),
    ],
  );
  selected.value = initialMatch?.id ?? "";
  if (matches.length > 0) {
    loginSection.append(field(document, "Update", selected, "field-match"));
  }

  const hostname = safeHostname(origin) || document.location.hostname || "Login";
  const title = input(document, initialMatch?.title || hostname);
  title.autocomplete = "off";
  const username = input(document, candidate?.username ?? initialMatch?.username ?? "");
  username.autocomplete = "username";
  loginSection.append(
    field(document, "Login title", title, "field-title"),
    field(document, "Username", username, "field-username"),
  );

  const settings: GeneratorSettings = { ...defaultGeneratorSettings };
  const passwordInput = input(
    document,
    candidate?.password || generatePassword(settings),
  );
  passwordInput.type = "text";
  passwordInput.autocomplete = "new-password";
  passwordInput.spellcheck = false;
  const passwordControls = document.createElement("div");
  passwordControls.className = "password-control";
  const regenerateButton = button(document, "↻", "icon");
  regenerateButton.setAttribute("aria-label", "Generate another password");
  regenerateButton.title = "Generate another password";
  const visibilityButton = button(document, "Hide", "visibility");
  visibilityButton.setAttribute("aria-label", "Hide password");
  passwordControls.append(passwordInput, regenerateButton, visibilityButton);
  const passwordField = field(
    document,
    "Password",
    passwordControls,
    "field-password",
  );
  loginSection.append(passwordField);

  const modePicker = document.createElement("div");
  modePicker.className = "segmented";
  modePicker.setAttribute("role", "radiogroup");
  modePicker.setAttribute("aria-label", "Password type");
  const modeButtons = ([
    ["random", "Random"],
    ["memorable", "Memorable"],
    ["pin", "PIN"],
  ] as const).map(([mode, label]) => {
    const control = button(document, label, "mode");
    control.dataset.mode = mode;
    control.setAttribute("role", "radio");
    modePicker.append(control);
    return control;
  });
  loginSection.append(modePicker);

  const generatorOptions = document.createElement("div");
  generatorOptions.className = "generator-options";
  const strength = document.createElement("div");
  strength.className = "strength";
  const strengthTrack = document.createElement("div");
  strengthTrack.className = "strength-track";
  const strengthFill = document.createElement("div");
  strengthFill.className = "strength-fill";
  strengthTrack.append(strengthFill);
  const strengthCopy = document.createElement("div");
  strengthCopy.className = "strength-copy";
  const strengthLabel = document.createElement("span");
  const strengthTime = document.createElement("span");
  strengthCopy.append(strengthLabel, strengthTime);
  strength.append(strengthTrack, strengthCopy);
  loginSection.append(generatorOptions, strength);

  const useButton = button(document, "Use password", "secondary use");
  const scope = select(
    document,
    "Vault",
    scopes.map((choice) => ({ value: choice.id, label: choice.label })),
  );
  if (initialMatch?.scopeId) scope.value = initialMatch.scopeId;
  if (scopes.length > 1) {
    loginSection.append(field(document, "Vault", scope, "field-vault"));
  }

  const saveActions = document.createElement("div");
  saveActions.className = "actions";
  const updateButton = button(document, "Update login", "primary");
  updateButton.disabled = !initialMatch;
  const saveButton = button(
    document,
    matches.length > 0 ? "Save as new" : "Save login",
    matches.length > 0 ? "quiet" : "primary",
  );
  saveActions.append(useButton);
  if (matches.length > 0) saveActions.append(updateButton);
  saveActions.append(saveButton);
  loginSection.append(saveActions);
  body.append(loginSection);

  const totpDetails = document.createElement("details");
  totpDetails.className = "totp";
  const totpSummary = document.createElement("summary");
  totpSummary.textContent = initialMatch?.hasTotp
    ? "Replace one-time password"
    : "Add one-time password";
  const totpBody = document.createElement("div");
  totpBody.className = "totp-body";
  const totpURI = input(document, "");
  totpURI.placeholder = "Paste otpauth:// setup link";
  totpURI.setAttribute("aria-label", "TOTP setup link");
  totpURI.autocomplete = "off";
  const totpButton = button(document, "Add to login", "secondary");
  totpButton.disabled = !initialMatch;
  totpBody.append(totpURI, totpButton);
  totpDetails.append(totpSummary, totpBody);

  const status = document.createElement("p");
  status.className = "status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  body.append(totpDetails, status);
  panel.append(header, body);
  root.append(style, panel);
  document.documentElement.append(host);

  let closed = false;
  const view = document.defaultView;
  const viewportInset = 12;
  let dragged = false;
  let panelPosition: { left: number; top: number } | undefined;
  let drag:
    | {
        pointerId: number;
        offsetX: number;
        offsetY: number;
      }
    | undefined;

  function selectedMatch(): ActionLoginMatch | undefined {
    return matches.find((match) => match.id === selected.value);
  }

  function currentPassword(): string {
    return passwordInput.value;
  }

  function renderStrength(): void {
    const result = passwordStrength(passwordInput.value);
    const isPIN = settings.mode === "pin";
    strength.classList.toggle("is-hidden", isPIN);
    strength.setAttribute("aria-hidden", String(isPIN));
    strengthFill.dataset.score = String(result.score);
    strengthFill.style.width = `${(result.score + 1) * 20}%`;
    strengthLabel.textContent = result.label;
    strengthTime.textContent = `${result.crackTime} to crack`;
  }

  function regenerate(): void {
    passwordInput.value = generatePassword(settings);
    renderStrength();
  }

  function renderOptions(): void {
    generatorOptions.replaceChildren();
    for (const control of modeButtons) {
      const active = control.dataset.mode === settings.mode;
      control.classList.toggle("is-active", active);
      control.setAttribute("aria-checked", String(active));
      control.tabIndex = active ? 0 : -1;
    }

    switch (settings.mode) {
      case "memorable":
        generatorOptions.append(
          range(
            document,
            "Words",
            3,
            10,
            settings.words,
            (value) => {
              settings.words = value;
              regenerate();
            },
          ),
          compactSelect(
            document,
            "Separator",
            settings.separator,
            [
              { value: "-", label: "Hyphen" },
              { value: " ", label: "Space" },
              { value: ".", label: "Period" },
              { value: "_", label: "Underscore" },
            ],
            (value) => {
              settings.separator = value;
              regenerate();
            },
          ),
          toggle(document, "Capitalise words", settings.capitalize, (checked) => {
            settings.capitalize = checked;
            regenerate();
          }),
          toggle(document, "Add a number", settings.addNumber, (checked) => {
            settings.addNumber = checked;
            regenerate();
          }),
          toggle(document, "Add a symbol", settings.addSymbol, (checked) => {
            settings.addSymbol = checked;
            regenerate();
          }),
        );
        break;
      case "pin":
        generatorOptions.append(
          range(
            document,
            "Digits",
            4,
            12,
            settings.pinLength,
            (value) => {
              settings.pinLength = value;
              regenerate();
            },
          ),
        );
        break;
      default:
        generatorOptions.append(
          range(
            document,
            "Length",
            12,
            64,
            settings.length,
            (value) => {
              settings.length = value;
              regenerate();
            },
          ),
          toggle(document, "Uppercase letters", settings.uppercase, (checked) => {
            settings.uppercase = checked;
            regenerate();
          }),
          toggle(document, "Numbers", settings.numbers, (checked) => {
            settings.numbers = checked;
            regenerate();
          }),
          toggle(document, "Symbols", settings.symbols, (checked) => {
            settings.symbols = checked;
            regenerate();
          }),
        );
    }
    position();
  }

  async function run(action: () => Promise<void>, success: string): Promise<void> {
    if (panel.dataset.busy !== undefined) return;
    panel.dataset.busy = "";
    for (const control of panel.querySelectorAll<
      HTMLButtonElement | HTMLInputElement | HTMLSelectElement
    >("button,input,select")) {
      control.disabled = true;
    }
    status.dataset.tone = "neutral";
    status.textContent = "Working…";
    try {
      await action();
      status.textContent = success;
      // Disabled controls drop focus to the page; hand it back to the field
      // unless the user has moved on in the meantime.
      view?.setTimeout(() => {
        const active = document.activeElement;
        close(!active || active === host || active === document.body);
      }, 700);
    } catch (error) {
      delete panel.dataset.busy;
      for (const control of panel.querySelectorAll<
        HTMLButtonElement | HTMLInputElement | HTMLSelectElement
      >("button,input,select")) {
        control.disabled = false;
      }
      const hasSelectedMatch = Boolean(selectedMatch());
      updateButton.disabled = !hasSelectedMatch;
      totpButton.disabled = !hasSelectedMatch;
      status.dataset.tone = "error";
      status.textContent =
        error instanceof Error
          ? error.message
          : "fd0 could not complete this action.";
    }
  }

  function requirePassword(): string {
    const value = currentPassword();
    if (!value) throw new Error("Enter or generate a password first.");
    return value;
  }

  function onUse(): void {
    try {
      actions.useGenerated(requirePassword());
      status.dataset.tone = "neutral";
      status.textContent = "Password filled. Save it before leaving this page.";
    } catch (error) {
      status.dataset.tone = "error";
      status.textContent =
        error instanceof Error ? error.message : "No password field was found.";
    }
  }

  function onSave(): void {
    void run(
      () =>
        actions.save({
          title: title.value.trim() || hostname,
          username: username.value.trim(),
          password: requirePassword(),
          scopeId: scope.value || scopes[0]?.id || "",
        }),
      "Login saved in fd0.",
    );
  }

  function onUpdate(): void {
    const match = selectedMatch();
    if (!match) return;
    void run(
      () =>
        actions.update({
          credentialId: match.id,
          revision: match.revision,
          title: title.value.trim() || match.title,
          username: username.value.trim(),
          password: requirePassword(),
        }),
      "Login updated in fd0.",
    );
  }

  function onAddTOTP(): void {
    const match = selectedMatch();
    if (!match) return;
    void run(
      () =>
        actions.addTOTP({
          credentialId: match.id,
          revision: match.revision,
          uri: totpURI.value.trim(),
        }),
      "One-time password added to fd0.",
    );
  }

  function position(): void {
    if (closed) return;
    const viewportWidth = view?.innerWidth ?? 420;
    const viewportHeight = view?.innerHeight ?? 760;
    const width = Math.min(390, Math.max(0, viewportWidth - viewportInset * 2));
    panel.style.width = `${width}px`;
    const rect = panel.getBoundingClientRect();
    const panelWidth = rect.width || width;
    const panelHeight =
      rect.height ||
      Math.min(620, Math.max(0, viewportHeight - viewportInset * 2));
    const desired =
      dragged && panelPosition
        ? panelPosition
        : {
            left: viewportWidth - panelWidth - viewportInset,
            top: viewportInset,
          };
    panelPosition = clampPosition(
      desired.left,
      desired.top,
      panelWidth,
      panelHeight,
    );
    applyPosition(panelPosition);
  }

  function clampPosition(
    left: number,
    top: number,
    panelWidth: number,
    panelHeight: number,
  ): { left: number; top: number } {
    const viewportWidth = view?.innerWidth ?? 420;
    const viewportHeight = view?.innerHeight ?? 760;
    return {
      left: Math.min(
        Math.max(viewportInset, left),
        Math.max(viewportInset, viewportWidth - panelWidth - viewportInset),
      ),
      top: Math.min(
        Math.max(viewportInset, top),
        Math.max(viewportInset, viewportHeight - panelHeight - viewportInset),
      ),
    };
  }

  function applyPosition(next: { left: number; top: number }): void {
    panel.style.left = `${next.left}px`;
    panel.style.top = `${next.top}px`;
  }

  function onDragStart(event: PointerEvent): void {
    const target = event.target as HTMLElement | null;
    if (event.button !== 0 || target?.closest?.("button,input,select,a")) return;
    const rect = panel.getBoundingClientRect();
    dragged = true;
    drag = {
      pointerId: event.pointerId,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
    };
    header.classList.add("is-dragging");
    if (typeof header.setPointerCapture === "function") {
      try {
        header.setPointerCapture(event.pointerId);
      } catch {
        // Some embedded documents do not expose pointer capture.
      }
    }
    event.preventDefault();
  }

  function onDragMove(event: PointerEvent): void {
    if (!drag || event.pointerId !== drag.pointerId) return;
    const rect = panel.getBoundingClientRect();
    panelPosition = clampPosition(
      event.clientX - drag.offsetX,
      event.clientY - drag.offsetY,
      rect.width || Number.parseFloat(panel.style.width),
      rect.height ||
        Math.min(
          620,
          Math.max(0, (view?.innerHeight ?? 760) - viewportInset * 2),
        ),
    );
    applyPosition(panelPosition);
    event.preventDefault();
  }

  function onDragEnd(event: PointerEvent): void {
    if (!drag || event.pointerId !== drag.pointerId) return;
    drag = undefined;
    header.classList.remove("is-dragging");
    if (
      typeof header.hasPointerCapture === "function" &&
      header.hasPointerCapture(event.pointerId)
    ) {
      try {
        header.releasePointerCapture(event.pointerId);
      } catch {
        // The browser may already have released capture.
      }
    }
  }

  function close(restoreFocus = true): void {
    if (closed) return;
    closed = true;
    document.removeEventListener("pointerdown", onPointerDown, true);
    document.removeEventListener("keydown", onKeyDown, true);
    view?.removeEventListener("resize", position);
    passwordInput.value = "";
    totpURI.value = "";
    host.remove();
    if (restoreFocus && anchor.isConnected) anchor.focus({ preventScroll: true });
  }

  function onPointerDown(event: Event): void {
    if (panel.dataset.busy === undefined && !event.composedPath().includes(host)) close(false);
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (event.key !== "Escape" || panel.dataset.busy !== undefined) return;
    event.preventDefault();
    event.stopPropagation();
    close();
  }

  selected.addEventListener("change", () => {
    const match = selectedMatch();
    updateButton.disabled = !match;
    totpButton.disabled = !match;
    if (!match) return;
    title.value = match.title;
    username.value = match.username ?? "";
    scope.value = match.scopeId;
    totpSummary.textContent = match.hasTotp
      ? "Replace one-time password"
      : "Add one-time password";
  });
  for (const control of modeButtons) {
    control.addEventListener("click", () => {
      settings.mode = control.dataset.mode as GeneratorMode;
      renderOptions();
      regenerate();
    });
    control.addEventListener("keydown", (event) => {
      const current = modeButtons.indexOf(control);
      let next: number | undefined;
      if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        next = (current + modeButtons.length - 1) % modeButtons.length;
      } else if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        next = (current + 1) % modeButtons.length;
      } else if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = modeButtons.length - 1;
      }
      if (next === undefined) return;
      event.preventDefault();
      settings.mode = modeButtons[next].dataset.mode as GeneratorMode;
      renderOptions();
      regenerate();
      modeButtons[next].focus();
    });
  }
  passwordInput.addEventListener("input", renderStrength);
  regenerateButton.addEventListener("click", regenerate);
  visibilityButton.addEventListener("click", () => {
    const visible = passwordInput.type === "text";
    passwordInput.type = visible ? "password" : "text";
    visibilityButton.textContent = visible ? "Show" : "Hide";
    visibilityButton.setAttribute(
      "aria-label",
      visible ? "Show password" : "Hide password",
    );
  });
  closeButton.addEventListener("click", () => close());
  useButton.addEventListener("click", onUse);
  saveButton.addEventListener("click", onSave);
  updateButton.addEventListener("click", onUpdate);
  totpButton.addEventListener("click", onAddTOTP);
  header.addEventListener("pointerdown", onDragStart);
  header.addEventListener("pointermove", onDragMove);
  header.addEventListener("pointerup", onDragEnd);
  header.addEventListener("pointercancel", onDragEnd);
  header.addEventListener("lostpointercapture", onDragEnd);
  document.addEventListener("pointerdown", onPointerDown, true);
  document.addEventListener("keydown", onKeyDown, true);
  view?.addEventListener("resize", position);

  renderOptions();
  renderStrength();
  position();
  const previousFocus = document.activeElement;
  view?.requestAnimationFrame(() => {
    if (closed) return;
    position();
    if (focusOnOpen && document.activeElement === previousFocus) {
      (matches.length > 0 ? selected : title).focus({ preventScroll: true });
    }
  });
  return { host, root, close };
}

function button(
  document: Document,
  text: string,
  className: string,
): HTMLButtonElement {
  const result = document.createElement("button");
  result.type = "button";
  result.className = className;
  result.textContent = text;
  return result;
}

function input(document: Document, value: string): HTMLInputElement {
  const result = document.createElement("input");
  result.value = value;
  return result;
}

let fieldSequence = 0;

function field(
  document: Document,
  label: string,
  control: HTMLElement,
  className: string,
): HTMLDivElement {
  const result = document.createElement("div");
  result.className = `field ${className}`;
  const copy = document.createElement("label");
  copy.textContent = label;
  const focusable: HTMLElement | null = control.matches("input,select")
    ? control
    : control.querySelector<HTMLElement>("input,select");
  if (focusable) {
    const id = `fd0-login-field-${++fieldSequence}`;
    focusable.id = id;
    copy.htmlFor = id;
  }
  result.append(copy, control);
  return result;
}

function select(
  document: Document,
  label: string,
  options: Array<{ value: string; label: string }>,
): HTMLSelectElement {
  const result = document.createElement("select");
  result.setAttribute("aria-label", label);
  for (const option of options) {
    const element = document.createElement("option");
    element.value = option.value;
    element.textContent = option.label;
    result.append(element);
  }
  return result;
}

function range(
  document: Document,
  label: string,
  min: number,
  max: number,
  value: number,
  onChange: (value: number) => void,
): HTMLLabelElement {
  const result = document.createElement("label");
  result.className = "range";
  const copy = document.createElement("span");
  copy.textContent = label;
  const control = document.createElement("input");
  control.type = "range";
  control.min = String(min);
  control.max = String(max);
  control.value = String(value);
  control.setAttribute("aria-label", label);
  const output = document.createElement("output");
  output.value = String(value);
  control.addEventListener("input", () => {
    output.value = control.value;
    onChange(Number(control.value));
  });
  result.append(copy, control, output);
  return result;
}

function toggle(
  document: Document,
  label: string,
  checked: boolean,
  onChange: (checked: boolean) => void,
): HTMLLabelElement {
  const result = document.createElement("label");
  result.className = "toggle";
  const copy = document.createElement("span");
  copy.textContent = label;
  const control = document.createElement("input");
  control.type = "checkbox";
  control.checked = checked;
  control.addEventListener("change", () => onChange(control.checked));
  const track = document.createElement("span");
  track.className = "toggle-track";
  result.append(copy, control, track);
  return result;
}

function compactSelect(
  document: Document,
  label: string,
  value: string,
  options: Array<{ value: string; label: string }>,
  onChange: (value: string) => void,
): HTMLLabelElement {
  const result = document.createElement("label");
  result.className = "compact-select";
  const copy = document.createElement("span");
  copy.textContent = label;
  const control = select(document, label, options);
  control.value = value;
  control.addEventListener("change", () => onChange(control.value));
  result.append(copy, control);
  return result;
}

function safeHostname(origin: string): string {
  try {
    return new URL(origin).hostname;
  } catch {
    return "";
  }
}

const styles = `
  :host { color-scheme: dark; }
  * { box-sizing: border-box; }
  .panel {
    --bg:#0d100e;--raised:#141713;--field:#0f120f;--border:#2b312c;
    --text:#f1efe9;--muted:#949b95;--accent:#ffb000;--accent-on:#171105;
    --error:#ef8177;--good:#7fbf86;
    position:fixed;max-height:calc(100vh - 24px);overflow:auto;padding:0;
    color:var(--text);background:var(--bg);border:1px solid var(--border);
    border-radius:10px;box-shadow:0 8px 30px rgb(0 0 0 / 48%);
    font:13px/1.4 "Geist Variable","SF Pro Text",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    pointer-events:auto;
  }
  header {
    position:sticky;top:0;z-index:2;display:grid;grid-template-columns:auto 1fr auto;
    align-items:center;gap:8px;min-height:42px;padding:7px 8px 7px 12px;background:var(--bg);
    cursor:grab;touch-action:none;user-select:none;
  }
  header.is-dragging { cursor:grabbing; }
  header strong { display:flex;align-items:center;gap:7px;font-size:12px; }
  header strong::before { width:6px;height:6px;border-radius:50%;background:var(--accent);content:""; }
  header span { color:#c3c7c1;font-size:12px; }
  button,input,select { font:inherit;color:inherit; }
  button { cursor:pointer; }
  button:disabled { cursor:wait;opacity:.55; }
  button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible {
    outline:2px solid var(--accent);outline-offset:1px;
  }
  .close { width:28px;height:28px;padding:0;color:var(--muted);background:transparent;border:0;font-size:20px; }
  .body { display:grid;gap:8px;padding:0 8px 8px; }
  .login { display:grid;gap:9px;padding:11px;background:var(--raised);border-radius:7px; }
  .field { display:grid;gap:4px;color:var(--muted);font-size:11px; }
  .field > input,.field > select,.password-control {
    width:100%;height:36px;background:var(--field);border:1px solid var(--border);border-radius:6px;
  }
  .field > input,.field > select { padding:0 9px;color:var(--text);font-size:13px; }
  .password-control { display:grid;grid-template-columns:minmax(0,1fr) 32px 39px;align-items:center; }
  .password-control input {
    min-width:0;height:34px;padding:0 9px;color:var(--text);background:transparent;border:0;
    font:12px/1.3 ui-monospace,"SFMono-Regular",Consolas,monospace;
  }
  .password-control input:focus-visible { outline:0; }
  .icon,.visibility {
    height:30px;padding:0;color:var(--muted);background:transparent;border:0;border-radius:5px;
  }
  .icon { font-size:18px; }
  .visibility { font-size:11px; }
  .icon:hover,.visibility:hover,.close:hover { color:var(--text);background:#1b1f1b; }
  .segmented { display:flex;gap:3px;padding:3px;background:var(--field);border:1px solid var(--border);border-radius:6px; }
  .mode { flex:1;height:29px;color:var(--muted);background:transparent;border:0;border-radius:4px;font-size:12px;font-weight:600; }
  .mode:hover { color:var(--text); }
  .mode.is-active { color:var(--text);background:#22261f; }
  .generator-options { display:grid;align-content:start;gap:7px;min-height:177px; }
  .range { display:grid;grid-template-columns:82px minmax(0,1fr) 28px;align-items:center;gap:8px;min-height:29px;color:var(--muted);font-size:12px; }
  .range input { appearance:none;width:100%;height:3px;border-radius:99px;background:#343a34; }
  .range input::-webkit-slider-thumb { appearance:none;width:14px;height:14px;border:0;border-radius:50%;background:var(--accent); }
  .range output { color:var(--text);font:11px ui-monospace,"SFMono-Regular",Consolas,monospace;text-align:right; }
  .toggle { position:relative;display:flex;align-items:center;justify-content:space-between;min-height:29px;color:#c9cdc7;font-size:12px; }
  .toggle input { position:absolute;width:1px;height:1px;opacity:0; }
  .toggle-track { position:relative;width:30px;height:17px;border:1px solid #485048;border-radius:99px;background:#202420; }
  .toggle-track::after { position:absolute;top:2px;left:2px;width:11px;height:11px;border-radius:50%;background:#8d958e;content:"";transition:transform 100ms ease; }
  .toggle input:checked + .toggle-track { border-color:#8d6500;background:#372b0d; }
  .toggle input:checked + .toggle-track::after { background:var(--accent);transform:translateX(13px); }
  .toggle input:focus-visible + .toggle-track { outline:2px solid var(--accent);outline-offset:2px; }
  .compact-select { display:grid;grid-template-columns:82px minmax(0,1fr);align-items:center;gap:8px;min-height:29px;color:var(--muted);font-size:12px; }
  .compact-select select { height:29px;padding:0 7px;background:var(--field);border:1px solid var(--border);border-radius:5px;font-size:12px; }
  .strength { display:grid;gap:5px;min-height:26px; }
  .strength.is-hidden { visibility:hidden; }
  .strength-track { height:3px;overflow:hidden;border-radius:99px;background:#272c27; }
  .strength-fill { height:100%;border-radius:inherit;background:var(--good);transition:width 120ms ease; }
  .strength-fill[data-score="0"] { background:var(--error); }
  .strength-fill[data-score="1"] { background:#d58a65; }
  .strength-fill[data-score="2"] { background:#d1a842; }
  .strength-copy { display:flex;justify-content:space-between;gap:10px;color:var(--muted);font-size:10px; }
  .strength-copy span:first-child { color:#c8ccc7;text-transform:capitalize; }
  .actions { display:flex;align-items:center;gap:7px;padding-top:1px; }
  .actions .use { margin-right:auto; }
  button.primary,button.secondary,button.quiet {
    min-height:32px;padding:0 10px;border-radius:6px;font-size:12px;font-weight:650;
  }
  button.primary { color:var(--accent-on);background:var(--accent);border:1px solid #ffc23b; }
  button.secondary { background:#1a1e1a;border:1px solid var(--border); }
  button.quiet { color:#c5c9c3;background:transparent;border:0; }
  button.quiet:hover { background:#1a1e1a; }
  .totp { padding:0 10px;background:var(--raised);border-radius:7px; }
  .totp summary { min-height:38px;padding:10px 0;color:#c8ccc7;cursor:pointer;font-size:12px;font-weight:600; }
  .totp-body { display:grid;gap:7px;padding:0 0 10px; }
  .totp-body input { width:100%;height:34px;padding:0 9px;background:var(--field);border:1px solid var(--border);border-radius:6px; }
  .status { min-height:0;margin:0 4px;color:var(--muted);font-size:11px; }
  .status:not(:empty) { min-height:22px;padding:3px 0; }
  .status[data-tone="error"] { color:var(--error); }
  @media (prefers-reduced-motion: reduce) {
    .toggle-track::after,.strength-fill { transition:none; }
  }
`;
