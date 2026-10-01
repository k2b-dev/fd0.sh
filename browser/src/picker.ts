export type LoginMatch = {
  id: string;
  title: string;
  username?: string;
  revision?: string;
  hasTotp?: boolean;
  scopeId?: string;
  scope?: string;
};

export type LoginPicker = {
  host: HTMLElement;
  root: ShadowRoot;
  close: (restoreFocus?: boolean) => void;
  focusFirst: () => void;
};

export type LoginNotice = {
  host: HTMLElement;
  close: () => void;
};

export type LoginTrigger = {
  host: HTMLElement;
  root: ShadowRoot;
  setBusy: (busy: boolean) => void;
  close: () => void;
};

export type LoginPrompt = {
  host: HTMLElement;
  root: ShadowRoot;
  close: (restoreFocus?: boolean) => void;
};

export function mountLoginTrigger(
  document: Document,
  anchor: HTMLElement,
  activate: () => void,
): LoginTrigger {
  const host = document.createElement("div");
  host.dataset.fd0LoginTrigger = "";
  host.style.cssText =
    "all:initial;position:fixed;inset:0;z-index:2147483646;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = triggerStyles;
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "f";
  button.setAttribute("aria-label", "Open fd0 logins");
  root.append(style, button);
  document.documentElement.append(host);

  let closed = false;
  const view = document.defaultView;
  function position(): void {
    if (closed) return;
    const rect = anchor.getBoundingClientRect();
    button.hidden = !anchor.isConnected || rect.width < 64 || rect.height < 24;
    button.style.left = `${Math.max(4, rect.right - 30)}px`;
    button.style.top = `${Math.max(4, rect.top + (rect.height - 24) / 2)}px`;
  }
  function onClick(event: Event): void {
    event.preventDefault();
    event.stopPropagation();
    activate();
  }
  function setBusy(busy: boolean): void {
    button.setAttribute("aria-busy", String(busy));
    button.disabled = busy;
  }
  function close(): void {
    if (closed) return;
    closed = true;
    button.removeEventListener("click", onClick);
    view?.removeEventListener("resize", position);
    view?.removeEventListener("scroll", position, true);
    host.remove();
  }
  button.addEventListener("click", onClick);
  view?.addEventListener("resize", position);
  view?.addEventListener("scroll", position, true);
  position();
  view?.requestAnimationFrame(position);
  return { host, root, setBusy, close };
}

export function mountLoginPrompt(
  document: Document,
  anchor: HTMLElement,
  title: string,
  message: string,
  retry: () => void,
  onClose?: (restoredFocus: boolean) => void,
): LoginPrompt {
  const host = document.createElement("div");
  host.dataset.fd0LoginPrompt = "";
  host.style.cssText =
    "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = pickerStyles;

  const panel = document.createElement("section");
  panel.className = "panel prompt";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "false");
  panel.setAttribute("aria-labelledby", "fd0-prompt-title");

  const header = document.createElement("header");
  const brand = document.createElement("span");
  brand.className = "brand";
  brand.textContent = "fd0";
  const heading = document.createElement("span");
  heading.id = "fd0-prompt-title";
  heading.className = "heading";
  heading.textContent = title;
  const closeButton = document.createElement("button");
  closeButton.className = "close";
  closeButton.type = "button";
  closeButton.setAttribute("aria-label", "Close fd0");
  closeButton.textContent = "×";
  header.append(brand, heading, closeButton);

  const body = document.createElement("div");
  body.className = "prompt-body";
  const description = document.createElement("p");
  description.textContent = message;
  const retryButton = document.createElement("button");
  retryButton.className = "retry";
  retryButton.type = "button";
  retryButton.textContent = "Try again";
  body.append(description, retryButton);
  panel.append(header, body);
  root.append(style, panel);
  document.documentElement.append(host);

  let closed = false;
  const view = document.defaultView;

  function position(): void {
    if (closed) return;
    const rect = anchor.getBoundingClientRect();
    const viewportWidth = view?.innerWidth ?? document.documentElement.clientWidth;
    const viewportHeight = view?.innerHeight ?? document.documentElement.clientHeight;
    const width = Math.min(320, Math.max(240, viewportWidth - 24));
    const left = Math.min(
      Math.max(12, rect.left),
      Math.max(12, viewportWidth - width - 12),
    );
    panel.style.width = `${width}px`;
    panel.style.left = `${left}px`;
    const height = panel.getBoundingClientRect().height || 168;
    const below = rect.bottom + 8;
    panel.style.top = `${
      below + height <= viewportHeight - 12
        ? below
        : Math.max(12, rect.top - height - 8)
    }px`;
  }

  function close(restoreFocus = true): void {
    if (closed) return;
    closed = true;
    closeButton.removeEventListener("click", onCloseClick);
    retryButton.removeEventListener("click", onRetry);
    document.removeEventListener("pointerdown", onPointerDown, true);
    view?.removeEventListener("resize", position);
    view?.removeEventListener("scroll", position, true);
    host.remove();
    const restored = restoreFocus && anchor.isConnected;
    onClose?.(restored);
    if (restored) anchor.focus({ preventScroll: true });
  }
  function onCloseClick(): void {
    close();
  }
  function onRetry(): void {
    close(false);
    retry();
  }
  function onPointerDown(event: Event): void {
    if (!event.composedPath().includes(host)) close(false);
  }

  closeButton.addEventListener("click", onCloseClick);
  retryButton.addEventListener("click", onRetry);
  document.addEventListener("pointerdown", onPointerDown, true);
  view?.addEventListener("resize", position);
  view?.addEventListener("scroll", position, true);
  position();
  view?.requestAnimationFrame(position);
  retryButton.focus({ preventScroll: true });

  return { host, root, close };
}

export function mountLoginNotice(
  document: Document,
  message: string,
  tone: "neutral" | "error" = "neutral",
): LoginNotice {
  const host = document.createElement("div");
  host.dataset.fd0LoginNotice = "";
  host.style.cssText =
    "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = noticeStyles;
  const notice = document.createElement("div");
  notice.className = "notice";
  notice.dataset.tone = tone;
  notice.setAttribute("role", tone === "error" ? "alert" : "status");
  notice.setAttribute("aria-live", tone === "error" ? "assertive" : "polite");
  const brand = document.createElement("span");
  brand.className = "brand";
  brand.textContent = "fd0";
  const text = document.createElement("span");
  text.textContent = message;
  notice.append(brand, text);
  root.append(style, notice);
  document.documentElement.append(host);

  let closed = false;
  const timeout = document.defaultView?.setTimeout(() => close(), tone === "error" ? 6000 : 3500);
  function close(): void {
    if (closed) return;
    closed = true;
    if (timeout !== undefined) document.defaultView?.clearTimeout(timeout);
    host.remove();
  }
  return { host, close };
}

export function mountLoginPicker(
  document: Document,
  anchor: HTMLElement,
  matches: LoginMatch[],
  select: (credentialId: string, signal: AbortSignal) => Promise<void>,
  onClose?: (restoredFocus: boolean) => void,
  openTools?: () => void,
  focusOnOpen = true,
): LoginPicker {
  if (matches.length === 0) throw new Error("A login picker requires at least one match.");

  const host = document.createElement("div");
  host.dataset.fd0LoginPicker = "";
  host.style.cssText =
    "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = pickerStyles;

  const panel = document.createElement("section");
  panel.className = "panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "false");
  panel.setAttribute("aria-labelledby", "fd0-picker-title");

  const header = document.createElement("header");
  const brand = document.createElement("span");
  brand.className = "brand";
  brand.textContent = "fd0";
  const heading = document.createElement("span");
  heading.id = "fd0-picker-title";
  heading.className = "heading";
  heading.textContent = matches.length === 1 ? "Fill this login" : "Choose a login";
  const closeButton = document.createElement("button");
  closeButton.className = "close";
  closeButton.type = "button";
  closeButton.setAttribute("aria-label", "Close fd0");
  closeButton.textContent = "×";
  header.append(brand, heading, closeButton);

  const list = document.createElement("div");
  list.className = "list";
  list.setAttribute("role", "listbox");
  list.setAttribute("aria-label", "Matching fd0 logins");

  const status = document.createElement("div");
  status.className = "status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");

  const options = matches.map((match, index) => {
    const option = document.createElement("button");
    option.className = "option";
    option.type = "button";
    option.setAttribute("role", "option");
    option.setAttribute("aria-selected", String(index === 0));
    option.tabIndex = index === 0 ? 0 : -1;

    const title = document.createElement("span");
    title.className = "title";
    title.textContent = match.title || "Untitled login";
    const username = document.createElement("span");
    username.className = "username";
    username.textContent = match.username || "No username";
    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.setAttribute("aria-hidden", "true");
    arrow.textContent = "→";
    option.append(title, username, arrow);
    option.addEventListener("click", () => void choose(index));
    list.append(option);
    return option;
  });

  const toolsButton = document.createElement("button");
  toolsButton.className = "tools";
  toolsButton.type = "button";
  toolsButton.textContent = "Password tools";
  if (openTools) {
    toolsButton.addEventListener("click", () => {
      close(false);
      openTools();
    });
  }
  panel.append(header, list, status);
  if (openTools) panel.append(toolsButton);
  root.append(style, panel);
  document.documentElement.append(host);

  let activeIndex = 0;
  let busy = false;
  let selection: AbortController | undefined;
  let closed = false;
  const view = document.defaultView;

  function activate(index: number, focus = true): void {
    activeIndex = (index + options.length) % options.length;
    options.forEach((option, current) => {
      const active = current === activeIndex;
      option.tabIndex = active ? 0 : -1;
      option.setAttribute("aria-selected", String(active));
    });
    if (focus) options[activeIndex].focus();
  }

  async function choose(index: number): Promise<void> {
    if (busy || closed) return;
    activate(index, false);
    busy = true;
    panel.dataset.busy = "";
    options.forEach((option) => {
      option.disabled = true;
    });
    status.textContent = "Filling login…";
    try {
      selection = new AbortController();
      await select(matches[index].id, selection.signal);
      close(false);
    } catch (error) {
      if (closed) return;
      busy = false;
      delete panel.dataset.busy;
      options.forEach((option) => {
        option.disabled = false;
      });
      status.textContent =
        error instanceof Error && error.message
          ? error.message
          : "fd0 could not fill this login.";
      activate(index);
    }
  }

  function position(): void {
    if (closed) return;
    list.toggleAttribute(
      "data-scrollable",
      list.clientHeight > 0 && list.scrollHeight > list.clientHeight,
    );
    const rect = anchor.getBoundingClientRect();
    const viewportWidth = view?.innerWidth ?? document.documentElement.clientWidth;
    const viewportHeight = view?.innerHeight ?? document.documentElement.clientHeight;
    const width = Math.min(320, Math.max(240, viewportWidth - 24));
    const left = Math.min(
      Math.max(12, rect.left),
      Math.max(12, viewportWidth - width - 12),
    );
    panel.style.width = `${width}px`;
    panel.style.left = `${left}px`;

    const height = panel.getBoundingClientRect().height || Math.min(320, 116 + matches.length * 64);
    const below = rect.bottom + 8;
    const top =
      below + height <= viewportHeight - 12
        ? below
        : Math.max(12, rect.top - height - 8);
    panel.style.top = `${top}px`;
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (busy) return;
    if (!event.composedPath().includes(list)) return;
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        activate(activeIndex + 1);
        break;
      case "ArrowUp":
        event.preventDefault();
        activate(activeIndex - 1);
        break;
      case "Home":
        event.preventDefault();
        activate(0);
        break;
      case "End":
        event.preventDefault();
        activate(options.length - 1);
        break;
      case "Enter":
        event.preventDefault();
        void choose(activeIndex);
        break;
    }
  }

  function onPointerDown(event: Event): void {
    if (!event.composedPath().includes(host)) close(false);
  }

  function onCloseClick(): void {
    close();
  }

  function close(restoreFocus = true): void {
    if (closed) return;
    closed = true;
    selection?.abort();
    panel.removeEventListener("keydown", onKeyDown);
    closeButton.removeEventListener("click", onCloseClick);
    document.removeEventListener("pointerdown", onPointerDown, true);
    view?.removeEventListener("resize", position);
    view?.removeEventListener("scroll", position, true);
    host.remove();
    const restored = restoreFocus && anchor.isConnected;
    onClose?.(restored);
    if (restored) anchor.focus({ preventScroll: true });
  }

  panel.addEventListener("keydown", onKeyDown);
  closeButton.addEventListener("click", onCloseClick);
  document.addEventListener("pointerdown", onPointerDown, true);
  view?.addEventListener("resize", position);
  view?.addEventListener("scroll", position, true);
  position();
  view?.requestAnimationFrame(position);
  const focusFirst = () => options[0].focus({ preventScroll: true });
  if (focusOnOpen) focusFirst();

  return { host, root, close, focusFirst };
}

const pickerStyles = `
  :host {
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  .panel {
    --fd0-bg: #0d100e;
    --fd0-raised: #121612;
    --fd0-hover: #171b17;
    --fd0-selected: #211f13;
    --fd0-border: #2b312c;
    --fd0-text: #f1efe9;
    --fd0-text-2: #c3c7c1;
    --fd0-muted: #949b95;
    --fd0-accent: #ffb000;
    --fd0-accent-hover: #ffc23b;
    --fd0-accent-on: #171105;
    position: fixed;
    overflow: hidden;
    max-height: min(420px, calc(100vh - 24px));
    color: var(--fd0-text);
    background: var(--fd0-bg);
    border: 1px solid var(--fd0-border);
    border-radius: 10px;
    box-shadow: 0 6px 24px rgb(0 0 0 / 44%), 0 1px 2px rgb(0 0 0 / 40%);
    font-family: "Geist Variable", "SF Pro Text", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 13px;
    font-synthesis: none;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
    pointer-events: auto;
  }
  header {
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 8px;
    min-height: 40px;
    padding: 8px 8px 6px 12px;
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    color: var(--fd0-text);
    font-size: 12px;
    font-weight: 680;
    letter-spacing: -0.015em;
  }
  .brand::before {
    width: 6px;
    height: 6px;
    background: var(--fd0-accent);
    border-radius: 50%;
    box-shadow: 0 0 0 3px var(--fd0-selected);
    content: "";
  }
  .heading {
    overflow: hidden;
    color: var(--fd0-text-2);
    font-size: 12px;
    font-weight: 550;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  button {
    appearance: none;
    font: inherit;
    color: inherit;
  }
  .close {
    width: 28px;
    height: 28px;
    padding: 0;
    color: var(--fd0-muted);
    background: transparent;
    border: 0;
    border-radius: 4px;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
  }
  .close:hover { background: var(--fd0-hover); color: var(--fd0-text); }
  .close:focus-visible { outline: 2px solid var(--fd0-accent); outline-offset: -2px; }
  .list {
    display: grid;
    gap: 4px;
    max-height: 280px;
    padding: 2px 8px 8px;
    overflow: auto;
    scrollbar-gutter: auto;
  }
  .list[data-scrollable] {
    scrollbar-gutter: stable;
  }
  .option {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 2px 12px;
    width: 100%;
    min-height: 48px;
    padding: 8px 10px;
    text-align: left;
    background: transparent;
    border: 0;
    border-radius: 6px;
    cursor: pointer;
  }
  .option:hover { background: var(--fd0-hover); }
  .option[aria-selected="true"] { background: var(--fd0-selected); }
  .option:focus-visible {
    outline: 2px solid var(--fd0-accent);
    outline-offset: -2px;
  }
  .option:disabled { cursor: wait; opacity: 0.62; }
  .title {
    min-width: 0;
    overflow: hidden;
    font-weight: 550;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .username {
    min-width: 0;
    overflow: hidden;
    color: var(--fd0-muted);
    font-size: 12px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .arrow {
    grid-column: 2;
    grid-row: 1 / span 2;
    align-self: center;
    color: var(--fd0-muted);
    color: var(--fd0-accent);
    font-size: 15px;
  }
  .status {
    min-height: 0;
    margin: 0 18px;
    color: #ef8177;
    font-size: 11px;
  }
  .status:not(:empty) { min-height: 24px; padding: 4px 0 7px; }
  .panel[data-busy] .status { color: var(--fd0-muted); }
  .tools {
    width: calc(100% - 16px);
    min-height: 32px;
    margin: 0 8px 8px;
    color: var(--fd0-text-2);
    background: var(--fd0-raised);
    border: 0;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }
  .tools:hover { background: var(--fd0-hover); color: var(--fd0-text); }
  .tools:focus-visible { outline: 2px solid var(--fd0-accent); outline-offset: -2px; }
  .prompt-body {
    display: grid;
    gap: 12px;
    padding: 3px 12px 12px;
  }
  .prompt-body p {
    margin: 0;
    color: var(--fd0-muted);
    font-size: 12px;
    line-height: 1.45;
  }
  .retry {
    justify-self: start;
    height: 30px;
    padding: 0 12px;
    color: var(--fd0-accent-on);
    background: var(--fd0-accent);
    border: 1px solid var(--fd0-accent-hover);
    border-radius: 6px;
    font-size: 12px;
    font-weight: 680;
    cursor: pointer;
  }
  .retry:hover { background: var(--fd0-accent-hover); }
  .retry:focus-visible { outline: 2px solid var(--fd0-text); outline-offset: 2px; }
  @media (prefers-reduced-motion: no-preference) {
    .panel { animation: fd0-in 90ms cubic-bezier(0.2, 0, 0.1, 1); transform-origin: top center; }
    @keyframes fd0-in {
      from { opacity: 0; transform: translateY(-2px); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
  }
`;

const noticeStyles = `
  :host {
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  .notice {
    --fd0-bg: #0d100e;
    --fd0-border: #2b312c;
    --fd0-text: #f1efe9;
    --fd0-accent: #ffb000;
    position: fixed;
    top: 16px;
    right: 16px;
    display: grid;
    grid-template-columns: auto 1fr;
    align-items: center;
    gap: 8px;
    max-width: min(320px, calc(100vw - 32px));
    min-height: 40px;
    padding: 8px 12px;
    color: var(--fd0-text);
    background: var(--fd0-bg);
    border: 1px solid var(--fd0-border);
    border-radius: 10px;
    box-shadow: 0 6px 24px rgb(0 0 0 / 44%), 0 1px 2px rgb(0 0 0 / 40%);
    font-family: "Geist Variable", "SF Pro Text", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 12px;
    font-synthesis: none;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }
  .notice[data-tone="error"] { --fd0-border: #653b37; }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-weight: 680;
  }
  .brand::before {
    width: 6px;
    height: 6px;
    background: var(--fd0-accent);
    border-radius: 50%;
    content: "";
  }
  @media (prefers-reduced-motion: no-preference) {
    .notice { animation: fd0-notice-in 90ms cubic-bezier(0.2, 0, 0.1, 1); }
    @keyframes fd0-notice-in {
      from { opacity: 0; transform: translateY(-3px); }
      to { opacity: 1; transform: translateY(0); }
    }
  }
`;

const triggerStyles = `
  :host {
    color-scheme: dark;
  }
  button {
    position: fixed;
    display: grid;
    place-items: center;
    width: 24px;
    height: 24px;
    padding: 0;
    color: #ffb000;
    background: #0d100e;
    border: 1px solid #2b312c;
    border-radius: 6px;
    box-shadow: 0 1px 3px rgb(0 0 0 / 38%);
    font: 680 13px/1 "Geist Variable", "SF Pro Text", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-synthesis: none;
    -webkit-font-smoothing: antialiased;
    pointer-events: auto;
    cursor: pointer;
  }
  button:hover { background: #171b17; border-color: #5c4a1d; }
  button:focus-visible { outline: 2px solid #ffb000; outline-offset: 2px; }
  button[aria-busy="true"] { color: transparent; cursor: wait; }
  button[aria-busy="true"]::after {
    position: absolute;
    width: 12px;
    height: 12px;
    border: 2px solid rgb(255 176 0 / 28%);
    border-top-color: #ffb000;
    border-radius: 50%;
    content: "";
    animation: fd0-spin 650ms linear infinite;
  }
  button[hidden] { display: none; }
  @keyframes fd0-spin { to { transform: rotate(360deg); } }
`;
