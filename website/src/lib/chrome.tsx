/**
 * Shared chrome — Nav + Footer for the three top-level pages.
 *
 * The visual identity (dark surface, amber accent, Geist sans + Geist
 * Mono code) is repeated everywhere instead of pushed into CSS so the
 * three pages remain self-contained and individually editable.
 */

export const C = {
  bg: "#0b0d0c",
  bgRaised: "#13161544",
  fg: "#e8e6e0",
  dim: "#7c7e7a",
  border: "#23262521",
  acc: "#ffb000",
  sage: "#a3c97a",
};

export const FONT_SANS = "Geist,Inter,system-ui,sans-serif";
export const FONT_MONO = "'Geist Mono',ui-monospace,monospace";

/** Latest signed fd0 Desktop release — the download everything points at. */
/*
 * Resolved server-side rather than linked straight at GitHub: /releases/latest
 * returns the newest release of any kind, and this repo tags client-v* and
 * desktop-v* into one feed, so a CLI release could send people to a page with
 * no app on it. /download picks the newest desktop-v* tag.
 */
export const DESKTOP_RELEASE_URL = "/download";

/**
 * Product screenshot with a caption that says what the reader is looking
 * at. The PNGs in public/shots are 2880×1800; `width`/`height` carry that
 * 16:10 ratio at half size so the browser reserves the box before the
 * bytes arrive and nothing reflows on load. Everything using this sits
 * below the fold, so the default is lazy.
 */
export const Shot = (p: {
  src: string;
  alt: string;
  title: string;
  body: string;
  eager?: boolean;
  /** Subordinate placement — smaller caption so it doesn't compete
   *  with the hero shot it sits under. */
  dense?: boolean;
}) => (
  <figure
    class="m-0 min-w-0"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <img
      src={p.src}
      alt={p.alt}
      width="1440"
      height="900"
      loading={p.eager ? "eager" : "lazy"}
      decoding="async"
      class="block w-full h-auto"
      style={`border-bottom:1px solid ${C.border};background:${C.bg};`}
    />
    <figcaption class={p.dense ? "p-4" : "p-5"}>
      <div
        class={`${p.dense ? "text-[12px]" : "text-[13px]"} font-medium mb-1.5`}
        style={`color:${C.acc};`}
      >
        {p.title}
      </div>
      <div
        class={`${p.dense ? "text-[12px]" : "text-[13px]"} leading-relaxed`}
        style={`color:${C.dim};`}
      >
        {p.body}
      </div>
    </figcaption>
  </figure>
);

export const LogoMark = (p: { size?: number }) => {
  const s = p.size ?? 20;
  const dot = s * 0.18;
  return (
    <span
      class="inline-block"
      style={`width:${s}px;height:${s}px;border:1.5px solid ${C.acc};position:relative;`}
    >
      <span
        class="absolute inset-0 m-auto block rounded-full"
        style={`background:${C.acc};width:${dot}px;height:${dot}px;top:50%;left:50%;transform:translate(-50%,-50%);`}
      />
    </span>
  );
};

type NavKey = "home" | "docs" | "spec" | "witness";

export const Nav = (p: { current?: NavKey }) => {
  const link = (key: NavKey, href: string, label: string) => (
    <a
      href={href}
      class="transition-colors"
      style={`color:${p.current === key ? C.fg : C.dim};`}
    >
      {label}
    </a>
  );
  return (
    <nav
      class="fd0-top-nav sticky top-0 z-30 px-6 md:px-10 flex items-center justify-between border-b text-sm backdrop-blur"
      style={`border-color:${C.border};background:${C.bg}f2;height:var(--fd0-nav-h);`}
    >
      <a
        href="/"
        class="flex items-center gap-2.5 font-medium"
        style={`color:${C.fg};`}
      >
        <LogoMark />
        <span>fd0</span>
        <span class="hidden sm:inline" style={`color:${C.dim};`}>
          / secrets you keep
        </span>
      </a>
      <div class="flex items-center gap-5 md:gap-7">
        {link("home", "/", "Home")}
        {link("docs", "/docs", "Docs")}
        {link("spec", "/spec", "Spec")}
        {link("witness", "/witness", "Witness")}
        <a
          href="https://github.com/k2b-dev/fd0.sh"
          class="hidden md:inline transition-colors"
          style={`color:${C.dim};`}
        >
          GitHub
        </a>
      </div>
    </nav>
  );
};

/* ─── Docs sidebar layout ─────────────────────────────────────────── */

export type DocsKey =
  | "overview"
  | "concepts"
  | "install"
  | "desktop"
  | "cli"
  | "pass"
  | "browser"
  | "ssh"
  | "talos"
  | "services"
  | "machines"
  | "server"
  | "yubikey"
  | "sync"
  | "recovery"
  | "troubleshooting";

export const DOCS_NAV: { key: DocsKey; href: string; label: string; group: string }[] = [
  { key: "overview", href: "/docs", label: "Overview", group: "Start" },
  { key: "concepts", href: "/docs/concepts", label: "Concepts", group: "Start" },
  { key: "install", href: "/docs/install", label: "Install", group: "Use" },
  { key: "desktop", href: "/docs/desktop", label: "Desktop app", group: "Use" },
  { key: "cli", href: "/docs/cli", label: "CLI reference", group: "Use" },
  { key: "pass", href: "/docs/pass", label: "Passwords", group: "Use" },
  { key: "browser", href: "/docs/browser", label: "Browser extension", group: "Use" },
  { key: "ssh", href: "/docs/ssh", label: "SSH", group: "Use" },
  { key: "talos", href: "/docs/talos", label: "Talos & Kube", group: "Use" },
  { key: "services", href: "/docs/services", label: "Services", group: "Use" },
  { key: "machines", href: "/docs/machines", label: "Machines & CI", group: "Use" },
  { key: "sync", href: "/docs/sync", label: "Sync", group: "Use" },
  { key: "server", href: "/docs/server", label: "Self-host server", group: "Deploy" },
  { key: "yubikey", href: "/docs/yubikey", label: "YubiKey unlock", group: "Hardware" },
  { key: "recovery", href: "/docs/recovery", label: "Recovery", group: "Hardware" },
  { key: "troubleshooting", href: "/docs/troubleshooting", label: "Troubleshooting", group: "Support" },
];

export const DocsLayout = (p: { current: DocsKey; title: string; kicker?: string; children: any }) => {
  const groups: Record<string, typeof DOCS_NAV> = {};
  for (const item of DOCS_NAV) {
    (groups[item.group] ??= []).push(item);
  }
  const groupOrder = ["Start", "Use", "Deploy", "Hardware", "Support"];
  return (
    <div
      class="min-h-screen"
      style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
    >
      <Nav current="docs" />
      <div class="max-w-7xl mx-auto px-6 md:px-10 pb-20 grid md:grid-cols-[14rem_1fr] gap-x-12 gap-y-8">
        {/* sidebar — sticks immediately below the sticky top nav.
            `top` and `max-height` reference --fd0-nav-h so they stay
            in lockstep with the nav's enforced height. Sticky engages
            at scroll 0 → the sidebar never visibly moves. */}
        <aside
          class="fd0-docs-sidebar md:sticky md:self-start text-sm md:overflow-y-auto md:pr-2 pt-6 md:pt-8 pb-6"
          style="top: var(--fd0-nav-h); max-height: calc(100vh - var(--fd0-nav-h));"
        >
          <div
            class="text-[11px] tracking-[0.18em] uppercase mb-4 pb-3"
            style={`color:${C.acc};border-bottom:1px solid ${C.border};`}
          >
            Docs
          </div>
          <nav class="flex flex-col gap-5">
            {groupOrder.map((g) =>
              groups[g] ? (
                <div>
                  <div
                    class="text-[10px] tracking-[0.18em] uppercase mb-2"
                    style={`color:${C.dim};`}
                  >
                    {g}
                  </div>
                  <div class="flex flex-col">
                    {groups[g].map((item) => {
                      const active = item.key === p.current;
                      return (
                        <a
                          href={item.href}
                          class="py-1.5 transition-colors text-[13.5px]"
                          style={
                            active
                              ? `color:${C.acc};border-left:2px solid ${C.acc};padding-left:10px;margin-left:-12px;`
                              : `color:${C.dim};border-left:2px solid transparent;padding-left:10px;margin-left:-12px;`
                          }
                        >
                          {item.label}
                        </a>
                      );
                    })}
                  </div>
                </div>
              ) : null
            )}
          </nav>
          <div
            class="mt-7 pt-4 text-[12px] leading-relaxed"
            style={`border-top:1px solid ${C.border};color:${C.dim};`}
          >
            Looking for the protocol?{" "}
            <a href="/spec" style={`color:${C.acc};`}>
              /spec
            </a>
          </div>
        </aside>

        {/* main content */}
        <main class="min-w-0 max-w-3xl pt-8 md:pt-10">
          {p.kicker ? (
            <div
              class="text-[11px] tracking-[0.18em] uppercase mb-3"
              style={`color:${C.acc};`}
            >
              {p.kicker}
            </div>
          ) : null}
          <h1 class="text-[2rem] md:text-[2.4rem] leading-[1.1] tracking-tight font-medium mb-8">
            {p.title}
          </h1>
          {p.children}

          {/* prev/next */}
          <DocsPager current={p.current} />
        </main>
      </div>
      <Footer />
    </div>
  );
};

const DocsPager = (p: { current: DocsKey }) => {
  const idx = DOCS_NAV.findIndex((x) => x.key === p.current);
  const prev = idx > 0 ? DOCS_NAV[idx - 1] : null;
  const next = idx >= 0 && idx < DOCS_NAV.length - 1 ? DOCS_NAV[idx + 1] : null;
  return (
    <div
      class="mt-16 pt-6 grid grid-cols-2 gap-4 text-sm"
      style={`border-top:1px solid ${C.border};`}
    >
      {prev ? (
        <a
          href={prev.href}
          class="p-4 transition-colors"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="text-[11px] mb-1" style={`color:${C.dim};`}>← Previous</div>
          <div style={`color:${C.acc};`}>{prev.label}</div>
        </a>
      ) : <div />}
      {next ? (
        <a
          href={next.href}
          class="p-4 transition-colors text-right"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="text-[11px] mb-1" style={`color:${C.dim};`}>Next →</div>
          <div style={`color:${C.acc};`}>{next.label}</div>
        </a>
      ) : <div />}
    </div>
  );
};

/* ─── Spec sidebar layout (Docusaurus pattern, playful flavour) ──── */

export type SpecKey =
  | "overview"
  | "wire"
  | "crypto"
  | "storage"
  | "sync"
  | "translog"
  | "threats";

export const SPEC_NAV: {
  key: SpecKey;
  href: string;
  label: string;
  hex: string;
  glyph: string;
  link?: string;
}[] = [
  { key: "overview", href: "/spec", label: "Overview", hex: "0x00", glyph: "◇" },
  { key: "wire", href: "/spec/wire", label: "Wire format", hex: "0x01", glyph: "⌬", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/PROTOCOL.md" },
  { key: "crypto", href: "/spec/crypto", label: "Cryptography", hex: "0x02", glyph: "⚛", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/PROTOCOL.md#1-primitives" },
  { key: "storage", href: "/spec/storage", label: "Storage", hex: "0x03", glyph: "▢", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/STORAGE.md" },
  { key: "sync", href: "/spec/sync", label: "Sync protocol", hex: "0x04", glyph: "⇄", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/API.md" },
  { key: "translog", href: "/spec/translog", label: "Transparency log", hex: "0x05", glyph: "⊞", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/TRANSLOG.md" },
  { key: "threats", href: "/spec/threats", label: "Threat model", hex: "0x06", glyph: "⚠", link: "https://github.com/k2b-dev/fd0.sh/blob/main/docs/THREATS.md" },
];

export const SpecLayout = (p: { current: SpecKey; title: string; children: any }) => {
  const current = SPEC_NAV.find((s) => s.key === p.current)!;
  return (
    <div
      class="min-h-screen"
      style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
    >
      <Nav current="spec" />
      <div class="max-w-7xl mx-auto px-6 md:px-10 pb-20 grid md:grid-cols-[16rem_1fr] gap-x-12 gap-y-8">
        {/* sidebar — playful spec flavour */}
        <aside
          class="fd0-docs-sidebar md:sticky md:self-start text-sm md:overflow-y-auto md:pr-2 pt-6 md:pt-8 pb-6"
          style="top: var(--fd0-nav-h); max-height: calc(100vh - var(--fd0-nav-h));"
        >
          {/* live-spec header with pulsing dot + faux hex magic strip */}
          <div
            class="text-[11px] tracking-[0.18em] uppercase mb-4 pb-3 flex items-center gap-2"
            style={`color:${C.acc};border-bottom:1px solid ${C.border};`}
          >
            <span
              class="inline-block w-1.5 h-1.5 rounded-full fd0-pulse"
              style={`background:${C.sage};`}
            />
            spec
          </div>
          <div
            class="text-[10px] mb-5 leading-[1.5]"
            style={`color:${C.dim};font-family:${FONT_MONO};`}
            aria-hidden="true"
          >
            46 44 30 53 50 45 43 0a
            <br />
            <span style={`color:${C.acc}99;`}>F  D  0  S  P  E  C  ↩</span>
          </div>

          <nav class="flex flex-col">
            {SPEC_NAV.map((item) => {
              const active = item.key === p.current;
              return (
                <a
                  href={item.href}
                  class="group py-2 transition-colors"
                  style={
                    active
                      ? `border-left:2px solid ${C.acc};padding-left:10px;margin-left:-12px;background:${C.bgRaised};`
                      : `border-left:2px solid transparent;padding-left:10px;margin-left:-12px;`
                  }
                >
                  <div class="flex items-center gap-2.5 text-[13.5px]">
                    <span
                      style={`color:${active ? C.acc : C.dim};font-family:${FONT_MONO};font-size:11px;width:2.2rem;`}
                    >
                      {item.hex}
                    </span>
                    <span
                      style={`color:${active ? C.acc : C.fg};width:1rem;text-align:center;`}
                      aria-hidden="true"
                    >
                      {item.glyph}
                    </span>
                    <span style={`color:${active ? C.acc : C.dim};`}>
                      {item.label}
                    </span>
                  </div>
                </a>
              );
            })}
          </nav>

          <div
            class="mt-7 pt-4 text-[12px] leading-relaxed"
            style={`border-top:1px solid ${C.border};color:${C.dim};`}
          >
            Operator-side?{" "}
            <a href="/docs" style={`color:${C.acc};`}>
              /docs
            </a>
          </div>
        </aside>

        {/* main content */}
        <main class="min-w-0 max-w-3xl pt-8 md:pt-10">
          <div class="flex flex-wrap items-baseline justify-between gap-3 mb-3">
            <div class="flex items-center gap-2.5">
              <span
                class="text-[11px] px-2 py-0.5"
                style={`color:${C.acc};font-family:${FONT_MONO};background:${C.acc}14;border:1px solid ${C.acc}33;`}
              >
                {current.hex}
              </span>
              <span
                class="text-[11px] tracking-[0.18em] uppercase"
                style={`color:${C.acc};`}
              >
                {current.label}
              </span>
            </div>
            {current.link ? (
              <a
                href={current.link}
                class="text-[11px] tracking-widest uppercase"
                style={`color:${C.dim};`}
              >
                → normative spec on GitHub
              </a>
            ) : null}
          </div>
          <h1 class="text-[2rem] md:text-[2.6rem] leading-[1.05] tracking-tight font-medium mb-8">
            {p.title}
          </h1>

          {p.children}

          <SpecPager current={p.current} />
        </main>
      </div>
      <Footer />
    </div>
  );
};

const SpecPager = (p: { current: SpecKey }) => {
  const idx = SPEC_NAV.findIndex((x) => x.key === p.current);
  const prev = idx > 0 ? SPEC_NAV[idx - 1] : null;
  const next = idx >= 0 && idx < SPEC_NAV.length - 1 ? SPEC_NAV[idx + 1] : null;
  return (
    <div
      class="mt-16 pt-6 grid grid-cols-2 gap-4 text-sm"
      style={`border-top:1px solid ${C.border};`}
    >
      {prev ? (
        <a
          href={prev.href}
          class="p-4"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="text-[11px] mb-1" style={`color:${C.dim};`}>
            ← {prev.hex}
          </div>
          <div style={`color:${C.acc};`}>{prev.label}</div>
        </a>
      ) : <div />}
      {next ? (
        <a
          href={next.href}
          class="p-4 text-right"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="text-[11px] mb-1" style={`color:${C.dim};`}>
            {next.hex} →
          </div>
          <div style={`color:${C.acc};`}>{next.label}</div>
        </a>
      ) : <div />}
    </div>
  );
};

export const Footer = () => (
  <footer
    class="fd0-footer px-6 md:px-10 py-12 border-t text-sm"
    style={`border-color:${C.border};color:${C.dim};`}
  >
    <div class="max-w-6xl mx-auto grid md:grid-cols-[1.4fr_1fr_1fr_1fr] gap-8">
      <div>
        <div class="flex items-center gap-2.5 mb-3" style={`color:${C.fg};`}>
          <LogoMark size={18} />
          <span class="font-medium">fd0</span>
        </div>
        {/* "Self-hosted" undersold it and contradicted the rest of the site:
            the hosted instance is the default backend. What holds either way
            is that the server cannot read anything. */}
        <p class="text-xs leading-relaxed max-w-xs">
          Zero-knowledge secrets manager. Hosted or self-hosted, the server
          stores ciphertext only; membership rotates the per-scope key
          cryptographically.
        </p>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Product
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="/" class="hover:text-white">Home</a>
          <a href="/docs/desktop" class="hover:text-white">fd0 Desktop</a>
          <a href="/#install" class="hover:text-white">Install</a>
          <a href="/#quickstart" class="hover:text-white">Quickstart</a>
          <a href="/#compare" class="hover:text-white">Compare</a>
        </div>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Reference
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="/docs" class="hover:text-white">Docs</a>
          <a href="/docs/cli" class="hover:text-white">CLI reference</a>
          <a href="/docs/pass" class="hover:text-white">Passwords</a>
          <a href="/docs/ssh" class="hover:text-white">SSH</a>
          <a href="/docs/server" class="hover:text-white">Self-host</a>
          <a href="/spec" class="hover:text-white">Specification</a>
          <a href="/spec/threats" class="hover:text-white">Threat model</a>
        </div>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Project
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="https://github.com/k2b-dev/fd0.sh" class="hover:text-white">
            GitHub
          </a>
          <a href="https://github.com/k2b-dev/fd0.sh/blob/main/LICENSE" class="hover:text-white">
            Apache-2.0 licence
          </a>
          <a href="https://github.com/k2b-dev/fd0.sh/releases" class="hover:text-white">
            Releases
          </a>
          <a href="/privacy" class="hover:text-white">Privacy</a>
          <a href="/impressum" class="hover:text-white">Impressum</a>
        </div>
      </div>
    </div>
    <div
      class="max-w-6xl mx-auto mt-10 pt-6 flex flex-wrap justify-between items-center gap-3 text-xs"
      style={`border-top:1px solid ${C.border};`}
    >
      <div>fd0.sh — Apache-2.0</div>
      <div>self-hostable · no telemetry · ciphertext only</div>
    </div>
  </footer>
);
