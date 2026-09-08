/**
 * / — Landing + Quickstart.
 *
 * Design language: V1 (dark amber, polished SaaS register, Geist sans
 * + Geist Mono for code). Wording is technical and concrete — no
 * editorial framing, no condescension, no story-telling, no padding.
 * The marketing register is OK because fd0 is professional-grade;
 * not because we're selling anything (it's Apache-2.0 open source).
 *
 * fd0 ships in two flavours sharing one protocol:
 *   - self-host  — run fd0-server on your own infrastructure
 *   - fd0.sh     — managed instance we operate; same ciphertext-only
 *                  contract, just one less binary to run
 *
 * Narrative order — what it is, what it holds, why you can trust it,
 * then how to get it. A reader should never be asked to install
 * something before they know what it stores:
 *
 *   hero → verifiable properties → what it holds (pass, ssh, clusters)
 *   → guarantees + architecture → fd0 Desktop → compare
 *   → install + quickstart → spec/docs CTA
 *
 * Rhythm: sections alternate between C.bg and C.bgRaised and vary in
 * vertical padding (see PAD). Hairline borders are only drawn where a
 * ground change does NOT already separate the material — a border on
 * every slab reads as a table, not a page.
 */

import { setPageSeo, ssr } from "../../config";
import { Shell } from "../lib/shell";
import {
  C,
  FONT_SANS,
  FONT_MONO,
  Nav,
  Footer,
  Shot,
  DESKTOP_RELEASE_URL,
} from "../lib/chrome";

/* ─── primitives ──────────────────────────────────────────────────── */

const Btn = (p: {
  href: string;
  primary?: boolean;
  ghost?: boolean;
  children: any;
}) => (
  <a
    href={p.href}
    class={`fd0-btn ${
      p.primary ? "fd0-btn-primary" : p.ghost ? "fd0-btn-ghost" : "fd0-btn-secondary"
    } inline-flex items-center gap-2 py-2.5 text-sm font-medium transition-colors ${
      p.ghost ? "px-0.5" : "px-5"
    }`}
    style={
      p.primary
        ? `background:${C.acc};color:#0a0a0a;border:1px solid ${C.acc};`
        : p.ghost
          ? `color:${C.dim};`
          : `color:${C.fg};border:1px solid ${C.border};`
    }
  >
    {p.children}
  </a>
);

/*
 * Vertical rhythm. One scale, referenced by name, so "dense reference
 * section" and "headline section" are a decision rather than whatever
 * py-20 happened to get pasted in.
 */
const PAD = {
  xs: "py-9 md:py-10",
  sm: "py-14 md:py-16",
  md: "py-16 md:py-20",
  lg: "py-20 md:py-24",
  xl: "py-20 md:py-28",
  xxl: "py-24 md:py-32",
} as const;

/*
 * C.bgRaised is #13161544 — 27% alpha, which is right for a card
 * floating on the page but resolves to a 2/255 difference when it is
 * painted as a full-bleed section ground. Alternating sections use the
 * same colour at full opacity so the change of ground is actually
 * visible and can carry the separation a hairline border used to.
 */
const GROUND = C.bgRaised.slice(0, 7);

const Section = (p: {
  id?: string;
  raised?: boolean;
  pad?: keyof typeof PAD;
  border?: "top" | "y";
  children: any;
}) => (
  <section
    id={p.id}
    class={`px-6 md:px-10 ${PAD[p.pad ?? "lg"]}${
      p.border === "y" ? " border-y" : p.border === "top" ? " border-t" : ""
    }`}
    style={`${p.raised ? `background:${GROUND};` : ""}${
      p.border ? `border-color:${C.border};` : ""
    }`}
  >
    {/* One container width for every section — the left edge of every
        kicker on the page lines up, and every section resolves on the
        same right edge, whatever the measure inside. */}
    <div class="max-w-6xl mx-auto">{p.children}</div>
  </section>
);

/**
 * The amber eyebrow above a heading. Five of them on this page — section
 * heads, the architecture block, the compare index, the quickstart rail
 * and the closing reference — so the size, tracking and gap live once.
 */
const Kicker = (p: { children: any }) => (
  <div
    class="text-[11px] tracking-[0.18em] uppercase mb-3"
    style={`color:${C.acc};`}
  >
    {p.children}
  </div>
);

/** Kicker + heading + optional lede, with one fixed gap to the body. */
/*
 * Heading left, lede right.
 *
 * Stacked, both sat at reading width against the left rail and stopped ~480px
 * short of the container while the screenshots below ran its full width — five
 * different right edges down the page, which reads as the whole layout leaning
 * left. Pairing them closes the right edge and gives the prose somewhere to go.
 * Below lg they stack again, where one column is the only sensible measure.
 */
const SectionHead = (p: { kicker: string; title: string; children?: any }) => (
  <div class="mb-10 md:mb-12">
    <Kicker>{p.kicker}</Kicker>
    <div class="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-x-12 gap-y-5 items-end">
      <h2 class="text-3xl md:text-4xl font-medium tracking-tight text-balance">
        {p.title}
      </h2>
      {p.children ? (
        <p class="text-base leading-relaxed lg:pb-1" style={`color:${C.dim};`}>
          {p.children}
        </p>
      ) : null}
    </div>
  </div>
);

const Feature = (p: {
  kicker: string;
  title: string;
  body: string;
  onRaised?: boolean;
}) => (
  <div
    class="p-7 flex flex-col gap-3"
    style={`background:${p.onRaised ? C.bg : C.bgRaised};border:1px solid ${C.border};`}
  >
    <div
      class="text-[11px] tracking-[0.18em] uppercase"
      style={`color:${C.acc};`}
    >
      {p.kicker}
    </div>
    <div class="text-lg font-medium">{p.title}</div>
    <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
      {p.body}
    </p>
  </div>
);

const PropertyCard = (p: { label: string; value: string; sub?: string }) => (
  <div class="px-2 min-w-0">
    <div
      class="text-[10px] tracking-[0.22em] uppercase mb-2"
      style={`color:${C.dim};`}
    >
      {p.label}
    </div>
    <div
      class="text-base font-medium leading-snug fd0-tnum"
      style={`color:${C.fg};font-family:${FONT_MONO};`}
    >
      {p.value}
    </div>
    {p.sub ? (
      <div class="text-[11px] mt-1 break-words" style={`color:${C.dim};`}>
        {p.sub}
      </div>
    ) : null}
  </div>
);

/** One row of the "what it holds" index — name, one line, the command. */
const HoldsRow = (p: { name: string; body: string; cmd: string }) => (
  <div
    class="grid md:grid-cols-[9rem_1fr_13rem] gap-x-8 gap-y-1.5 py-5"
    style={`border-bottom:1px solid ${C.border};`}
  >
    <div class="font-medium">{p.name}</div>
    <p class="text-sm leading-relaxed min-w-0" style={`color:${C.dim};`}>
      {p.body}
    </p>
    <div
      class="text-[13px] md:text-right fd0-mono min-w-0"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.cmd}
    </div>
  </div>
);

const TermFrame = (p: { title: string; children: any }) => (
  <div
    class="text-[13px] leading-[1.7] self-start"
    style={`background:${C.bg};border:1px solid ${C.border};box-shadow:0 30px 80px -40px ${C.acc}33,inset 0 1px 0 ${C.border};font-family:${FONT_MONO};`}
  >
    <div
      class="flex items-center gap-1.5 px-4 py-3 border-b"
      style={`color:${C.dim};border-color:${C.border};`}
    >
      <span class="w-2.5 h-2.5 rounded-full" style="background:#ff5f56;" />
      <span class="w-2.5 h-2.5 rounded-full" style="background:#ffbd2e;" />
      <span class="w-2.5 h-2.5 rounded-full" style="background:#27c93f;" />
      <span class="ml-3 text-[11px]">{p.title}</span>
    </div>
    <div class="p-5">{p.children}</div>
  </div>
);

/** Numbered terminal snippet — the repeated unit in the pass/ssh tours. */
const CmdCard = (p: { label: string; code: string; onRaised?: boolean }) => (
  <div
    class="p-5 text-[13px] leading-[1.6] min-w-0 overflow-hidden"
    style={`background:${p.onRaised ? C.bg : C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
  >
    <div class="text-[11px] mb-3 fd0-tnum" style={`color:${C.dim};`}>
      {p.label}
    </div>
    <Shell>{p.code}</Shell>
  </div>
);

/** Snippet plus an explanatory paragraph. */
const NoteCard = (p: {
  title: string;
  code?: string;
  onRaised?: boolean;
  children: any;
}) => (
  <div
    class="p-5 text-sm min-w-0"
    style={`background:${p.onRaised ? C.bg : C.bgRaised};border:1px solid ${C.border};`}
  >
    <div class="text-[11px] mb-2" style={`color:${C.acc};`}>
      {p.title}
    </div>
    {p.code ? (
      <div style={`color:${C.fg};`}>
        <Shell>{p.code}</Shell>
      </div>
    ) : null}
    <p
      class={`${p.code ? "mt-3" : ""} text-[13px] leading-relaxed`}
      style={`color:${C.dim};`}
    >
      {p.children}
    </p>
  </div>
);

const BackendCol = (p: {
  badge: string;
  title: string;
  body: string;
  code: string;
  codeNote: string;
}) => (
  // min-w-0 keeps this grid item from inheriting the shell block's
  // intrinsic line width as its automatic minimum size — without it the
  // card grows past a 375px viewport and takes the body copy with it.
  <div
    class="p-6 flex flex-col gap-4 min-w-0"
    style={`background:${C.bg};border:1px solid ${C.border};`}
  >
    <div class="flex items-center justify-between">
      <span
        class="text-[10px] tracking-widest uppercase px-2 py-0.5"
        style={`background:${C.acc}22;color:${C.acc};border:1px solid ${C.acc}44;`}
      >
        {p.badge}
      </span>
    </div>
    <div>
      <div class="text-lg font-medium mb-2">{p.title}</div>
      <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
        {p.body}
      </p>
    </div>
    <div
      class="p-4 text-[13px] leading-[1.6] min-w-0"
      style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
    >
      <Shell>{p.code}</Shell>
    </div>
    <div class="text-xs leading-relaxed mt-1" style={`color:${C.dim};`}>
      {p.codeNote}
    </div>
  </div>
);

/*
 * Number, explanation, terminal.
 *
 * The quickstart used to be capped at max-w-4xl inside the shared
 * max-w-6xl container, which left 256px of the section unused and gave
 * the page a fourth right edge. Uncapped, a two-column step would run
 * its 14px body copy out to ~1050px — 175 characters, unreadable — so
 * the extra width goes to the terminal instead: from xl the code sits
 * beside the prose rather than under it, which holds the body at a
 * ~380px measure and lets the block close the container's right edge.
 * xl rather than lg because only there is the container guaranteed to
 * be 1152px, wide enough that the longest line still fits unscrolled.
 */
const Step = (p: { n: string; title: string; body: string; code: string }) => (
  <div class="grid md:grid-cols-[5rem_1fr] xl:grid-cols-[5rem_minmax(0,24rem)_minmax(0,1fr)] gap-x-6 gap-y-4">
    <div
      class="text-3xl tracking-tight font-medium fd0-tnum"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.n}
    </div>
    <div class="min-w-0">
      <div class="text-lg font-medium mb-1.5">{p.title}</div>
      <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
        {p.body}
      </p>
    </div>
    <div
      class="p-4 text-[13px] leading-[1.6] min-w-0 md:col-start-2 xl:col-start-3 xl:row-start-1"
      style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
    >
      <Shell>{p.code}</Shell>
    </div>
  </div>
);

/* ─── page ────────────────────────────────────────────────────────── */

const Home = () => (
  <div
    class="min-h-screen"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
  >
    <Nav current="home" />

    {/* ─── hero ──────────────────────────────────────────────────────
        Statement, then proof. The claim block is one left-aligned
        column at reading width; the product visual runs the full
        container underneath it, with the CLI terminal overlapping the
        app window's empty lower-right quadrant. The two surfaces —
        window and terminal — are the whole pitch, so they are shown
        together at a size where both are actually legible.

        The overlap is flow layout below `lg` (terminal stacks under
        the shot) and absolute at `lg`+, where the terminal is wide
        enough to hold its longest line without scrolling. Absolute
        positioning contributes no width, so no viewport can overflow
        because of it. */}
    <header class="px-6 md:px-10 pt-16 md:pt-24 pb-16 md:pb-24 max-w-6xl mx-auto">
      <div class="max-w-3xl">
        <div
          class="inline-flex items-center gap-2 px-3 py-1 text-[11px] tracking-widest uppercase mb-7"
          style={`color:${C.acc};border:1px solid ${C.border};`}
        >
          <span
            class="inline-block w-1.5 h-1.5 rounded-full"
            style={`background:${C.acc};`}
          />
          Apache-2.0 · client-side encrypted
        </div>
        <h1 class="text-[2.6rem] md:text-[3.4rem] leading-[1.05] tracking-tight font-medium">
          <span class="fd0-rotword-wrap">
            <span id="fd0-rotword" class="fd0-rotword">Secrets</span>
            <span id="fd0-rotbar" class="fd0-rotbar" />
          </span>{" "}
          you keep,
          <br />
          <span style={`color:${C.acc};`}>not secrets you trust.</span>
        </h1>
        <style innerHTML={`
          .fd0-rotword-wrap {
            display: inline-block;
            position: relative;
            padding-bottom: 6px;
          }
          .fd0-rotword {
            display: inline-block;
            transition: opacity 380ms ease, transform 380ms ease;
          }
          .fd0-rotword.fade-out { opacity: 0; transform: translateY(-6px); }
          .fd0-rotbar {
            position: absolute;
            left: 0;
            bottom: 0;
            height: 3px;
            width: 0;
            background: ${C.acc};
            border-radius: 2px;
            animation: fd0-rotbar 4500ms linear infinite;
          }
          .fd0-rotbar.paused { animation-play-state: paused; }
          @keyframes fd0-rotbar {
            0%   { width: 0; opacity: 1; }
            92%  { width: 100%; opacity: 1; }
            100% { width: 100%; opacity: 0; }
          }
          @media (prefers-reduced-motion: reduce) {
            .fd0-rotbar { animation: none; width: 100%; }
          }
        `} />
        <script innerHTML={`(function(){
          var words = ['Secrets','Passwords','SSH keys','SSH hosts','Kube configs'];
          var el  = document.getElementById('fd0-rotword');
          var bar = document.getElementById('fd0-rotbar');
          if (!el || !bar) return;
          // Readers who asked for less motion get the first word, held.
          var motion = window.matchMedia
            ? window.matchMedia('(prefers-reduced-motion: reduce)')
            : null;
          if (motion && motion.matches) return;
          var idx = 0;
          var paused = false;
          var wrap = el.parentElement;
          var hold = function(){
            paused = true;
            bar.classList.add('paused');
          };
          var release = function(){
            paused = false;
            bar.classList.remove('paused');
          };
          wrap.addEventListener('mouseenter', hold);
          wrap.addEventListener('mouseleave', release);
          // Keyboard users get the same pause when focus lands inside.
          wrap.addEventListener('focusin', hold);
          wrap.addEventListener('focusout', release);
          if (motion && motion.addEventListener) {
            motion.addEventListener('change', function(e){
              if (e.matches) { hold(); } else { release(); }
            });
          }
          setInterval(function(){
            if (paused) return;
            el.classList.add('fade-out');
            setTimeout(function(){
              idx = (idx + 1) % words.length;
              el.textContent = words[idx];
              el.classList.remove('fade-out');
              // Restart bar animation in sync with the word change so
              // they never drift after many cycles.
              bar.style.animation = 'none';
              void bar.offsetWidth;
              bar.style.animation = '';
            }, 380);
          }, 4500);
        })();`} />
        <p class="mt-6 text-lg leading-relaxed max-w-2xl" style={`color:${C.dim};`}>
          One zero-knowledge vault for the credentials you'd otherwise
          scatter across <span style={`color:${C.acc};`}>.ssh</span>,{" "}
          <span style={`color:${C.acc};`}>kubeconfig</span>, Talos config,
          and someone's Notion page. The server stores ciphertext and signed
          events only. Sharing membership rotates per-scope keys atomically.
          Configured witnesses can detect server-side forks.
        </p>
        <div class="mt-9 flex flex-wrap items-center gap-x-4 gap-y-3">
          <Btn href={DESKTOP_RELEASE_URL} primary>
            Download fd0 Desktop →
          </Btn>
          <Btn href="#install">Install the CLI →</Btn>
          <Btn href="https://github.com/k2b-dev/fd0.sh" ghost>
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.34-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.95.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.09-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.04 11.04 0 0 1 5.78 0c2.21-1.49 3.18-1.18 3.18-1.18.62 1.59.23 2.76.11 3.05.74.8 1.18 1.83 1.18 3.09 0 4.42-2.7 5.39-5.27 5.68.41.35.78 1.04.78 2.1 0 1.52-.02 2.74-.02 3.11 0 .3.21.66.8.55C20.21 21.38 23.5 17.07 23.5 12 23.5 5.65 18.35.5 12 .5z" />
            </svg>
            Source on GitHub
          </Btn>
        </div>
        <p class="mt-6 text-[13px] leading-relaxed" style={`color:${C.dim};`}>
          macOS and Linux · signed and notarized · no telemetry ·{" "}
          <a href="/docs/desktop" style={`color:${C.acc};`}>
            what the app does →
          </a>
        </p>
      </div>

      <div class="relative mt-14 md:mt-20 lg:pb-10">
        <figure
          class="m-0 w-full lg:w-[86%]"
          style={`background:${C.bgRaised};border:1px solid ${C.border};box-shadow:0 40px 120px -60px ${C.acc}40;`}
        >
          <img
            src="/public/shots/vault.png"
            alt="fd0 Desktop showing the item list beside an open Cloudflare login with its login fields, a one-time code and a recovery section."
            width="1440"
            height="900"
            loading="eager"
            fetchpriority="high"
            decoding="async"
            class="block w-full h-auto"
            style={`background:${C.bg};`}
          />
        </figure>
        <div class="mt-5 lg:mt-0 lg:absolute lg:right-0 lg:bottom-0 lg:w-[42%]">
          <TermFrame title="example — fd0 sync">
            <Shell>{`$ fd0 sync
→ POST /v1/sync  scope=work  push=3
← 200 OK  pull=0  sth=verified@43
✓ chain advanced (seq=7)
✓ STH verified

$ fd0 secret get DEPLOY_KEY
ghp_xxxxxxxxxxxxxxxxxxxx`}</Shell>
          </TermFrame>
        </div>
      </div>
    </header>

    {/* ─── verifiable properties strip ───────────────────────────────── */}
    <Section raised pad="xs" border="y">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-x-8 gap-y-7">
        <PropertyCard
          label="Cryptography"
          value="Ed25519 · X25519"
          sub="AES-256-GCM AEAD"
        />
        <PropertyCard
          label="Transparency"
          value="RFC 6962 + witness"
          sub="independent cosigner"
        />
        <PropertyCard
          label="Releases"
          value="signed installer"
          sub="cosign-verifiable manifest"
        />
        <PropertyCard
          label="Source"
          value="Apache-2.0"
          sub="github.com/k2b-dev/fd0.sh"
        />
      </div>
    </Section>

    {/* ─── what it holds ─────────────────────────────────────────────── */}
    <Section id="surface" pad="md">
      <SectionHead
        kicker="What it holds"
        title="One vault for every kind of credential."
      >
        Every record type shares the same scopes, the same version history
        and the same ciphertext-only contract. Sharing a kubeconfig is the
        same operation as sharing a password — add someone to the scope.
      </SectionHead>
      <div style={`border-top:1px solid ${C.border};`}>
        <HoldsRow
          name="Logins"
          body="Usernames, passwords, TOTP, passkeys stored as data, and small file attachments."
          cmd="fd0 pass"
        />
        <HoldsRow
          name="SSH"
          body="Keys generated inside the agent, a host inventory, terminal sessions, and two-way file transfer."
          cmd="fd0 key · fd0 ssh · fd0 sftp"
        />
        <HoldsRow
          name="Clusters"
          body="Kubeconfigs and Talos contexts, handed out per scope instead of copied around."
          cmd="fd0 kube · fd0 talos"
        />
        <HoldsRow
          name="Everything else"
          body="Opaque values — deploy tokens, connection strings, licence keys, API keys."
          cmd="fd0 secret"
        />
      </div>
    </Section>

    {/* ─── fd0 pass ──────────────────────────────────────────────────── */}
    <Section raised pad="lg">
      <SectionHead
        kicker="fd0 pass"
        title="A password manager that shares the same scopes."
      >
        A pass item is a title, a set of URLs, a note, and typed fields:{" "}
        <span style={`color:${C.acc};`}>text</span>,{" "}
        <span style={`color:${C.acc};`}>secret</span>,{" "}
        <span style={`color:${C.acc};`}>totp</span>,{" "}
        <span style={`color:${C.acc};`}>passkey</span>,{" "}
        <span style={`color:${C.acc};`}>file</span>, and{" "}
        <span style={`color:${C.acc};`}>section</span> to group them. It
        stores like every other fd0 record.
      </SectionHead>

      <div class="grid md:grid-cols-3 gap-5">
        <CmdCard
          onRaised
          label="01 · Create an item"
          code={`$ fd0 pass add github \\
    --url https://github.com \\
    --scope work

✓ pass item created`}
        />
        <CmdCard
          onRaised
          label="02 · Fill it in"
          code={`$ fd0 pass field set github \\
    username ada@example.com
$ fd0 pass field set github \\
    password --secret --generate
$ fd0 pass totp add github \\
    "otpauth://totp/GitHub:ada?..."`}
        />
        <CmdCard
          onRaised
          label="03 · Use it"
          code={`$ fd0 pass
$ fd0 pass copy github
$ fd0 pass totp code github
$ fd0 pass show github`}
        />
      </div>

      <div class="grid md:grid-cols-2 gap-5 mt-5">
        <NoteCard
          onRaised
          title="Attachments and recovery codes"
          code={`$ fd0 pass section add github Recovery
$ fd0 pass file add github ~/backup.pem`}
        >
          Small files are attached as fields and come back with{" "}
          <span style={`color:${C.acc};`}>fd0 pass file export</span>.
          Sections give an item structure without a second record.
        </NoteCard>
        <NoteCard
          onRaised
          title="Every version is kept"
          code={`$ fd0 pass history show github
$ fd0 pass history restore github 3`}
        >
          Restore writes forward: it appends a new version carrying the old
          content, so an undo is itself auditable. The same two commands
          work on secrets, keys, hosts, kubeconfigs, and Talos contexts.
        </NoteCard>
      </div>
    </Section>

    {/* ─── fd0 ssh ───────────────────────────────────────────────────── */}
    <Section pad="lg">
      <SectionHead
        kicker="fd0 ssh"
        title="SSH keys, hosts, terminals, and files."
      >
        Keys are generated inside fd0-agent and served via the standard
        ssh-agent protocol. Hosts are structured entries that render to
        a regular <span style={`color:${C.acc};`}>~/.ssh/fd0.conf</span> you
        Include from your own config. Native SSH features (jump hosts,
        agent forwarding, port forwarding) all work because we are just
        an agent. The same host record also opens an fd0 terminal or an SFTP
        Files window.
      </SectionHead>

      <div class="grid md:grid-cols-3 gap-5">
        <CmdCard
          label="01 · Generate a key"
          code={`$ fd0 key add laptop
✓ ed25519 (scope: personal)

ssh-ed25519 AAAAC3NzaC1lZD…
laptop@fd0`}
        />
        <CmdCard
          label="02 · Add a host"
          code={`$ fd0 ssh add prod-db \\
    app@db.internal \\
    --jump bastion \\
    --key laptop \\
    --scope work

✓ host added
✓ ~/.ssh/fd0.conf rendered`}
        />
        <CmdCard
          label="03 · Connect or transfer"
          code={`$ fd0 ssh prod-db
$ fd0 sftp prod-db
$ fd0 sftp cp prod-db \\
    ./release.tar \\
    remote:/tmp/release.tar`}
        />
      </div>

      <div class="grid md:grid-cols-3 gap-5 mt-5">
        <NoteCard
          title="For your team"
          code={`$ fd0 scope add-member bob --scope work
$ fd0 sync`}
        >
          Bob's next sync gives him the key, the host, and the tags.{" "}
          <span style={`color:${C.acc};`}>fd0 scope remove-member</span>{" "}
          rotates the per-scope key — his next sync drops access.
        </NoteCard>
        <NoteCard title="Standard ssh-agent protocol">
          fd0-agent talks the same protocol as OpenSSH ssh-agent.{" "}
          <span style={`color:${C.acc};`}>ssh, git, scp, rsync, VS Code Remote</span>{" "}
          — anything that respects{" "}
          <code class="fd0-mono" style={`color:${C.acc};font-family:${FONT_MONO};`}>
            SSH_AUTH_SOCK
          </code>{" "}
          works. fd0 never writes anything to the remote server.
        </NoteCard>
        <NoteCard
          title="Files without a second connection setup"
          code={`$ fd0 sftp tree prod-db /srv/app --depth 2`}
        >
          Desktop and CLI reuse the exact fd0-rendered OpenSSH configuration:
          assigned key, jump host, options, and strict host verification.
          Transfers show progress and can be cancelled.
        </NoteCard>
      </div>
    </Section>

    {/* ─── guarantees + architecture ─────────────────────────────────── */}
    <Section id="how" raised pad="xxl">
      <SectionHead
        kicker="Three guarantees"
        title="Built into the protocol, not the deployment."
      />
      <div class="grid md:grid-cols-3 gap-6">
        <Feature
          onRaised
          kicker="Encryption"
          title="The server cannot decrypt."
          body="Every secret is sealed by the client before it leaves the device. The server stores ciphertext and signed event metadata — an operator with full database access reads no secret values or secret names."
        />
        <Feature
          onRaised
          kicker="Membership"
          title="Add or remove members atomically."
          body="Each scope has its own key. Adding a member wraps the key to their card; removing one rotates it. Cryptographic, not policy-enforced."
        />
        <Feature
          onRaised
          kicker="Transparency"
          title="Forks are detectable."
          body="The server signs every tree head. With configured witnesses or clients comparing notes, divergent histories become publishable evidence."
        />
      </div>

      {/* Internal division inside "how it works": deliberately tighter
          than the space between two sections, so it reads as the next
          part of one argument rather than a new one. */}
      <div class="mt-16 pt-12" style={`border-top:1px solid ${C.border};`}>
        <Kicker>Architecture</Kicker>
        <div class="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-x-12 gap-y-5 items-start mb-10">
        <h3 class="text-2xl md:text-3xl font-medium tracking-tight text-balance">
          Six components. Keys stay on your device.
        </h3>
        <div class="flex flex-col gap-5">
        <p class="text-base leading-relaxed" style={`color:${C.dim};`}>
          The CLI, the desktop app, and the agent run locally. After unlock,
          private key material stays in the agent and is never written to disk
          in plaintext — fd0 Desktop reads it through the same agent, not
          around it. Standard tools (ssh, git, scp) attach through the
          ssh-agent socket. The server holds ciphertext and signed events; the
          witness holds signed tree heads. Neither holds secret keys.
        </p>
        <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
          The six shipped components are{" "}
          <span style={`color:${C.acc};font-family:${FONT_MONO};`}>fd0</span>,{" "}
          <span style={`color:${C.acc};font-family:${FONT_MONO};`}>fd0-agent</span>,{" "}
          <span style={`color:${C.acc};`}>fd0 Desktop</span>,{" "}
          <span style={`color:${C.acc};font-family:${FONT_MONO};`}>fd0-server</span>,{" "}
          <span style={`color:${C.acc};font-family:${FONT_MONO};`}>fd0-witness</span>,
          and this site. The diagram below shows where each one sits.
        </p>
        </div>
        </div>
        {/* Centred in its band: at container width the fixed-width diagram
            left-aligned leaves a void the prose above no longer has. Scrolls
            inside itself on narrow viewports rather than widening the page. */}
        <div class="overflow-x-auto -mx-6 px-6 flex lg:justify-center">
          <div class="w-fit">
            <pre
              class="shell p-6 pb-2 text-[12px] leading-[1.55]"
              style={`background:${C.bg};border:1px solid ${C.border};border-bottom:none;color:${C.fg};font-family:${FONT_MONO};`}
            >{`consumers           your device           server                  observer
┌────────────────┐  ┌─────────────────┐   ┌────────────────────┐   ┌────────────────────┐
│ ssh, scp,      │  │ fd0  (CLI)      │   │ fd0-server         │   │ fd0-witness        │
│ git, rsync,    │ ─│ fd0-agent       │ ─▶│ ciphertext +       │ ─▶│ cosigns verified   │
│ kubectl …      │ ◀│   unlocked keys │   │ signed events      │ ✓ │ archives forks     │
│                │  │   vault.enc     │   │                    │   │ independent host   │
└────────────────┘  └─────────────────┘   └────────────────────┘   └────────────────────┘
   ssh-agent         single primary (api.fd0.sh) · DR backup mirrors it read-only
   protocol`}</pre>
            <div
              class="text-[12px] text-center px-6 pb-6 pt-1"
              style={`background:${C.bg};border:1px solid ${C.border};border-top:none;color:${C.dim};font-family:${FONT_MONO};`}
            >
              standard protocols on both sides · zero-knowledge contract end-to-end
            </div>
          </div>
        </div>
      </div>
    </Section>

    {/* ─── fd0 Desktop ───────────────────────────────────────────────── */}
    <Section id="desktop" pad="xl">
      <SectionHead
        kicker="fd0 Desktop"
        title="The whole vault, in one window."
      >
        Logins, secrets, SSH hosts, keys and clusters share one searchable
        list, each with its scope, its version history and a restore. The app
        talks to the same local agent as the CLI, so private key material
        never reaches the window you are looking at.
      </SectionHead>

      <div class="flex flex-wrap items-center gap-x-4 gap-y-3 mb-10">
        <Btn href={DESKTOP_RELEASE_URL} primary>
          Download for macOS and Linux →
        </Btn>
        <Btn href="/docs/desktop" ghost>
          Desktop docs →
        </Btn>
      </div>

      <div class="grid gap-5">
        <Shot
          src="/public/shots/palette.png"
          alt="The fd0 Desktop command palette open over the vault, filtered to Cloudflare, offering open and copy."
          title="⌘K goes anywhere"
          body="One surface searches items and runs commands. Enter opens an item; ⌘↵ copies its password without opening anything at all."
        />
        <div class="grid md:grid-cols-2 gap-5">
          <Shot
            dense
            src="/public/shots/ssh.png"
            alt="fd0 Desktop showing an SSH host with its hostname, user, port and bound key."
            title="SSH lives here too"
            body="Hosts and keys sit beside your passwords and render into an ssh_config include, so `ssh web-01` simply works."
          />
          <Shot
            dense
            src="/public/shots/generator.png"
            alt="The fd0 Desktop password generator with a random password and a strength read-out."
            title="Generate, then decide"
            body="Random, memorable or PIN, with a strength read-out. Nothing is stored until you save it."
          />
        </div>
      </div>
    </Section>

    {/* ─── small compare strip ───────────────────────────────────────── *
     * The heading is the first cell of the index, not a band above it.
     * There is no lede to pair it with, so a full-width head left ~600px
     * of empty rail beside a short h2 — and five entries in two columns
     * left a sixth cell empty at the bottom, a second void directly under
     * the first. Five entries plus the head is six, which fills three
     * columns in two exact rows, and it drops the measure of the 14px
     * comparison copy from ~550px to ~350px on the way. */}
    <Section id="compare" raised pad="sm">
      <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-x-12 gap-y-8 text-sm">
        <div class="md:col-span-2 lg:col-span-1">
          <Kicker>Compare</Kicker>
          <h2 class="text-3xl md:text-4xl font-medium tracking-tight text-balance">
            Same shape, different trust model.
          </h2>
        </div>
        {[
          {
            k: "vs. Bitwarden / Vaultwarden",
            v: "Same use case. fd0's server cannot decrypt under any operator access — cryptographic, not policy.",
          },
          {
            k: "vs. 1Password Teams",
            v: "Same team-sharing model. fd0 keys live on devices you control; the server is yours or fd0.sh.",
          },
          {
            k: "vs. 1Password SSH / Bitwarden SSH",
            v: "Same per-sign agent protocol pattern. fd0 adds team-scoped keys — sharing an SSH key is the same op as sharing a password, cryptographic at scope membership.",
          },
          {
            k: "vs. pass (Git + GPG)",
            v: "fd0 has cryptographic membership built in: add/remove rotates the per-scope key atomically.",
          },
          {
            k: "vs. HashiCorp Vault",
            v: "Different scope. fd0 is a human-facing secret store; Vault is a policy engine for service-to-service auth.",
          },
        ].map((c) => (
          <div class="flex flex-col gap-1.5">
            <div style={`color:${C.acc};`} class="font-medium">
              {c.k}
            </div>
            <div style={`color:${C.dim};`}>{c.v}</div>
          </div>
        ))}
      </div>
    </Section>

    {/* ─── install + backend choice ──────────────────────────────────── */}
    <Section id="install" pad="lg">
      <SectionHead
        kicker="Install"
        title="Install the client. Pick a backend."
      >
        Same client either way. The main difference is who runs the server.
        Client-side encryption and scope membership work the same; witness
        enforcement depends on your client config.
      </SectionHead>

      {/* step 1: install client */}
      <div class="mb-12">
        <div
          class="text-xs tracking-[0.18em] uppercase mb-3 fd0-tnum"
          style={`color:${C.dim};`}
        >
          01 · Install the client
        </div>
        {/* The measure lives on a wrapper: styles.css caps any direct
            parent of a .shell at max-width:100% (unlayered, so it wins
            over a Tailwind max-w-* utility on the same element). */}
        <div class="max-w-2xl">
          <div
            class="p-4 text-[14px] select-all cursor-text min-w-0"
            style={`background:${C.bgRaised};border:1px solid ${C.acc};font-family:${FONT_MONO};`}
          >
            <Shell>curl -fsSL https://fd0.sh/install | sh</Shell>
          </div>
        </div>
        <div class="text-xs mt-3 leading-relaxed max-w-2xl" style={`color:${C.dim};`}>
          Asks whether to install{" "}
          <span style={`color:${C.acc};`}>fd0 Desktop</span> or the CLI and
          agent. The CLI path also offers YubiKey support. Run the same command
          to update; the current choice stays selected and the installer asks
          before changing anything. Explicit{" "}
          <span style={`color:${C.acc};`}>--desktop</span>,{" "}
          <span style={`color:${C.acc};`}>--flavor</span>, and{" "}
          <span style={`color:${C.acc};`}>--yes</span> flags remain available
          for scripted installs. Prefer a{" "}
          <a href={DESKTOP_RELEASE_URL} style={`color:${C.acc};`}>
            downloaded DMG or AppImage
          </a>{" "}
          if you only want the app.
        </div>
      </div>

      <div class="mb-12 max-w-2xl">
        <h3 class="text-lg font-medium mb-3">Use fd0 with your coding agent</h3>
        <p class="text-sm leading-relaxed mb-4" style={`color:${C.dim};`}>
          Add the fd0 skill so your coding agent knows how to store passwords,
          manage SSH keys, and work with your vault. Choose either command:
        </p>
        <Shell>{`npx skills add k2b-dev/fd0.sh
# Or with Bun:
bunx skills add k2b-dev/fd0.sh`}</Shell>
        <p class="text-xs mt-3 leading-relaxed" style={`color:${C.dim};`}>
          Install and set up fd0 separately; the skill supplies instructions for
          using it. <a href="/docs/install#agent-skill" style={`color:${C.acc};`}>Agent selection and setup →</a>
        </p>
      </div>

      {/* step 2: pick backend */}
      <div>
        <div
          class="text-xs tracking-[0.18em] uppercase mb-3 fd0-tnum"
          style={`color:${C.dim};`}
        >
          02 · Pick a backend
        </div>
        <div class="grid md:grid-cols-2 gap-5">
          <BackendCol
            badge="Self-host"
            title="Run fd0-server yourself."
            body="Download the minimal compose file, run one fd0-server on localhost, and put your own TLS terminator in front. Pin image tags for production."
            code={`mkdir fd0-server && cd fd0-server
curl -fsSLO https://fd0.sh/files/compose.yml
umask 077
printf 'METRICS_TOKEN=%s\\n' "$(openssl rand -hex 32)" > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\\n' 'ghcr.io/valentinkolb/fd0-server:latest-arm64' >> .env ;; esac
docker compose up -d`}
            codeNote="One primary per client — clients set [sync].server. For redundancy run a standby with FD0_REPLICATE_FROM=<primary> (the primary lists it in FD0_PEERS); it mirrors the primary read-only for disaster recovery."
          />
          <BackendCol
            badge="Hosted at fd0.sh"
            title="Use the managed instance."
            body="A managed primary plus a disaster-recovery backup operated by Kolb Antik GmbH in Germany. Same ciphertext-only contract: the operator cannot decrypt secrets."
            code={`# ~/.fd0/config.toml — this is the default
[sync]
server    = "https://api.fd0.sh"
on_unlock = true`}
            codeNote="The production runbook linked from /docs/server covers hosting topology, backups, metrics, witnesses, and key rotation."
          />
        </div>
      </div>
    </Section>

    {/* ─── quickstart ────────────────────────────────────────────────── */}
    <Section id="quickstart" pad="lg" border="top">
      {/* Same ground as #install above — the hairline says "still the
          getting-started chapter, next step" rather than "new topic". */}
      <SectionHead kicker="Quickstart" title="Four steps." />
      <div class="flex flex-col gap-12">
        <Step
          n="01"
          title="Generate identity, seal the vault"
          body="fd0 init writes a fresh Ed25519 keypair to ~/.fd0/vault.enc, sealed under a passphrase. The passphrase only protects the file at rest — it never reaches the server."
          code={`$ fd0 init
Choose a passphrase: ********
✓ identity created (upIamMlsgn…)
✓ vault written to ~/.fd0/vault.enc`}
        />
        <Step
          n="02"
          title="Unlock once per session"
          body="The agent holds the unlocked identity in memory. The CLI signs and decrypts through it without re-prompting until you run fd0 lock."
          code={`$ fd0 unlock
Passphrase: ********
✓ agent started
✓ vault unlocked (passphrase)`}
        />
        <Step
          n="03"
          title="Create a scope, store a secret"
          body="A scope is a group of secrets with its own encryption key. Adding or removing members rotates that key."
          code={`$ fd0 scope create --label work
$ fd0 secret set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxx" --scope work
$ fd0 secret get DEPLOY_KEY
ghp_xxxxxxxxxxxxxxxxxxxx`}
        />
        <Step
          n="04"
          title="Sync — local goes to the server"
          body="fd0 sync is the explicit network command. The agent can also sync after unlock when on_unlock is enabled."
          code={`$ fd0 sync
→ POST /v1/sync  scope=work  push=3 events
← 200 OK         pull=0      sth=verified@tree_size=43
✓ local chain updated
✓ STH verified against the pinned server key`}
        />
      </div>
    </Section>

    {/* ─── docs CTA ──────────────────────────────────────────────────── */}
    <Section raised pad="lg">
      {/*
       * The same heading/lede pairing the section heads use, with the two
       * calls to action hanging off the bottom of the heading column. This
       * block used to sit in a max-w-2xl measure — 672px of the 1152px
       * container every other section fills — so the page finished on the
       * same left lean it opens with. `items-end` sits the paragraph on
       * the button row rather than letting it float against the h2.
       */}
      <div class="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-x-12 gap-y-8 items-end">
        <div>
          <Kicker>Reference</Kicker>
          <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-7 text-balance">
            Specified, not implied.
          </h2>
          <div class="flex flex-wrap gap-x-4 gap-y-3">
            <Btn href="/docs" primary>
              Read the docs →
            </Btn>
            <Btn href="/spec">Read the spec →</Btn>
          </div>
        </div>
        <p class="text-base leading-relaxed lg:pb-1" style={`color:${C.dim};`}>
          Docs cover the common workflows.{" "}
          <code class="fd0-mono" style={`color:${C.acc};font-family:${FONT_MONO};`}>
            fd0 --help
          </code>{" "}
          covers the full command surface. The specification covers the wire
          format, cryptographic constructions, on-disk format, transparency log,
          and threat model.
        </p>
      </div>
    </Section>

    <Footer />
  </div>
);

export default ssr(async (c) => {
  setPageSeo(c, "home");
  return () => <Home />;
});
