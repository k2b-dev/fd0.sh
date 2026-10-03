import { createConfig } from "@valentinkolb/ssr";
import { createSSRHandler, routes } from "@valentinkolb/ssr/hono";

// Per-page metadata. Beyond the SSR-default title/description, OG/Twitter
// fields support social previews; canonical lets crawlers dedup; structured
// data drives rich results.
type PageOptions = {
  title?: string;
  description?: string;
  canonical?: string;
  ogImage?: string;
  ogType?: "website" | "article";
  structuredData?: unknown[];
};

const SITE_NAME = "fd0";
const SITE_URL = process.env.FD0_SITE_URL ?? "https://fd0.sh";
const SITE_DESCRIPTION =
  "fd0 — a zero-knowledge secrets manager you run yourself or use hosted at fd0.sh. " +
  "Ciphertext-only server, hardware-backed identity via YubiKey-PIV, " +
  "end-to-end transparency log with independent witness verification.";
const SITE_LASTMOD = process.env.FD0_WEBSITE_LASTMOD ?? "2026-07-26";

type SeoRoute = {
  key: string;
  path: string;
  title: string;
  description: string;
  section?: "docs" | "spec";
  lastmod?: string;
};

export const canonicalUrl = (path: string) =>
  `${SITE_URL}${path === "/" ? "/" : path}`;

export const SEO_ROUTE = {
  home: {
    key: "home",
    path: "/",
    title: "fd0 — zero-knowledge secrets manager",
    description:
      "fd0 is a zero-knowledge secrets manager for passwords, SSH keys, host inventory, Kubernetes and Talos credentials, with a desktop app for macOS and Linux.",
  },
  docs: {
    key: "docs",
    path: "/docs",
    title: "fd0 documentation",
    description:
      "Learn how to install fd0, unlock your vault, store secrets, share scopes, sync devices, and use SSH, Talos, and Kubernetes integrations.",
    section: "docs",
  },
  docsConcepts: {
    key: "docsConcepts",
    path: "/docs/concepts",
    title: "fd0 concepts and architecture",
    description:
      "Understand fd0 identities, scopes, object encryption keys, cards, the local agent, sync server, and transparency witness.",
    section: "docs",
  },
  docsInstall: {
    key: "docsInstall",
    path: "/docs/install",
    title: "Install fd0 — Desktop, CLI, and agent",
    description:
      "Download fd0 Desktop for macOS or Linux, install the CLI and agent, initialize a vault, and choose the hosted fd0.sh backend or a self-hosted server.",
    section: "docs",
  },
  docsDesktop: {
    key: "docsDesktop",
    path: "/docs/desktop",
    title: "fd0 Desktop for macOS and Linux",
    description:
      "Download fd0 Desktop, see the vault, command palette, SSH hosts, and generator, and learn how the app installs alongside the fd0 CLI and agent.",
    section: "docs",
  },
  docsCli: {
    key: "docsCli",
    path: "/docs/cli",
    title: "fd0 CLI daily use",
    description:
      "Daily fd0 CLI commands: the shared item grammar, plain secrets, scopes and sharing, item history, unlock methods, and local health checks.",
    section: "docs",
  },
  docsPass: {
    key: "docsPass",
    path: "/docs/pass",
    title: "fd0 password manager",
    description:
      "Use fd0 pass for login items, secret and text fields, TOTP codes, passkeys, file attachments, sections, and the interactive browser.",
    section: "docs",
  },
  docsBrowser: {
    key: "docsBrowser",
    path: "/docs/browser",
    title: "fd0 browser extension for Chrome",
    description:
      "Install the fd0 Chrome extension for password autofill, generation, save/update, and one-time passwords from your local encrypted vault.",
    section: "docs",
  },
  docsSsh: {
    key: "docsSsh",
    path: "/docs/ssh",
    title: "fd0 SSH keys, hosts, and SFTP files",
    description:
      "Use fd0 for encrypted SSH keys, scope-shared hosts, terminal sessions, and two-way SFTP transfers through the same native OpenSSH configuration.",
    section: "docs",
  },
  docsTalos: {
    key: "docsTalos",
    path: "/docs/talos",
    title: "fd0 Talos and Kubernetes credentials",
    description:
      "Store, render, merge, and share Talos contexts, Kubernetes kubeconfigs, and day-0 Talos recovery credentials with fd0.",
    section: "docs",
  },
  docsServices: {
    key: "docsServices",
    path: "/docs/services",
    title: "fd0 services: credentials that programs read",
    description:
      "Keep database passwords, API tokens, and certificates in fd0 services and hand them to programs as env files, Kubernetes Secrets, or with fd0 run.",
    section: "docs",
  },
  docsMachines: {
    key: "docsMachines",
    path: "/docs/machines",
    title: "fd0 for machines and CI",
    description:
      "Give CI runners and deploy hosts their own fd0 identity with a key file, a pinned server, and read-only access to the scopes they need.",
    section: "docs",
  },
  docsSync: {
    key: "docsSync",
    path: "/docs/sync",
    title: "fd0 sync and scope discovery",
    description:
      "How fd0 sync pushes signed local events, pulls server history, discovers shared scopes, and refreshes enabled local projections.",
    section: "docs",
  },
  docsServer: {
    key: "docsServer",
    path: "/docs/server",
    title: "Self-host fd0 server",
    description:
      "Run the fd0 server yourself with the compose example, a TLS reverse proxy, backups, metrics, and an optional transparency witness.",
    section: "docs",
  },
  docsYubikey: {
    key: "docsYubikey",
    path: "/docs/yubikey",
    title: "fd0 YubiKey unlock",
    description:
      "Add a YubiKey PIV unlock method to fd0, use PIN plus touch to unlock locally, and keep recovery available for device loss.",
    section: "docs",
  },
  docsRecovery: {
    key: "docsRecovery",
    path: "/docs/recovery",
    title: "fd0 recovery and backup",
    description:
      "Export and restore fd0 recovery material so a lost device or passphrase method does not permanently lock you out.",
    section: "docs",
  },
  docsTroubleshooting: {
    key: "docsTroubleshooting",
    path: "/docs/troubleshooting",
    title: "fd0 troubleshooting",
    description:
      "Diagnose fd0 vault, sync, SSH socket, missing host, and local config refresh problems with doctor and agent commands.",
    section: "docs",
  },
  spec: {
    key: "spec",
    path: "/spec",
    title: "fd0 protocol specification",
    description:
      "Read the fd0 protocol overview covering deterministic wire formats, cryptography, storage, sync, transparency, and threat model.",
    section: "spec",
  },
  specWire: {
    key: "specWire",
    path: "/spec/wire",
    title: "fd0 wire format specification",
    description:
      "fd0 wire-format reference for deterministic CBOR, domain-separated signatures, IDs, timestamps, and binary encodings.",
    section: "spec",
  },
  specCrypto: {
    key: "specCrypto",
    path: "/spec/crypto",
    title: "fd0 cryptography specification",
    description:
      "fd0 cryptography reference for Ed25519, X25519, AES-256-GCM, Argon2id, OEK rotation, passphrase, and YubiKey unlocks.",
    section: "spec",
  },
  specStorage: {
    key: "specStorage",
    path: "/spec/storage",
    title: "fd0 storage format specification",
    description:
      "fd0 storage reference for the encrypted vault, append-only user and scope chains, event bodies, tombstones, and verified history repair.",
    section: "spec",
  },
  specSync: {
    key: "specSync",
    path: "/spec/sync",
    title: "fd0 sync protocol specification",
    description:
      "fd0 sync protocol reference for optimistic concurrency, signed pushes, paginated pulls, replay, discovery, and conflict handling.",
    section: "spec",
  },
  specTranslog: {
    key: "specTranslog",
    path: "/spec/translog",
    title: "fd0 transparency log specification",
    description:
      "fd0 transparency-log reference for RFC 6962 Merkle trees, signed tree heads, witness cosigning, and fork detection.",
    section: "spec",
  },
  specThreats: {
    key: "specThreats",
    path: "/spec/threats",
    title: "fd0 threat model",
    description:
      "fd0 threat model for server compromise, client compromise, replay, equivocation, metadata exposure, and operational limits.",
    section: "spec",
  },
  witness: {
    key: "witness",
    path: "/witness",
    title: "fd0 public transparency witness",
    description:
      "Live state of the official fd0 transparency-log witness: pubkey, observed chains, cosignatures, and equivocation status.",
  },
  privacy: {
    key: "privacy",
    path: "/privacy",
    title: "fd0 privacy policy",
    description:
      "How fd0 Desktop, the CLI and agent, browser extension, hosted sync service, and fd0.sh website handle data.",
  },
} satisfies Record<string, SeoRoute>;

export type SeoRouteKey = keyof typeof SEO_ROUTE;

export const SEO_ROUTES = [
  SEO_ROUTE.home,
  SEO_ROUTE.docs,
  SEO_ROUTE.docsConcepts,
  SEO_ROUTE.docsInstall,
  SEO_ROUTE.docsDesktop,
  SEO_ROUTE.docsCli,
  SEO_ROUTE.docsPass,
  SEO_ROUTE.docsBrowser,
  SEO_ROUTE.docsSsh,
  SEO_ROUTE.docsTalos,
  SEO_ROUTE.docsServices,
  SEO_ROUTE.docsMachines,
  SEO_ROUTE.docsSync,
  SEO_ROUTE.docsServer,
  SEO_ROUTE.docsYubikey,
  SEO_ROUTE.docsRecovery,
  SEO_ROUTE.docsTroubleshooting,
  SEO_ROUTE.spec,
  SEO_ROUTE.specWire,
  SEO_ROUTE.specCrypto,
  SEO_ROUTE.specStorage,
  SEO_ROUTE.specSync,
  SEO_ROUTE.specTranslog,
  SEO_ROUTE.specThreats,
  SEO_ROUTE.witness,
  SEO_ROUTE.privacy,
] as const;

export const sitemapLastmod = (route: SeoRoute) =>
  route.lastmod ?? SITE_LASTMOD;

const breadcrumbStructuredData = (route: SeoRoute) => {
  if (route.path === "/") return undefined;

  const items = [{ name: SITE_NAME, path: "/" }];
  if (route.section === "docs") items.push({ name: "Docs", path: "/docs" });
  if (route.section === "spec") items.push({ name: "Spec", path: "/spec" });
  if (items[items.length - 1].path !== route.path) {
    items.push({
      name: route.title.replace(/^fd0\s+—\s+/, ""),
      path: route.path,
    });
  }

  return {
    "@type": "BreadcrumbList",
    itemListElement: items.map((item, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: item.name,
      item: canonicalUrl(item.path),
    })),
  };
};

export const setPageSeo = (
  c: { get: (key: "page") => PageOptions },
  key: SeoRouteKey,
) => {
  const route = SEO_ROUTE[key];
  const page = c.get("page");
  page.title = route.title;
  page.description = route.description;
  page.canonical = canonicalUrl(route.path);
  const breadcrumb = breadcrumbStructuredData(route);
  page.structuredData = breadcrumb ? [breadcrumb] : undefined;
};

// @font-face declarations live in the HTML head as an inline <style>
// block — keeps bun's CSS bundler from trying to resolve the woff2
// URLs at build time. The files themselves are copied to
// dist/public/fonts/ by scripts/copy-fonts.ts and served by the same
// serveStatic route as everything else under /public/.
const FONT_FACE_CSS = `
@font-face{font-family:"Geist";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-latin-wght-normal.woff2") format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:"Geist";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-latin-ext-wght-normal.woff2") format("woff2-variations");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF;}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-mono-latin-wght-normal.woff2") format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-mono-latin-ext-wght-normal.woff2") format("woff2-variations");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF;}
`.trim();

const ORG_JSONLD = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${SITE_URL}/#org`,
      name: SITE_NAME,
      url: SITE_URL,
      logo: `${SITE_URL}/public/logo.svg`,
      sameAs: ["https://github.com/k2b-dev/fd0.sh"],
    },
    {
      "@type": "SoftwareApplication",
      name: "fd0",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Linux, macOS",
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
      license: "https://www.apache.org/licenses/LICENSE-2.0",
      url: SITE_URL,
    },
  ],
};

export const { config, plugin, html } = createConfig<PageOptions>({
  dev: process.env.NODE_ENV === "development",
  rootDir: import.meta.dir,
  template: ({
    body,
    scripts,
    title,
    description,
    canonical,
    ogImage,
    ogType,
    structuredData,
  }) => {
    const t = title ?? "fd0 — zero-knowledge secrets manager";
    const d = description ?? SITE_DESCRIPTION;
    const img = ogImage ?? `${SITE_URL}/public/og-card.png`;
    const url = canonical ?? SITE_URL;
    const jsonLd = {
      ...ORG_JSONLD,
      "@graph": [...ORG_JSONLD["@graph"], ...(structuredData ?? [])],
    };
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#0b0d0c">
    <meta name="color-scheme" content="dark">
    <meta name="view-transition" content="same-origin">
    <title>${t}</title>
    <meta name="description" content="${d}">

    <link rel="canonical" href="${url}">

    <meta property="og:type" content="${ogType ?? "website"}">
    <meta property="og:site_name" content="${SITE_NAME}">
    <meta property="og:title" content="${t}">
    <meta property="og:description" content="${d}">
    <meta property="og:url" content="${url}">
    <meta property="og:image" content="${img}">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">

    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${t}">
    <meta name="twitter:description" content="${d}">
    <meta name="twitter:image" content="${img}">

    <link rel="icon" type="image/svg+xml" href="/public/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/public/favicon-32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/public/favicon-16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/public/apple-touch-icon.png">
    <link rel="shortcut icon" href="/public/favicon.ico">
    <link rel="preload" as="font" type="font/woff2" href="/public/fonts/geist-latin-wght-normal.woff2" crossorigin>
    <link rel="preload" as="font" type="font/woff2" href="/public/fonts/geist-mono-latin-wght-normal.woff2" crossorigin>
    <style>${FONT_FACE_CSS}</style>
    <link rel="stylesheet" href="/public/styles.css">

    <script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
  </head>
  <body>${body}${scripts}</body>
</html>`;
  },
});

export const ssr = createSSRHandler(html);
export { routes, SITE_URL, SITE_LASTMOD };
