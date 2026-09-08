import { Hono, type Context } from "hono";
import { logger } from "hono/logger";
import { serveStatic } from "hono/bun";
import { timingSafeEqual } from "crypto";
import { join } from "node:path";
import {
  canonicalUrl,
  config,
  routes,
  SEO_ROUTES,
  sitemapLastmod,
  SITE_URL,
} from "../config";
import { ErrorPage, errorPresets } from "./lib/error";
import { html as renderHTML } from "../config";
import {
  DocsOverview,
  DocsConcepts,
  DocsInstall,
  DocsDesktop,
  DocsCli,
  DocsPass,
  DocsBrowser,
  DocsSsh,
  DocsTalos,
  DocsSync,
  DocsServer,
  DocsYubikey,
  DocsRecovery,
  DocsTroubleshooting,
} from "./pages/Docs";
import Home from "./pages/Home";
import {
  SpecOverview,
  SpecWire,
  SpecCrypto,
  SpecStorage,
  SpecSync,
  SpecTranslog,
  SpecThreats,
} from "./pages/Spec";
import Witness from "./pages/Witness";
import Privacy from "./pages/Privacy";
import { fetchStableDesktopReleases } from "./lib/desktop-releases";

const VERSION = process.env.FD0_WEBSITE_VERSION ?? "dev";
const IMPRESSUM_URL = "https://impressum.valentin-kolb.com";
const METRICS_TOKEN = (process.env.FD0_WEBSITE_METRICS_TOKEN ?? "").trim();
const installScriptPath = (name: "install.sh" | "install-desktop.sh"): string =>
  process.env.NODE_ENV === "production"
    ? join(import.meta.dir, "public", name)
    : join(import.meta.dir, "..", "..", "scripts", name);

const serveInstallScript = async (
  c: Context,
  name: "install.sh" | "install-desktop.sh",
) => {
  const file = Bun.file(installScriptPath(name));
  if (!(await file.exists())) return c.notFound();
  return new Response(file, {
    headers: {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
};

// ─── tiny in-process metrics ───────────────────────────────────────
//
// We intentionally don't pull a prom-client dep — three counters and
// a histogram are easier to keep in sync with the Go binaries by
// hand-rolling the text-format exposition (it's six fields).
const startedAt = Date.now();
const m = {
  requestsTotal: new Map<string, number>(), // key = "method|path_label|status_class"
  responseBytes: 0,
  inFlight: 0,
  uptime: () => (Date.now() - startedAt) / 1000,
};
const metricPaths = new Set([
  ...SEO_ROUTES.map((route) => route.path),
  "/impressum",
  "/health",
  "/version",
  "/metrics",
  "/robots.txt",
  "/sitemap.xml",
  "/llms.txt",
  "/install",
  "/install.sh",
  "/install-desktop",
  "/install-desktop.sh",
  "/files/compose.yml",
  "/api/desktop/releases",
  "/download",
]);
export const metricPathLabel = (path: string): string => {
  if (metricPaths.has(path)) return path;
  if (path.startsWith("/public/")) return "/public/*";
  return "/*";
};
export const metricMethod = (method: string): string =>
  ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)
    ? method
    : "OTHER";
const statusClass = (s: number): string => {
  if (s >= 500) return "5xx";
  if (s >= 400) return "4xx";
  if (s >= 300) return "3xx";
  if (s >= 200) return "2xx";
  return "other";
};
const bumpCounter = (k: string) =>
  m.requestsTotal.set(k, (m.requestsTotal.get(k) ?? 0) + 1);

const renderPrometheus = (): string => {
  const lines: string[] = [];
  lines.push(
    "# HELP fd0_http_requests_total HTTP requests processed by the website.",
  );
  lines.push("# TYPE fd0_http_requests_total counter");
  for (const [key, n] of m.requestsTotal) {
    const [method, op, klass] = key.split("|");
    lines.push(
      `fd0_http_requests_total{service="fd0-website",op="${method} ${op}",status_class="${klass}"} ${n}`,
    );
  }
  lines.push("# HELP fd0_http_in_flight In-flight requests.");
  lines.push("# TYPE fd0_http_in_flight gauge");
  lines.push(`fd0_http_in_flight{service="fd0-website"} ${m.inFlight}`);
  lines.push("# HELP fd0_uptime_seconds Process uptime in seconds.");
  lines.push("# TYPE fd0_uptime_seconds gauge");
  lines.push(`fd0_uptime_seconds{service="fd0-website"} ${m.uptime().toFixed(0)}`);
  lines.push("# HELP fd0_build_info Build identifier (constant 1).");
  lines.push("# TYPE fd0_build_info gauge");
  lines.push(
    `fd0_build_info{service="fd0-website",version="${VERSION}"} 1`,
  );
  return lines.join("\n") + "\n";
};

const checkBearer = (auth: string | undefined, expected: string): boolean => {
  if (!expected) return true; // open mode
  const got = (auth ?? "").trim();
  const want = `Bearer ${expected}`;
  if (got.length !== want.length) return false;
  return timingSafeEqual(Buffer.from(got), Buffer.from(want));
};

const xmlEscape = (s: string): string =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const renderSitemap = (): string =>
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  SEO_ROUTES.map(
    (route) =>
      `  <url><loc>${xmlEscape(canonicalUrl(route.path))}</loc>` +
      `<lastmod>${xmlEscape(sitemapLastmod(route))}</lastmod></url>`,
  ).join("\n") +
  "\n</urlset>\n";

const renderLlmsTxt = (): string =>
  [
    "# fd0",
    "",
    "> fd0 is a zero-knowledge secrets manager for passwords, SSH keys, " +
      "host inventory, Kubernetes and Talos credentials.",
    "",
    "Use fd0 when you need client-side encryption, scope-based sharing, " +
      "local agent unlock, SSH-agent integration, and a transparency-log-backed sync server.",
    "",
    "## Primary pages",
    ...SEO_ROUTES.filter(
      (route) => route.path === "/" || route.path.startsWith("/docs"),
    ).map(
      (route) =>
        `- [${route.title}](${canonicalUrl(route.path)}): ${route.description}`,
    ),
    "",
    "## Agent skill",
    "Install with `npx skills add k2b-dev/fd0.sh` or `bunx skills add k2b-dev/fd0.sh`.",
    "The skill provides fd0 CLI instructions. Install fd0 and initialize a vault separately; normal access and unlock requirements apply.",
    "- [Agent skill setup](https://fd0.sh/docs/install#agent-skill): choose agents and project or global installation.",
    "- [Skill source](https://github.com/k2b-dev/fd0.sh/tree/main/skills/fd0): instructions and command references.",
    "",
    "## Protocol and trust model",
    ...SEO_ROUTES.filter(
      (route) => route.path.startsWith("/spec") || route.path === "/witness",
    ).map(
      (route) =>
        `- [${route.title}](${canonicalUrl(route.path)}): ${route.description}`,
    ),
    "",
    "## Source",
    "- [GitHub repository](https://github.com/k2b-dev/fd0.sh): client, server, witness, website, protocol docs, and release workflows.",
    "",
  ].join("\n");

const withoutTrailingSlash = (url: string): string | undefined => {
  const u = new URL(url);
  if (u.pathname === "/" || !u.pathname.endsWith("/")) return undefined;
  u.pathname = u.pathname.replace(/\/+$/, "");
  return `${u.pathname}${u.search}`;
};

// ─── Hono app ──────────────────────────────────────────────────────
const app = new Hono()
  .use(logger())
  // Metrics middleware — counts every request, records bytes/status.
  .use(async (c, next) => {
    m.inFlight++;
    try {
      await next();
    } finally {
      m.inFlight--;
      bumpCounter(
        [metricMethod(c.req.method), metricPathLabel(c.req.path), statusClass(c.res.status)].join("|"),
      );
    }
  })
  .use(async (c, next) => {
    const target = withoutTrailingSlash(c.req.url);
    if (target) return c.redirect(target, 308);
    await next();
  })
  // Operational endpoints — version-neutral, never under /v1/.
  .get("/health", (c) =>
    c.json({ status: "ok", service: "fd0-website", version: VERSION }),
  )
  .get("/version", (c) =>
    c.json({
      service: "fd0-website",
      server_version: VERSION,
      api_version: "v1",
    }),
  )
  /*
   * One click to the newest desktop build.
   *
   * GitHub's own /releases/latest returns the most recent release of ANY kind,
   * and this repo tags client-v* and desktop-v* into the same feed — so a CLI
   * release landing after a desktop one would send people to a page with no
   * app on it. This resolves the newest stable desktop-v* tag instead, and
   * falls back to the filtered release list when the feed cannot be read.
   */
  .get("/download", async (c) => {
    const fallback = "https://github.com/k2b-dev/fd0.sh/releases?q=desktop-v&expanded=true";
    try {
      const releases = await fetchStableDesktopReleases();
      const newest = releases[0]?.tag_name;
      if (!newest) return c.redirect(fallback, 302);
      return c.redirect(`https://github.com/k2b-dev/fd0.sh/releases/tag/${newest}`, 302);
    } catch {
      return c.redirect(fallback, 302);
    }
  })
  .get("/api/desktop/releases", async (c) => {
    try {
      const releases = await fetchStableDesktopReleases();
      const headers = {
        "Cache-Control": "public, max-age=300, stale-if-error=86400",
      };
      if (c.req.query("format") === "tags") {
        return c.text(releases.map((release) => release.tag_name).join("\n") + "\n", 200, headers);
      }
      return c.json(releases, 200, headers);
    } catch {
      return c.json({ error: "release feed unavailable" }, 503, {
        "Cache-Control": "no-store",
      });
    }
  })
  .get("/metrics", (c) => {
    if (!checkBearer(c.req.header("Authorization"), METRICS_TOKEN)) {
      return c.notFound();
    }
    return c.body(renderPrometheus(), 200, {
      "Content-Type": "text/plain; version=0.0.4",
    });
  })
  // Static assets
  .route("/_ssr", routes(config))
  .use(
    "/public/*",
    serveStatic({
      root: "./public",
      rewriteRequestPath: (p) => p.replace(/^\/public/, ""),
    }),
  )
  .get("/files/compose.yml", async (c) => {
    const file = Bun.file("./public/files/compose.yml");
    if (!(await file.exists())) return c.notFound();
    return new Response(file, {
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Cache-Control": "public, max-age=300",
      },
    });
  })
  // SEO files
  .get("/robots.txt", (c) =>
    c.body(
      [
        "User-agent: *",
        "Allow: /",
        "Disallow: /health",
        "Disallow: /metrics",
        "Disallow: /version",
        "",
        `Sitemap: ${SITE_URL}/sitemap.xml`,
        "",
      ].join("\n"),
      200,
      { "Content-Type": "text/plain; charset=utf-8" },
    ),
  )
  .get("/sitemap.xml", (c) => {
    return c.body(renderSitemap(), 200, {
      "Content-Type": "application/xml; charset=utf-8",
    });
  })
  .get("/llms.txt", (c) => {
    return c.body(renderLlmsTxt(), 200, {
      "Content-Type": "text/plain; charset=utf-8",
    });
  })
  // Install aliases serve the scripts embedded in this website build.
  .get("/install", (c) => serveInstallScript(c, "install.sh"))
  .get("/install.sh", (c) => serveInstallScript(c, "install.sh"))
  .get("/install-desktop", (c) => serveInstallScript(c, "install-desktop.sh"))
  .get("/install-desktop.sh", (c) => serveInstallScript(c, "install-desktop.sh"))
  // Pages
  .get("/", ...Home)
  .get("/docs", ...DocsOverview)
  .get("/docs/concepts", ...DocsConcepts)
  .get("/docs/install", ...DocsInstall)
  .get("/docs/desktop", ...DocsDesktop)
  .get("/docs/cli", ...DocsCli)
  .get("/docs/pass", ...DocsPass)
  .get("/docs/browser", ...DocsBrowser)
  .get("/docs/ssh", ...DocsSsh)
  .get("/docs/talos", ...DocsTalos)
  .get("/docs/sync", ...DocsSync)
  .get("/docs/server", ...DocsServer)
  .get("/docs/yubikey", ...DocsYubikey)
  .get("/docs/recovery", ...DocsRecovery)
  .get("/docs/troubleshooting", ...DocsTroubleshooting)
  .get("/spec", ...SpecOverview)
  .get("/spec/wire", ...SpecWire)
  .get("/spec/crypto", ...SpecCrypto)
  .get("/spec/storage", ...SpecStorage)
  .get("/spec/sync", ...SpecSync)
  .get("/spec/translog", ...SpecTranslog)
  .get("/spec/threats", ...SpecThreats)
  .get("/witness", ...Witness)
  .get("/privacy", ...Privacy)
  // The legal notice is maintained in one place for every site the same
  // provider runs. Temporary (302) rather than permanent so the route can
  // come back here without fighting a cached redirect.
  .get("/impressum", (c) => c.redirect(IMPRESSUM_URL, 302))
  // Error handlers — designed pages instead of plaintext.
  .notFound(async (c) => {
    const res = await renderHTML(() => <ErrorPage content={errorPresets[404]} />);
    return new Response(res.body, { status: 404, headers: res.headers });
  })
  .onError(async (err, c) => {
    console.error("[fd0-site] handler error:", err);
    const detail =
      process.env.NODE_ENV === "development"
        ? String(err.stack ?? err.message ?? err)
        : undefined;
    const res = await renderHTML(() => (
      <ErrorPage content={errorPresets[500]} detail={detail} />
    ));
    return new Response(res.body, { status: 500, headers: res.headers });
  });

const port = Number(process.env.PORT ?? 5173);
export default { port, fetch: app.fetch };
console.log(
  `[fd0-site] listening on http://localhost:${port}`,
  METRICS_TOKEN ? "(metrics: token-protected)" : "(metrics: open)",
);
