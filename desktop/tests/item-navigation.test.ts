import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/item-navigation";

let browser: Browser;
let code: string;
let css: string;
beforeAll(async () => {
  const result = await build({ configFile: false, plugins: [solid()], logLevel: "error",
    build: { write: false, lib: { entry: `${import.meta.dirname}/fixtures/item-navigation.tsx`, name: "NavigationTest", formats: ["iife"] } } });
  const bundle = Array.isArray(result) ? result[0] : result;
  if (!bundle || !("output" in bundle)) throw new Error("Missing component bundle");
  const chunk = bundle.output.find((output) => output.type === "chunk");
  if (!chunk || chunk.type !== "chunk") throw new Error("Missing component code");
  code = chunk.code;
  css = bundle.output.filter((output) => output.type === "asset" && output.fileName.endsWith(".css"))
    .map((output) => output.type === "asset" ? String(output.source) : "").join("\n");
  browser = await chromium.launch({ headless: true });
}, 30_000);
afterAll(async () => { await browser?.close(); });

async function withPage(run: (page: Page) => Promise<void>) {
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.route("**/*", (route) => route.fulfill({ contentType: "text/html", body: "<html><body></body></html>" }));
    await page.goto("https://fd0-component.test");
    await page.addStyleTag({ content: css });
    await page.addScriptTag({ content: code });
    await page.evaluate(() => window.navigationTest.ready());
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

test("global search crosses filters and Back restores the password context", () => withPage(async (page) => {
  await page.evaluate(() => {
    window.navigationTest.filter({ type: "password", vault: "work", view: "favorites", tags: ["Team"] });
    window.navigationTest.query("Login"); window.navigationTest.palette();
  });
  await page.getByPlaceholder("Search items or type a command…").fill("API token");
  await page.getByRole("option").filter({ hasText: "API token" }).click();
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "API token", detail: "API token", back: "Login", query: "", filters: { type: "secret", vault: "private", tags: [], view: "all" } });
  await page.getByRole("button", { name: "Back to Login", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "Login", detail: "Login", query: "Login", filters: { type: "password", vault: "work", tags: ["Team"], view: "favorites" } });
}));

test("linked SSH key returns to its host and search context", () => withPage(async (page) => {
  await page.evaluate(() => { window.navigationTest.filter({ type: "ssh" }); window.navigationTest.query("Host"); window.navigationTest.narrow(true); });
  await page.getByRole("button", { name: "Open SSH key Key", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "Key", detail: "Key", back: "Host" });
  await page.getByRole("button", { name: "Back to Host", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "Host", detail: "Host", query: "Host" });
  await page.getByRole("button", { name: "Back to the list", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state().listShown)).toBe(true);
}));

test("history skips removed items and clears on manual navigation and lock", () => withPage(async (page) => {
  await page.evaluate(async () => {
    window.navigationTest.jump("Host"); window.navigationTest.jump("Key");
    await window.navigationTest.remove("Host"); window.navigationTest.back();
  });
  expect(await page.evaluate(() => window.navigationTest.state().selected)).toBe("Login");
  await page.evaluate(() => { window.navigationTest.jump("API token"); window.navigationTest.select("API token"); });
  expect(await page.evaluate(() => window.navigationTest.state().back)).toBeUndefined();
  await page.evaluate(() => { window.navigationTest.jump("Login"); window.navigationTest.filter({ type: "all" }); });
  expect(await page.evaluate(() => window.navigationTest.state().back)).toBeUndefined();
  await page.evaluate(async () => { window.navigationTest.jump("Key"); await window.navigationTest.lock(); });
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "", back: undefined, detail: undefined });
}));

test("Back handles changed metadata and restores raw projection without self loops", () => withPage(async (page) => {
  await page.evaluate(async () => {
    window.navigationTest.query("Login"); window.navigationTest.jump("API token");
    await window.navigationTest.rename(); window.navigationTest.back();
  });
  expect(await page.evaluate(() => window.navigationTest.state().selected)).toBe("Login");
  await page.evaluate(() => {
    window.navigationTest.filter({ type: "secret" }); window.navigationTest.raw(true);
    window.navigationTest.select("Login");
    window.navigationTest.jump("Key"); window.navigationTest.jump("Key");
  });
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "Key", raw: false, back: "Login" });
  await page.getByRole("button", { name: "Back to Renamed", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state())).toMatchObject({ selected: "Login", raw: true, back: undefined });
}));

test("tags edit secrets and hosts without exposing fields and keep host tag casing", () => withPage(async (page) => {
  await page.evaluate(() => window.navigationTest.jump("API token"));
  await page.getByRole("button", { name: "Edit tags", exact: true }).click();
  let input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("Production"); await input.press("Enter");
  await page.getByRole("button", { name: "Save tags", exact: true }).click();
  expect(await page.getByRole("button", { name: "Filter by tag Production", exact: true }).count()).toBe(1);
  await page.evaluate(() => window.navigationTest.jump("Host"));
  await page.getByRole("button", { name: "Edit tags", exact: true }).click();
  input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("Prod"); await input.press("Enter");
  await input.fill("prod"); await input.press("Enter");
  await input.fill("bad,tag");
  expect(await page.getByRole("alert").count()).toBeGreaterThan(0);
  await input.fill("");
  await page.getByRole("button", { name: "Save tags", exact: true }).click();
  expect(await page.getByRole("button", { name: "Filter by tag Prod", exact: true }).count()).toBe(1);
  expect(await page.getByRole("button", { name: "Filter by tag prod", exact: true }).count()).toBe(1);
  await page.getByRole("button", { name: "Filter by tag prod", exact: true }).click();
  expect(await page.evaluate(() => window.navigationTest.state().selected)).toBe("Host");
}));


test("bulk organization previews a fixed cross-type selection before applying", () => withPage(async page => {
 await page.getByRole("button", { name:"Organize", exact:true }).click();
 const modal = page.getByRole("dialog", { name:"Organize items", exact:true });
 await modal.getByRole("button", { name:"Select first 4", exact:true }).click();
 const tags = modal.getByRole("combobox", { name:/Tags/ });
 await tags.fill("Operations"); await tags.press("Enter");
 await modal.getByRole("button", { name:"Review changes", exact:true }).click();
 expect(await page.evaluate(() => window.navigationTest.batches().map(call => call.dryRun))).toEqual([true]);
 expect(await modal.getByText("Operations", { exact:false }).count()).toBe(4);
 await modal.getByRole("button", { name:"Apply reviewed changes", exact:true }).click();
 await modal.waitFor({ state:"hidden" });
 expect(await page.evaluate(() => window.navigationTest.batches().map(call => ({ dryRun:call.dryRun, count:call.items.length })))).toEqual([{dryRun:true,count:4},{dryRun:false,count:4}]);
}));
