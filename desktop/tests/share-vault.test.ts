import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/share-vault";

let browser: Browser;
let code: string;
let css: string;
beforeAll(async () => {
  const result = await build({ configFile: false, plugins: [solid()], logLevel: "error",
    build: { write: false, lib: { entry: `${import.meta.dirname}/fixtures/share-vault.tsx`, name: "ShareTest", formats: ["iife"] } } });
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

async function withPage(role: string, run: (page: Page) => Promise<void>) {
  const page = await browser.newPage({ viewport: { width: 720, height: 900 } });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.route("**/*", (route) => route.fulfill({ contentType: "text/html", body: "<html><body></body></html>" }));
    await page.goto(`https://fd0-component.test/?role=${role}`);
    await page.addStyleTag({ content: css });
    await page.addScriptTag({ content: code });
    await page.getByText("People with access").waitFor({ state: "attached" });
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

test("admins see roles and can change them", () => withPage("admin", async (page) => {
  await page.getByText("Reader · identity confirmed").waitFor({ state: "attached" });
  expect(await page.getByLabel("Role of ci-runner").count()).toBe(1);
  expect(await page.getByLabel("Role for people you add").count()).toBe(1);
  expect(await page.getByText("Remove", { exact: true }).count()).toBe(1);
  expect(await page.getByText("Give access").count()).toBe(1);
}));

test("readers see access read-only", () => withPage("reader", async (page) => {
  await page.getByText("Only admins can change who has access").waitFor({ state: "attached" });
  expect(await page.getByLabel("Role of ci-runner").count()).toBe(0);
  expect(await page.getByText("Remove", { exact: true }).count()).toBe(0);
  expect(await page.getByText("Give access").count()).toBe(0);
  expect(await page.getByText("People you know").count()).toBe(0);
  expect(await page.getByText("Rename", { exact: true }).count()).toBe(0);
}));
