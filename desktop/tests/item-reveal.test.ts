import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/item-reveal";

let browser: Browser;
let code: string;
beforeAll(async () => {
  const result = await build({
    configFile: false,
    plugins: [solid()],
    logLevel: "error",
    build: {
      write: false,
      lib: { entry: `${import.meta.dirname}/fixtures/item-reveal.tsx`, name: "RevealTest", formats: ["iife"] },
    },
  });
  const bundle = Array.isArray(result) ? result[0] : result;
  if (!bundle || !("output" in bundle)) throw new Error("Expected one component bundle");
  const chunk = bundle.output.find((output) => output.type === "chunk");
  if (!chunk || chunk.type !== "chunk") throw new Error("Missing component bundle");
  code = chunk.code;
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
    await page.clock.install();
    await page.addScriptTag({ content: code });
    await page.evaluate(() => window.revealTest.refresh());
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

test("same-item refresh preserves reveal until the original 15-second deadline", () => withPage(async (page) => {
  await page.getByRole("button", { name: "Reveal Token", exact: true }).click();
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(1);
  await page.clock.runFor(500);
  await page.evaluate(() => window.revealTest.refresh());
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(1);
  await page.clock.runFor(14_250);
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(1);
  await page.clock.runFor(250);
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(0);
}));

test("confirmation time and a pending refresh do not shorten the reveal window", () => withPage(async (page) => {
  await page.evaluate(() => window.revealTest.defer());
  await page.getByRole("button", { name: "Reveal Token", exact: true }).click();
  await page.clock.runFor(20_000);
  await page.evaluate(() => window.revealTest.refresh());
  await page.evaluate(() => window.revealTest.resolve());
  await page.clock.runFor(14_750);
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(1);
  await page.clock.runFor(250);
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(0);
}));

test("item changes and clearing the detail discard revealed values", () => withPage(async (page) => {
  await page.getByRole("button", { name: "Reveal Token", exact: true }).click();
  await page.evaluate(() => window.revealTest.refresh("second"));
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(0);
  await page.getByRole("button", { name: "Reveal Token", exact: true }).click();
  await page.evaluate(() => window.revealTest.clear());
  await page.evaluate(() => window.revealTest.refresh());
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(0);
}));

test("a late reveal response cannot reveal a different item", () => withPage(async (page) => {
  await page.evaluate(() => window.revealTest.defer());
  await page.getByRole("button", { name: "Reveal Token", exact: true }).click();
  await page.evaluate(() => window.revealTest.refresh("second"));
  await page.evaluate(() => window.revealTest.resolve());
  expect(await page.getByText("synthetic-secret", { exact: true }).count()).toBe(0);
}));
