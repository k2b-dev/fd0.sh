import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/recipes";

let browser: Browser;
let code: string;
let css: string;
beforeAll(async () => {
  const result = await build({ configFile: false, plugins: [solid()], logLevel: "error",
    build: { write: false, lib: { entry: `${import.meta.dirname}/fixtures/recipes.tsx`, name: "RecipesTest", formats: ["iife"] } } });
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

async function withPage(query: string, run: (page: Page) => Promise<void>) {
  const page = await browser.newPage({ viewport: { width: 860, height: 900 } });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.route("**/*", (route) => route.fulfill({ contentType: "text/html", body: "<html><body></body></html>" }));
    await page.goto(`https://fd0-component.test/${query}`);
    await page.addStyleTag({ content: css });
    await page.addScriptTag({ content: code });
    await page.getByRole("heading", { name: "Deploys" }).waitFor();
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

test("the command is always visible with targets and results", () => withPage("", async (page) => {
  await page.getByText('kubectl -n "org-k2b-$FD0_TARGET" apply -f -').waitFor();
  expect(await page.getByText("file on fd 3").isVisible()).toBe(true);
  expect(await page.getByText("Failed · exit 1").isVisible()).toBe(true);
  expect(await page.getByRole("row", { name: /fibel/ }).isVisible()).toBe(true);
  expect(await page.getByRole("button", { name: "Approve…" }).count()).toBe(0);
}));

test("deploy runs only after confirmation, for the whole recipe or one target", () => withPage("", async (page) => {
  await page.getByRole("button", { name: "Deploy", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Deploy now?" }).waitFor();
  expect(await page.evaluate(() => window.recipeCalls)).toEqual([]);
  await page.getByRole("dialog").getByRole("button", { name: "Deploy", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "detached" });
  await page.getByRole("row", { name: /rsql-docs/ }).hover();
  await page.getByRole("button", { name: "Deploy docs/k8s-1 to rsql-docs" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Deploy", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "detached" });
  expect(await page.evaluate(() => window.recipeCalls)).toEqual(["deploy:docs/k8s-1:", "deploy:docs/k8s-1:rsql-docs"]);
}));

test("an unapproved recipe shows the full command before approval", () => withPage("?approved=0", async (page) => {
  expect(await page.getByText("Not approved on this device").isVisible()).toBe(true);
  expect(await page.getByRole("button", { name: "Deploy", exact: true }).count()).toBe(0);
  await page.getByRole("button", { name: "Approve…" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve docs/k8s-1" });
  await dialog.waitFor();
  expect(await dialog.getByText("value=$(cat <&3)").isVisible()).toBe(true);
  expect(await dialog.getByText("fibel, rsql-docs · once each").isVisible()).toBe(true);
  await dialog.getByLabel("Passphrase", { exact: true }).fill("synthetic-only");
  await dialog.getByRole("button", { name: "Approve on this device" }).click();
  await dialog.waitFor({ state: "detached" });
  expect(await page.evaluate(() => window.recipeCalls)).toEqual(["approve:docs/k8s-1:dddd:auth"]);
  await page.getByRole("button", { name: "Deploy", exact: true }).first().waitFor();
}));
