import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/password-tags";

let browser: Browser;
let code: string;
let css: string;
beforeAll(async () => {
  const result = await build({ configFile: false, plugins: [solid()], logLevel: "error",
    build: { write: false, lib: { entry: `${import.meta.dirname}/fixtures/password-tags.tsx`, name: "TagsTest", formats: ["iife"] } } });
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
    await page.evaluate(() => window.tagsTest.ready());
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

test("tag entry accepts literal text, explicit suggestions, exact matches and Tab", () => withPage(async (page) => {
  await page.evaluate(() => window.tagsTest.openEditor());
  const input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("wo");
  expect(await page.getByRole("option", { name: "Work", exact: true }).count()).toBe(1);
  expect(await page.getByRole("option", { name: "Private", exact: true }).count()).toBe(0);
  await input.press("Enter");
  expect(await page.getByRole("button", { name: "Remove tag wo", exact: true }).count()).toBe(1);
  await input.fill("work"); await input.press("Enter");
  expect(await page.getByRole("button", { name: "Remove tag Work", exact: true }).count()).toBe(1);
  await input.fill("Team"); await input.press("ArrowDown"); await input.press("Enter");
  expect(await page.getByRole("button", { name: "Remove tag Team A", exact: true }).count()).toBe(1);
  await input.fill("Free text"); await input.press("Tab");
  expect(await input.evaluate((node) => node === document.activeElement)).toBe(false);
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.saved()?.item.meta?.tags)).toEqual(["Existing", "wo", "Work", "Team A", "Free text"]);
}));

test("unchanged tags are omitted; pending text survives submit and failed saves", () => withPage(async (page) => {
  await page.evaluate(() => window.tagsTest.openEditor());
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.saved()?.item.meta)).toBeUndefined();
  await page.evaluate(() => { window.tagsTest.openEditor(); window.tagsTest.fail(true); });
  const input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("Pending");
  await page.locator("#item-editor-form").evaluate((form) => { if (form instanceof HTMLFormElement) form.requestSubmit(); });
  expect(await page.getByRole("button", { name: "Remove tag Pending", exact: true }).count()).toBe(1);
  await page.evaluate(() => window.tagsTest.fail(false));
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.saved()?.item.meta?.tags)).toEqual(["Existing", "Pending"]);
}));

test("clear sends an empty array and invalid input blocks saving", () => withPage(async (page) => {
  await page.evaluate(() => window.tagsTest.openEditor());
  await page.getByRole("button", { name: "Remove tag Existing" }).click();
  const input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("x".repeat(65));
  expect(await page.getByRole("button", { name: "Save changes", exact: true }).isDisabled()).toBe(true);
  expect(await page.getByRole("alert").count()).toBe(1);
  await input.fill("");
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.saved()?.item.meta?.tags)).toEqual([]);
}));

test("tag filters combine, clear on vault changes and support untagged items", () => withPage(async (page) => {
  await page.evaluate(() => window.tagsTest.filter({ type: "password", vault: "work", tags: ["Work", "Team A"] }));
  expect(await page.evaluate(() => window.tagsTest.visible())).toEqual(["Work login"]);
  await page.evaluate(() => window.tagsTest.filter({ vault: "private" }));
  expect(await page.evaluate(() => window.tagsTest.filters().tags)).toEqual([]);
  expect(await page.evaluate(() => window.tagsTest.visible())).toEqual(["Personal"]);
  await page.evaluate(() => window.tagsTest.filter({ vault: "work", untagged: true }));
  expect(await page.evaluate(() => window.tagsTest.visible())).toEqual(["No tags"]);
  await page.evaluate(() => window.tagsTest.filter({ tags: ["existing"] }));
  expect(await page.evaluate(() => window.tagsTest.filters().untagged)).toBe(false);
  expect(await page.evaluate(() => window.tagsTest.visible())).toEqual(["GitHub"]);
}));

test("vault changes refresh suggestions without losing tags and Escape only closes suggestions", () => withPage(async (page) => {
  await page.evaluate(() => window.tagsTest.openEditor(true));
  const input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("Local"); await input.press("Enter");
  await input.press("Escape");
  expect(await input.getAttribute("aria-expanded")).toBe("false");
  expect(await page.getByRole("dialog").count()).toBe(1);
  await page.getByRole("combobox", { name: "Vault", exact: true }).click();
  await page.getByRole("option", { name: "Private vault", exact: true }).click();
  await input.click();
  expect(await page.getByRole("option", { name: "Private", exact: true }).count()).toBe(1);
  expect(await page.getByRole("option", { name: "Work", exact: true }).count()).toBe(0);
  expect(await page.getByRole("button", { name: "Remove tag Local" }).count()).toBe(1);
  await input.fill("Private"); await input.press("Enter");
  await page.getByRole("button", { name: "Create item", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.saved()?.scopeId)).toBe("private");
  expect(await page.evaluate(() => window.tagsTest.saved()?.item.meta?.tags)).toEqual(["Local", "Private"]);
}));

test("filter popup is keyboard accessible and detail tags activate a filter", () => withPage(async (page) => {
  const trigger = page.getByRole("button", { name: "Tags", exact: true });
  await trigger.focus(); await trigger.press("Enter");
  expect(await page.getByRole("searchbox", { name: "Search tags" }).evaluate((node) => node === document.activeElement)).toBe(true);
  await page.getByRole("checkbox", { name: /Team A/ }).check();
  expect(await page.evaluate(() => window.tagsTest.visible())).toEqual(["Work login"]);
  await page.keyboard.press("Escape");
  expect(await trigger.evaluate((node) => node === document.activeElement)).toBe(true);
  await page.getByRole("button", { name: "Filter by tag Work", exact: true }).click();
  expect(await page.evaluate(() => window.tagsTest.filters().tags)).toEqual(["Work"]);
}));

test("tag editor wraps in narrow light and dark windows", () => withPage(async (page) => {
  await page.setViewportSize({ width: 560, height: 720 });
  await page.evaluate(() => window.tagsTest.openEditor());
  const input = page.getByRole("combobox", { name: /Tags/ });
  await input.fill("A long tag with spaces that still fits within sixty four chars");
  await input.press("Enter");
  for (const theme of ["dark", "light"]) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    expect(await page.locator(".tag-input-wrap").evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.getByRole("dialog").evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (process.env.FD0_TAGS_SCREENSHOTS) await page.screenshot({ path: `${process.env.FD0_TAGS_SCREENSHOTS}/password-tags-${theme}.png` });
  }
}));


test("new secret saves tags and retries a tag failure without duplicating content", () => withPage(async page => {
 await page.evaluate(() => { window.tagsTest.failTags(true); window.tagsTest.openSecret(); });
 const input = page.getByRole("combobox", { name:/Tags/ });
 await input.fill("Operations"); await input.press("Enter");
 await page.getByRole("button", { name:"Create item", exact:true }).click();
 await page.getByRole("button", { name:"Retry saving tags", exact:true }).waitFor();
 expect(await page.evaluate(() => window.tagsTest.secretState().writes)).toBe(1);
 await page.evaluate(() => window.tagsTest.failTags(false));
 await page.getByRole("button", { name:"Retry saving tags", exact:true }).click();
 expect(await page.evaluate(() => window.tagsTest.secretState())).toEqual({writes:1,tags:["Operations"]});
}));
