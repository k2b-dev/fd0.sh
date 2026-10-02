import { afterAll, beforeAll, expect, test } from "bun:test";
import { chromium, type Browser, type Page } from "@playwright/test";
import { build } from "vite";
import solid from "vite-plugin-solid";
import type {} from "./fixtures/authentication";

let browser: Browser;
let code: string;
let css: string;
beforeAll(async () => {
  const result = await build({ configFile: false, plugins: [solid()], logLevel: "error",
    build: { write: false, lib: { entry: `${import.meta.dirname}/fixtures/authentication.tsx`, name: "TagsTest", formats: ["iife"] } } });
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
    await page.evaluate(() => Promise.resolve());
    await run(page);
    expect(errors).toEqual([]);
  } finally { await page.close(); }
}

for (const mode of ["unlock", "grant"]) {
  async function open(page: Page) {
    await page.evaluate((mode) => window.authTest.mode(mode), mode);
    if (mode === "grant") await page.getByRole("button", {name:"Allow SSH while locked…"}).click();
  }
  const submit = mode === "unlock" ? "Unlock" : "Authenticate and allow";
  test(`${mode}: shared choices, preferred touch-only key and method switching`, () => withPage(async (page) => {
    await open(page);
    const key = page.getByRole("radio", {name:"YubiKey"});
    expect(await key.getAttribute("aria-checked")).toBe("true");
    expect(await page.getByLabel("YubiKey PIN", {exact:true}).count()).toBe(0);
    await page.getByRole("radio", {name:"Passphrase",exact:true}).click();
    await page.getByRole("textbox", {name:"Passphrase",exact:true}).fill("synthetic-only");
    await key.click();
    await page.getByRole("button", {name:submit,exact:true}).click();
    expect(await page.evaluate(() => window.authTest.submitted())).toMatchObject({method:"key",passphrase:"",pin:""});
  }));
  test(`${mode}: PIN rules and errors match`, () => withPage(async (page) => {
    await page.evaluate(() => window.authTest.pin("required"));
    await open(page);
    const button=page.getByRole("button",{name:submit,exact:true});
    expect(await button.isDisabled()).toBe(true);
    await page.getByLabel("YubiKey PIN",{exact:true}).fill("123456");
    await page.evaluate(() => window.authTest.fail(true));
    await button.click();
    await page.getByRole("alert").waitFor();
    expect(await page.getByLabel("YubiKey PIN",{exact:true}).inputValue()).toBe("");
    expect(await page.getByLabel("YubiKey PIN",{exact:true}).evaluate(node => node === document.activeElement)).toBe(true);
    expect(await page.getByRole("radio").count()).toBe(2);
    await page.evaluate(() => window.authTest.pin("none",false));
    expect(await button.isDisabled()).toBe(true);
    expect(await page.getByText("This installation of fd0 was built without YubiKey support.").count()).toBe(1);
  }));
  test(`${mode}: passphrase authentication and missing methods`, () => withPage(async (page) => {
    await open(page);
    await page.getByRole("radio",{name:"Passphrase",exact:true}).click();
    await page.getByRole("textbox",{name:"Passphrase",exact:true}).fill("synthetic-only");
    await page.getByRole("button",{name:submit,exact:true}).click();
    expect(await page.evaluate(() => window.authTest.submitted())).toMatchObject({method:"pass",passphrase:"synthetic-only",pin:""});
    if (mode === "grant") await page.getByRole("button",{name:"Allow SSH while locked…"}).click();
    await page.evaluate(() => window.authTest.missing());
    expect(await page.getByRole("button",{name:submit,exact:true}).isDisabled()).toBe(true);
    expect(await page.getByRole("textbox",{name:"Passphrase",exact:true}).count()).toBe(0);
    expect(await page.getByRole("alert").count()).toBe(1);
  }));

}

test("active grants open a full-window overview instead of the unlock form", () => withPage(async (page) => {
  await page.evaluate(() => window.authTest.grants(2));
  const pill = page.getByRole("button", { name: "2 active grants" });
  await pill.waitFor();
  expect(await page.getByRole("button", { name: "Lock everything" }).count()).toBe(0);
  await pill.click();
  await page.getByRole("heading", { name: "Active while locked" }).waitFor();
  expect(await page.getByRole("button", { name: "Unlock", exact: true }).isVisible()).toBe(true);
  expect(await page.getByRole("textbox", { name: "Passphrase", exact: true }).count()).toBe(0);
  const rows = page.getByRole("option");
  expect(await rows.count()).toBe(2);
  expect(await rows.first().getAttribute("aria-selected")).toBe("true");
  await page.getByRole("option", { name: /backup-1/ }).click();
  await page.getByRole("heading", { name: "backup-1" }).waitFor();
  await page.getByRole("button", { name: "Open SSH" }).click();
  expect(await page.evaluate(() => window.authTest.opened())).toEqual({ scopeId: "work", name: "host:backup-1" });
  expect(await page.getByRole("button", { name: "Lock everything" }).isVisible()).toBe(true);
  await page.keyboard.press("Escape");
  await pill.waitFor();
  expect(await page.evaluate(() => document.activeElement?.textContent)).toContain("2 active grants");
  await pill.click();
  await page.getByRole("button", { name: "Lock everything" }).click();
  await pill.waitFor({ state: "detached" });
  await page.getByRole("button", { name: "Unlock", exact: true }).waitFor();
}));

test("a single grant reads as one active grant", () => withPage(async (page) => {
  await page.evaluate(() => window.authTest.grants(1));
  await page.getByRole("button", { name: "1 active grant", exact: true }).waitFor();
}));

test("the grants overview shows listing errors", () => withPage(async (page) => {
  await page.evaluate(() => window.authTest.grants(1, true));
  await page.getByRole("button", { name: "1 active grant", exact: true }).click();
  const alert = page.getByRole("alert");
  await alert.waitFor();
  expect(await alert.isVisible()).toBe(true);
}));
