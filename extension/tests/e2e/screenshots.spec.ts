// Screenshots of every popup state in light and dark, for review and the store
// listing: SCREENSHOTS=1 npx playwright test screenshots. Written to
// .e2e/screenshots/, plus one contact sheet (popup-states.png).

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { type Page, expect, test } from "@playwright/test";

import {
  type Browser,
  type Stack,
  configure,
  launch,
  openPopup,
  seedVault,
  startStack,
  unlockInPopup,
  unlocked,
} from "./harness";
import { E2E_DIR } from "./paths";

test.skip(!process.env.SCREENSHOTS, "set SCREENSHOTS=1 to write screenshots");
test.describe.configure({ mode: "serial" });

const OUT = join(E2E_DIR, "screenshots");
const shots: { state: string; scheme: string; file: string }[] = [];
let stack: Stack;
let browser: Browser;

test.beforeAll(async () => {
  mkdirSync(OUT, { recursive: true });
  stack = await startStack();
  await seedVault(stack);
  browser = await launch(stack);
});

test.afterAll(async () => {
  await browser?.close();
  await stack?.stop();
});

const SCHEMES = ["dark", "light"] as const;

const capture = async (popup: Page, state: string, scheme: string) => {
  await popup.emulateMedia({ colorScheme: scheme as "dark" | "light" });
  await popup.evaluate(() => document.fonts.ready);
  await popup.waitForTimeout(150);
  const file = join(OUT, `${state}-${scheme}.png`);
  await popup.locator("body").screenshot({ path: file, animations: "disabled" });
  shots.push({ state, scheme, file });
};

const site = async (url: string) => {
  const page = await browser.context.newPage();
  await page.goto(url);
  return page;
};

const each = (state: string, open: () => Promise<Page>, ready?: (popup: Page) => Promise<void>) =>
  test(state, async () => {
    for (const scheme of SCHEMES) {
      const popup = await open();
      await popup.emulateMedia({ colorScheme: scheme });
      if (ready) await ready(popup);
      await capture(popup, state, scheme);
      await popup.close();
    }
  });

each(
  "1-not-connected",
  () => openPopup(browser, null),
  async (popup) => {
    await expect(popup.getByText("Set up CipherMoth")).toBeVisible();
  }
);

test("2-locked", async () => {
  await configure(browser);
  for (const scheme of SCHEMES) {
    const popup = await openPopup(browser, null);
    await expect(popup.getByPlaceholder("Master password")).toBeVisible();
    await popup.getByPlaceholder("Master password").fill("hunter2-hunter2");
    await capture(popup, "2-locked", scheme);
    await popup.getByPlaceholder("Master password").fill("Not-The-Password-1");
    await popup.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(popup.getByRole("alert")).toBeVisible();
    await capture(popup, "3-wrong-password", scheme);
    await popup.close();
  }
});

test("unlocked states", async () => {
  await unlocked(browser, stack);
  const github = await site("https://github.test/login.html");
  const gitlab = await site("https://gitlab.test/login.html");
  const intranet = await site("http://intranet.test/login.html");
  const empty = await site("https://github.test/nofields.html");
  for (const scheme of SCHEMES) {
    let popup = await openPopup(browser, github);
    await expect(popup.getByRole("option")).toHaveCount(2);
    await capture(popup, "4-matches", scheme);
    await popup.getByRole("button", { name: "Copy 2FA code for GitHub", exact: true }).click();
    await expect(popup.getByRole("status")).toBeVisible();
    await capture(popup, "5-copied-2fa", scheme);
    await popup.close();

    popup = await openPopup(browser, gitlab);
    await expect(popup.getByText("No logins saved for this site")).toBeVisible();
    await capture(popup, "6-no-matches", scheme);
    await popup.getByPlaceholder("Search logins").fill("git");
    await expect(popup.getByRole("option").first()).toBeVisible();
    await capture(popup, "7-search", scheme);
    await popup.getByRole("option").first().click();
    await expect(popup.getByRole("alertdialog")).toBeVisible();
    await capture(popup, "8-confirm-other-site", scheme);
    await popup.close();

    popup = await openPopup(browser, intranet);
    await popup.getByRole("option").first().click();
    await expect(popup.getByRole("alertdialog")).toBeVisible();
    await capture(popup, "9-http-warning", scheme);
    await popup.close();

    popup = await openPopup(browser, empty);
    await popup.getByRole("option").first().click();
    await expect(popup.getByRole("alertdialog")).toBeVisible();
    await capture(popup, "10-no-fields", scheme);
    await popup.close();
  }
});

test("server problems", async () => {
  for (const scheme of SCHEMES) {
    await browser.worker.evaluate(() => chrome.storage.session.clear());
    await configure(browser, "https://old.test");
    let popup = await openPopup(browser, null);
    await unlockInPopup(popup);
    await expect(popup.getByText("CipherMoth needs an update")).toBeVisible();
    await capture(popup, "11-server-too-old", scheme);
    await popup.close();

    await configure(browser, "https://badtls.test");
    await browser.worker.evaluate(() =>
      chrome.storage.session.set({
        session: { token: "A".repeat(43), idleTimeoutMs: 120_000, expiresAt: Date.now() + 120_000 },
      })
    );
    popup = await openPopup(browser, null);
    await expect(popup.getByText("Can't reach CipherMoth")).toBeVisible();
    await capture(popup, "12-offline", scheme);
    await popup.close();
  }
  await configure(browser);
});

test("options page", async () => {
  await unlocked(browser, stack);
  for (const scheme of SCHEMES) {
    const options = await site(`chrome-extension://${browser.extensionId}/options.html`);
    await options.setViewportSize({ width: 760, height: 1100 });
    await options.emulateMedia({ colorScheme: scheme });
    await expect(options.getByText("Unlocked", { exact: true })).toBeVisible();
    await options.evaluate(() => document.fonts.ready);
    await options.screenshot({ path: join(OUT, `options-${scheme}.png`), fullPage: true });
    await options.close();
  }
});

test("contact sheet", async () => {
  const states = [...new Set(shots.map((s) => s.state))];
  const cell = (state: string, scheme: string) => {
    const shot = shots.find((s) => s.state === state && s.scheme === scheme);
    if (!shot) return "<td></td>";
    const data = readFileSync(shot.file).toString("base64");
    return `<td><img src="data:image/png;base64,${data}"></td>`;
  };
  const rows = states
    .map(
      (state) =>
        `<tr><th>${state.replace(/^\d+-/, "").replace(/-/g, " ")}</th>${cell(state, "dark")}${cell(
          state,
          "light"
        )}</tr>`
    )
    .join("");
  const html = `<!doctype html><style>
    body{margin:0;padding:24px;background:#d9d9d6;font:600 15px system-ui}
    table{border-spacing:20px 16px} th{text-align:right;vertical-align:top;padding-top:8px;width:150px;color:#333}
    td{vertical-align:top} img{display:block;width:360px;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.25)}
    thead th{text-align:center}
  </style><table><thead><tr><th></th><th>dark</th><th>light</th></tr></thead>${rows}</table>`;
  writeFileSync(join(OUT, "popup-states.html"), html);
  const page = await browser.context.newPage();
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.goto(`file://${join(OUT, "popup-states.html")}`);
  await page.screenshot({ path: join(OUT, "popup-states.png"), fullPage: true });
});
