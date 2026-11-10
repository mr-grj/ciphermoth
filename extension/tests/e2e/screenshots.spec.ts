// Screenshots of every popup state in light and dark, for review and the store
// listing: SCREENSHOTS=1 npx playwright test screenshots. Written to
// .e2e/screenshots/ at 2x, plus one contact sheet (popup-states.png), and the
// Chrome Web Store images to .e2e/store/ (texts: extension/store/).

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
import { E2E_DIR, TEST_BUILD } from "./paths";

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
  browser = await launch(stack, { scale: 2 });
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

// Chrome Web Store graphics: five 1280x800 screenshots (full bleed), the small
// promo tile (440x280), the marquee (1400x560) and the store icon (96 px of
// artwork in 128 px with transparent padding).
const SLIDES = [
  [
    "4-matches",
    "Fills only when you ask",
    "Click the toolbar button or press Ctrl+Shift+L (⌘+Shift+L on a Mac). Nothing appears inside web pages, nothing fills on page load.",
  ],
  [
    "8-confirm-other-site",
    "Exact-origin matching",
    "Lookalike domains, other ports and http:// copies of an https:// site never match. A login saved for another site asks first.",
  ],
  [
    "5-copied-2fa",
    "Passwords and 2FA codes",
    "Copy a password or a live 2FA code in one click. The clipboard clears itself.",
  ],
  [
    "2-locked",
    "Your vault stays yours",
    "Unlock with your master password, or hand off to CipherMoth for a security key. No CipherMoth account, no tracking.",
  ],
  [
    "7-search",
    "Your server or your desktop app",
    "Works with your self-hosted CipherMoth server, or with the CipherMoth desktop app on this computer, without any network.",
  ],
] as const;

test("store images", async () => {
  const dir = join(E2E_DIR, "store");
  mkdirSync(dir, { recursive: true });
  // setContent pages (about:blank) cannot load file: URLs.
  const font = (name: string) =>
    `data:font/woff2;base64,${readFileSync(join(TEST_BUILD, "fonts", `${name}.woff2`)).toString("base64")}`;
  const icon = `data:image/png;base64,${readFileSync(join(TEST_BUILD, "icons/icon-128.png")).toString("base64")}`;
  const png = (file: string) => `data:image/png;base64,${readFileSync(file).toString("base64")}`;
  const style = `<style>
    @font-face{font-family:G;src:url(${font("space-grotesk")})}
    @font-face{font-family:M;src:url(${font("space-mono")})}
    *{box-sizing:border-box} html,body{margin:0;background:#0b0b0c;color:#f4f4f2;font-family:G}
    .glow{color:#7dd3c0} .word{font-weight:700;letter-spacing:-.02em}
  </style>`;
  const page = await browser.context.newPage();
  const shoot = async (
    html: string,
    width: number,
    height: number,
    file: string,
    clear = false
  ) => {
    await page.setViewportSize({ width, height });
    await page.setContent(`<!doctype html>${style}${html}`);
    await page.evaluate(() => document.fonts.ready);
    // The context renders at 2x; the store wants exact pixel sizes.
    await page.screenshot({ path: join(dir, file), omitBackground: clear, scale: "css" });
  };
  for (const [index, [state, title, text]] of SLIDES.entries()) {
    const shot = shots.find((s) => s.state === state && s.scheme === "dark");
    expect(shot, state).toBeTruthy();
    await shoot(
      `<div style="display:flex;align-items:center;gap:72px;height:800px;padding:0 96px;
        background:radial-gradient(circle at 78% 50%,rgba(125,211,192,.16),transparent 55%)">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:14px;margin-bottom:40px">
            <img src="${icon}" width="44" height="44"><span class="word" style="font-size:28px">Cipher<span class="glow">Moth</span></span>
          </div>
          <h1 style="font-size:54px;line-height:1.08;margin:0 0 24px;letter-spacing:-.02em">${title}</h1>
          <p style="font-size:24px;line-height:1.45;margin:0;color:#b9bdb9">${text}</p>
        </div>
        <img src="${png(shot!.file)}" style="width:450px;border-radius:16px;
          box-shadow:0 0 0 1px rgba(125,211,192,.35),0 24px 80px rgba(0,0,0,.6)">
      </div>`,
      1280,
      800,
      `screenshot-${index + 1}-${state.replace(/^\d+-/, "")}.png`
    );
  }
  const brand = (size: number, tagline: number) => `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;
      background:radial-gradient(circle at 50% 40%,rgba(125,211,192,.22),transparent 60%)">
      <img src="${icon}" width="${size}" height="${size}">
      <div class="word" style="font-size:${size * 0.55}px;margin-top:${size * 0.18}px">Cipher<span class="glow">Moth</span></div>
      <div style="font-family:M;font-size:${tagline}px;color:#b9bdb9;margin-top:10px">Fill logins from your own vault</div>
    </div>`;
  await shoot(
    `<div style="height:280px">${brand(84, 15)}</div>`,
    440,
    280,
    "small-promo-tile-440x280.png"
  );
  await shoot(
    `<div style="height:560px">${brand(150, 26)}</div>`,
    1400,
    560,
    "marquee-1400x560.png"
  );
  await shoot(
    `<style>html,body{background:transparent}</style>
    <div style="width:128px;height:128px;display:flex;align-items:center;justify-content:center;background:transparent">
      <img src="${icon}" width="96" height="96"></div>`,
    128,
    128,
    "store-icon-128.png",
    true
  );
  await page.close();
});
