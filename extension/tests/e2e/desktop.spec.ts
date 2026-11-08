// Desktop mode end to end (design 8.4 and 10.2): the real native host and the
// app's real link server (a stand-in app on the live test backend), driven
// through the popup and the options page. Pairing with matching codes, a
// refused pairing, filling, the app locked ("Unlock CipherMoth"), not running
// ("Open CipherMoth"), turned off (no host), unpaired in the app, switching
// back to a server, and no token or key bytes in the profile.

import { readFileSync, readdirSync, statSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import { type Page, expect, test } from "@playwright/test";

import { AppStub, installHost, newQaRoot, uninstallHost } from "./desktop";
import {
  type Browser,
  type Stack,
  GITHUB_PASSWORD,
  fieldValues,
  fillCommand,
  launch,
  openPopup,
  seedVault,
  startStack,
} from "./harness";

let stack: Stack;
let browser: Browser;
let app: AppStub | null = null;
let qaRoot: string;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  stack = await startStack();
  await seedVault(stack);
  qaRoot = newQaRoot();
  browser = await launch(stack, { env: { CIPHERMOTH_QA_ROOT: qaRoot }, before: installHost });
  app = await AppStub.start(qaRoot, stack);
});

test.afterAll(async () => {
  await app?.stop();
  await browser?.close();
  await stack?.stop();
});

test.afterEach(async () => {
  for (const page of browser.context.pages().slice(1)) await page.close();
});

const site = async (url: string): Promise<Page> => {
  const page = await browser.context.newPage();
  await page.goto(url);
  return page;
};

const options = () => site(`chrome-extension://${browser.extensionId}/options.html`);

const code = async (popup: Page): Promise<string> => {
  const shown = popup.locator(".pairing-code");
  await expect(shown).toHaveText(/^\d{3} \d{3}$/);
  return ((await shown.textContent()) ?? "").replace(" ", "");
};

test("choosing the app on this computer, then pairing with the same code on both sides", async () => {
  const page = await options();
  await page.getByRole("radio", { name: /CipherMoth app on this computer/ }).check();
  await expect(page.getByRole("button", { name: "Pair" })).toBeVisible();
  const stored = await browser.worker.evaluate(() => chrome.storage.local.get("config"));
  expect(stored.config).toEqual({
    mode: "desktop",
    vault: "",
    api: "",
    subdomains: false,
    strictClipboard: false,
  });
  await page.close();

  const popup = await openPopup(browser, null);
  await expect(popup.getByRole("heading", { name: "Pair with the CipherMoth app" })).toBeVisible();
  await popup.getByRole("button", { name: "Pair" }).click();
  const shown = await code(popup);
  const asked = (await app!.next("code ")).slice(5);
  expect(shown).toBe(asked);
  app!.send("allow");
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible();
  await popup.close();
});

test("fill from the paired app, by popup and by shortcut", async () => {
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByRole("option")).toHaveCount(2);
  await popup.keyboard.press("Enter");
  await expect
    .poll(() => fieldValues(page))
    .toEqual([
      { id: "user", value: "moth@example.com" },
      { id: "pass", value: GITHUB_PASSWORD },
    ]);
  const single = await site("https://multi.test/login.html");
  expect(await fillCommand(browser, single)).toBe("filled");
});

test("nothing secret in extension storage: no token, a key that cannot be exported", async () => {
  const state = await browser.worker.evaluate(async () => {
    const local = await chrome.storage.local.get(null);
    const session = await chrome.storage.session.get(null);
    const pairing = await new Promise<{ id: string; key: CryptoKey } | undefined>((resolve) => {
      const open = indexedDB.open("ciphermoth", 1);
      open.onsuccess = () => {
        const get = open.result.transaction("pairing").objectStore("pairing").get("desktop");
        get.onsuccess = () => resolve(get.result);
      };
    });
    return {
      local,
      session,
      extractable: pairing?.key.extractable,
      algorithm: pairing?.key.algorithm.name,
      id: pairing?.id,
    };
  });
  expect(Object.keys(state.local)).toEqual(["config"]);
  expect(state.session.session).toBeUndefined();
  expect(state.extractable).toBe(false);
  expect(state.algorithm).toBe("HKDF");
  expect(state.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
});

test("the app locked: the popup offers Unlock CipherMoth, then continues", async () => {
  app!.send("lock");
  const popup = await openPopup(browser, null);
  await expect(popup.getByRole("heading", { name: "CipherMoth is locked" })).toBeVisible();
  await popup.getByRole("button", { name: /Unlock CipherMoth/ }).click();
  await app!.next("show");
  app!.send("unlock");
  const again = await openPopup(browser, null);
  await expect(again.getByPlaceholder("Search logins")).toBeVisible();
});

test("Lock in the popup locks the app", async () => {
  const popup = await openPopup(browser, null);
  await popup.getByRole("button", { name: "Lock CipherMoth" }).click();
  await app!.next("locked");
  const again = await openPopup(browser, null);
  await expect(again.getByRole("heading", { name: "CipherMoth is locked" })).toBeVisible();
  app!.send("unlock");
  await expect(again.getByPlaceholder("Search logins")).toBeVisible();
});

test("the app not running: Open CipherMoth starts it", async () => {
  await app!.stop();
  app = null;
  const marker = join(qaRoot, "launched");
  const script = join(qaRoot, "start-app.sh");
  writeFileSync(script, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o700 });
  const link = join(qaRoot, "browser-extension");
  if (!existsSync(link)) mkdirSync(link, { recursive: true });
  writeFileSync(join(link, "launch.json"), JSON.stringify({ program: script, args: [] }));

  const popup = await openPopup(browser, null);
  await expect(popup.getByRole("heading", { name: "CipherMoth isn't running" })).toBeVisible();
  await popup.getByRole("button", { name: "Open CipherMoth" }).click();
  await expect.poll(() => existsSync(marker)).toBe(true);
  // The app comes up; the open popup notices on its own.
  app = await AppStub.start(qaRoot, stack);
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible({ timeout: 15_000 });
});

test("the switch turned off in the app: the popup says how to turn it on", async () => {
  // What turning it off does: the app stops listening (closing every
  // connection) and removes the manifests.
  await app!.stop();
  uninstallHost(browser.profile);
  const popup = await openPopup(browser, null);
  await expect(
    popup.getByRole("heading", { name: "Turn on browser extensions in CipherMoth" })
  ).toBeVisible();
  installHost(browser.profile);
  app = await AppStub.start(qaRoot, stack);
  await popup.getByRole("button", { name: "Try again" }).click();
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible();
});

test("removed in the app: the extension forgets the pairing and asks again", async () => {
  app!.send("unpair");
  const popup = await openPopup(browser, null);
  await expect(popup.getByRole("heading", { name: "Pair with the CipherMoth app" })).toBeVisible();
  const gone = await browser.worker.evaluate(
    () =>
      new Promise<boolean>((resolve) => {
        const open = indexedDB.open("ciphermoth", 1);
        open.onsuccess = () => {
          const get = open.result.transaction("pairing").objectStore("pairing").get("desktop");
          get.onsuccess = () => resolve(get.result === undefined);
        };
      })
  );
  expect(gone).toBe(true);
});

test("a refused pairing keeps nothing", async () => {
  const popup = await openPopup(browser, null);
  await popup.getByRole("button", { name: "Pair" }).click();
  await code(popup);
  await app!.next("code ");
  app!.send("deny");
  await expect(popup.getByRole("alert")).toContainText("Pairing wasn't allowed");
  await expect(popup.getByRole("button", { name: "Pair" })).toBeVisible();
  // And pairing again works.
  await popup.getByRole("button", { name: "Pair" }).click();
  expect(await code(popup)).toBe((await app!.next("code ")).slice(5));
  app!.send("allow");
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible();
});

test("switching to a server ends desktop mode but keeps the pairing", async () => {
  const page = await options();
  await page.getByRole("radio", { name: /Your CipherMoth server/ }).check();
  await page.getByLabel("Vault address").fill("vault.test");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByRole("status")).toContainText("Connected");
  const config = (await browser.worker.evaluate(() => chrome.storage.local.get("config"))) as {
    config: { mode: string };
  };
  expect(config.config.mode).toBe("server");
  await page.getByRole("radio", { name: /CipherMoth app on this computer/ }).check();
  await expect(page.getByText("Paired · CipherMoth is unlocked")).toBeVisible();
});

test("Unpair in the extension removes the browser in the app too", async () => {
  const pairings = () =>
    (
      JSON.parse(readFileSync(join(qaRoot, "browser-extension/config.json"), "utf8")) as {
        pairings: unknown[];
      }
    ).pairings.length;
  expect(pairings()).toBe(1);
  const page = await options();
  await page.getByRole("button", { name: "Unpair" }).click();
  await expect(page.getByRole("status")).toContainText("Unpaired");
  await expect.poll(pairings).toBe(0);
  // Still in desktop mode, ready to pair again.
  await expect(page.getByRole("button", { name: "Pair" })).toBeVisible();
});

// Chromium gives a running service worker no connectNative for a permission
// granted after it started; the extension then reloads itself (restart.ts),
// which closes the settings, and a one-shot marker reopens them. Playwright
// cannot answer the permission prompt, and an extension loaded with
// --load-extension does not come back from runtime.reload(), so this stops the
// worker over CDP instead: the next one starts as after a reload.
test("a worker started with the restart marker reopens the settings once", async () => {
  const own = await launch(stack);
  try {
    await own.worker.evaluate(() => chrome.storage.local.set({ reopenOptions: true }));
    const page = await own.context.newPage();
    const cdp = await own.context.newCDPSession(page);
    await cdp.send("ServiceWorker.enable");
    await cdp.send("ServiceWorker.stopAllWorkers");
    const reopened = own.context.waitForEvent("page", {
      predicate: (p) => p.url().endsWith("/options.html"),
      timeout: 15_000,
    });
    // Any extension page wakes the worker.
    await page.goto(`chrome-extension://${own.extensionId}/popup.html`);
    const settings = await reopened;
    await expect
      .poll(() => settings.evaluate(async () => Object.keys(await chrome.storage.local.get(null))))
      .not.toContain("reopenOptions");
    // Once: the next start leaves the settings closed.
    await settings.close();
    await cdp.send("ServiceWorker.stopAllWorkers");
    await page.reload();
    await page.waitForTimeout(1_500);
    expect(own.context.pages().filter((p) => p.url().endsWith("/options.html"))).toEqual([]);
  } finally {
    await own.close();
  }
});

test("the profile holds no secret from the vault or the channel", async () => {
  await browser.close();
  const canaries = [GITHUB_PASSWORD, "moth@example.com"];
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      const info = statSync(path);
      if (info.isDirectory()) walk(path);
      else if (info.size < 50_000_000) {
        const content = readFileSync(path);
        for (const canary of canaries)
          if (content.includes(canary)) hits.push(`${path}: ${canary}`);
      }
    }
  };
  walk(browser.profile);
  expect(hits).toEqual([]);
});
