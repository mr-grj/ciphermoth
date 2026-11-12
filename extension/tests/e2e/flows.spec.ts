// The user's paths (design section 8.2): onboarding, unlock and the handoff
// unlock through the real web app, fill (popup and shortcut), copy, 2FA,
// multi-step logins, no fields, mismatch and HTTP prompts, lock, idle expiry,
// browser restart, disconnect from the vault's Settings, and a canary scan of
// the browser profile afterwards.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { type Page, expect, test } from "@playwright/test";

import {
  type Browser,
  type Stack,
  GITHUB_PASSWORD,
  INTRANET_PASSWORD,
  MASTER_PASSWORD,
  NOTE_BODY,
  TOTP_SECRET,
  WORK_PASSWORD,
  api,
  fieldValues,
  fillCommand,
  launch,
  openPopup,
  seedVault,
  sessionToken,
  startStack,
  unlockInPopup,
  unlocked,
} from "./harness";

let stack: Stack;
let browser: Browser;
let webToken: string;
const seenTokens = new Set<string>();

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  stack = await startStack();
  webToken = await seedVault(stack);
  browser = await launch(stack);
});

test.afterAll(async () => {
  await browser?.close();
  await stack?.stop();
});

test.afterEach(async () => {
  const token = await sessionToken(browser).catch(() => null);
  if (token) seenTokens.add(token);
  for (const page of browser.context.pages().slice(1)) await page.close();
});

const site = async (url: string): Promise<Page> => {
  const page = await browser.context.newPage();
  await page.goto(url);
  return page;
};

const row = (popup: Page, name: string) =>
  popup.getByRole("option", { name: new RegExp(`^${name.replace(/[()]/g, "\\$&")}`) }).first();

test("onboarding: connect to the vault from the options page", async () => {
  const popup = await openPopup(browser, null);
  await expect(
    popup.getByRole("heading", { name: /Fill logins from your CipherMoth/ })
  ).toBeVisible();
  await popup.close();

  const options = await site(`chrome-extension://${browser.extensionId}/options.html`);
  await options.getByLabel("Vault address").fill("vault.test");
  await options.getByRole("button", { name: "Connect" }).click();
  await expect(options.getByRole("status")).toContainText("Connected");
  await expect(options.getByText("Locked", { exact: true })).toBeVisible();
  const stored = await browser.worker.evaluate(() => chrome.storage.local.get(null));
  expect(stored).toEqual({
    config: {
      mode: "server",
      vault: "https://vault.test",
      api: "https://vault.test/api",
      subdomains: false,
      strictClipboard: false,
    },
  });
});

test("unlock with the master password, and a wrong one is refused", async () => {
  const popup = await openPopup(browser, null);
  await unlockInPopup(popup, "Not-The-Password-1");
  await expect(popup.getByRole("alert")).toContainText("Wrong master password");
  expect(await sessionToken(browser)).toBeNull();
  await unlockInPopup(popup);
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible();
  // The list view focuses its search box in an effect, just after it shows.
  await expect(popup.getByPlaceholder("Search logins")).toBeFocused();
  expect(await sessionToken(browser)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const sessions = await api(stack, "/extension/sessions", { method: "GET", token: webToken });
  expect(sessions.body).toEqual([expect.objectContaining({ browser: "Chromium" })]);
});

test("fill: React-style events, no submit, popup reports nothing to the page", async () => {
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByRole("option")).toHaveCount(2);
  await expect(row(popup, "GitHub")).toHaveAttribute("aria-selected", "true");
  await popup.keyboard.press("Enter");
  await expect
    .poll(() => fieldValues(page))
    .toEqual([
      { id: "user", value: "moth@example.com" },
      { id: "pass", value: GITHUB_PASSWORD },
    ]);
  expect(await page.evaluate(() => (window as never as { __events: string[][] }).__events)).toEqual(
    [
      ["input", "user"],
      ["change", "user"],
      ["input", "pass"],
      ["change", "pass"],
    ]
  );
  expect(await page.evaluate(() => (window as never as { __submitted: boolean }).__submitted)).toBe(
    false
  );
  const badge = await browser.worker.evaluate(() => chrome.action.getBadgeText({}));
  void badge;
});

test("keyboard: arrows choose, and the second login fills", async () => {
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByRole("option")).toHaveCount(2);
  await popup.keyboard.press("ArrowDown");
  await expect(row(popup, "GitHub (work)")).toHaveAttribute("aria-selected", "true");
  await popup.keyboard.press("Enter");
  await expect.poll(() => page.inputValue("#pass")).toBe(WORK_PASSWORD);
});

test("a late search answer never replaces what the box shows now", async () => {
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByRole("option")).toHaveCount(2);
  stack.delays.set("/api/extension/search", 1500);
  const seen = stack.requests.length;
  const search = popup.getByPlaceholder("Search logins");
  await search.fill("intranet");
  await expect
    .poll(() => stack.requests.slice(seen).some((r) => r.path === "/api/extension/search"))
    .toBe(true);
  await search.fill("");
  await popup.waitForTimeout(2000);
  await expect(popup.getByRole("option")).toHaveCount(2);
  await expect(row(popup, "Intranet")).toHaveCount(0);
});

test("open shadow roots are filled", async () => {
  const page = await site("https://github.test/shadow.html");
  const popup = await openPopup(browser, page);
  await row(popup, "GitHub").click();
  await expect
    .poll(() =>
      page.evaluate(() => (window as never as { shadowValues: () => unknown }).shadowValues())
    )
    .toEqual([
      { id: "user", value: "moth@example.com" },
      { id: "pass", value: GITHUB_PASSWORD },
    ]);
});

test("the fill shortcut fills one match directly and opens the list for several", async () => {
  const single = await site("https://multi.test/login.html");
  expect(await fillCommand(browser, single)).toBe("filled");
  await expect.poll(() => single.inputValue("#pass")).toBe("multi-canary-9");
  const several = await site("https://github.test/login.html");
  expect(await fillCommand(browser, several)).toBe("choose");
  expect(await several.inputValue("#pass")).toBe("");
});

test("copy username and password, and a live 2FA code", async () => {
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText());
  await popup.getByRole("button", { name: "Copy username for GitHub", exact: true }).click();
  await expect(popup.getByRole("status")).toContainText("Username copied. Clears in 3 s.");
  await expect.poll(clipboard).toBe("moth@example.com");
  await popup
    .getByRole("button", { name: "Copy password for GitHub", exact: true })
    .first()
    .click();
  await expect.poll(clipboard).toBe(GITHUB_PASSWORD);
  await popup.getByRole("button", { name: "Copy 2FA code for GitHub", exact: true }).click();
  await expect(popup.getByRole("status")).toContainText("2FA code copied");
  await expect.poll(clipboard).toMatch(/^\d{6}$/);
  const code = await clipboard();
  expect(code).toMatch(/^\d{6}$/);
  await expect(popup.getByLabel(new RegExp(`2FA code ${code}`))).toBeVisible();
  expect(await popup.content()).not.toContain(TOTP_SECRET);
  // Ctrl/Cmd+C copies the selected row's password.
  await popup.getByPlaceholder("Search logins").focus();
  await popup.keyboard.press(process.platform === "darwin" ? "Meta+c" : "Control+c");
  await expect.poll(clipboard).toBe(GITHUB_PASSWORD);
});

test("multi-step login: username first, then password", async () => {
  const first = await site("https://multi.test/step1.html");
  let popup = await openPopup(browser, first);
  await row(popup, "Multi").click();
  await expect(popup.getByRole("status")).toContainText(
    "Username filled. Fill again on the next step."
  );
  expect(await first.inputValue("#identifier")).toBe("moth");
  await popup.close();
  const second = await site("https://multi.test/step2.html");
  popup = await openPopup(browser, second);
  await row(popup, "Multi").click();
  await expect.poll(() => second.inputValue("#password")).toBe("multi-canary-9");
});

test("no login fields: say so and offer to copy", async () => {
  const page = await site("https://github.test/nofields.html");
  const popup = await openPopup(browser, page);
  await row(popup, "GitHub").click();
  await expect(popup.getByRole("alertdialog")).toContainText("No login fields found on this page.");
  await popup.getByRole("alertdialog").getByRole("button", { name: "Copy password" }).click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe(GITHUB_PASSWORD);
});

test("a login for another site asks first", async () => {
  const page = await site("https://gitlab.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByText("No logins saved for this site")).toBeVisible();
  await popup.getByPlaceholder("Search logins").fill("github");
  await expect(row(popup, "GitHub")).toBeVisible();
  await expect(popup.getByRole("option", { name: /Notes for GitHub/ })).toHaveCount(0);
  await row(popup, "GitHub").click();
  await expect(popup.getByRole("alertdialog")).toContainText(
    "This login is saved for github.test. Fill it on gitlab.test?"
  );
  expect(await page.inputValue("#pass")).toBe("");
  await popup.getByRole("button", { name: "Fill anyway" }).click();
  await expect.poll(() => page.inputValue("#pass")).toBe(GITHUB_PASSWORD);
});

test("an HTTP page warns and offers copy first", async () => {
  const page = await site("http://intranet.test/login.html");
  const popup = await openPopup(browser, page);
  await expect(popup.getByText("not secure")).toBeVisible();
  await row(popup, "Intranet").click();
  await expect(popup.getByRole("alertdialog")).toContainText(
    "This page isn't secure (HTTP). Copy instead?"
  );
  expect(await page.inputValue("#pass")).toBe("");
  await popup.getByRole("button", { name: "Fill anyway" }).click();
  await expect.poll(() => page.inputValue("#pass")).toBe(INTRANET_PASSWORD);
});

test("lock ends the session on the server too", async () => {
  const token = (await sessionToken(browser))!;
  const popup = await openPopup(browser, null);
  await popup.getByRole("button", { name: "Lock" }).click();
  await expect(popup.getByPlaceholder("Master password")).toBeVisible();
  expect(await sessionToken(browser)).toBeNull();
  expect((await api(stack, "/extension/session", { token })).status).toBe(401);
});

test("unlock in CipherMoth: the handoff through the real web app", async () => {
  const popup = await openPopup(browser, null);
  await popup.getByRole("button", { name: /Unlock in CipherMoth/ }).click();
  const vault = await browser.context.waitForEvent("page", (p) =>
    p.url().startsWith("https://vault.test/")
  );
  await vault.waitForLoadState("domcontentloaded");
  await expect(vault.getByText("Unlock to connect Chromium.")).toBeVisible();
  expect(vault.url()).not.toContain("request=");
  await vault.getByLabel("Master Password").fill(MASTER_PASSWORD);
  await vault.getByRole("button", { name: "Unlock Vault" }).click();
  const dialog = vault.getByRole("dialog", { name: /Connect Chromium to this vault/ });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("It cannot see notes, history or attachments");
  await dialog.getByRole("button", { name: "Connect" }).click();
  await expect(vault.getByRole("dialog", { name: "Connected" })).toBeVisible();
  await expect.poll(() => sessionToken(browser)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  await expect.poll(() => vault.isClosed(), { timeout: 5_000 }).toBe(true);
  const after = await openPopup(browser, null);
  await expect(after.getByPlaceholder("Search logins")).toBeVisible();
});

test("the web vault exposes its headings, favorite header and keyboard 2FA copy", async () => {
  const session = await api(stack, "/master_password/unlock", {
    body: { master_password: MASTER_PASSWORD },
  });
  expect(session.status).toBe(200);
  const vault = await browser.context.newPage();
  await vault.addInitScript((token) => {
    sessionStorage.setItem("ciphermothSession", token);
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: async (value: string) => {
          (window as unknown as { copied: string }).copied = value;
        },
      },
    });
  }, session.body.session_token);
  await vault.setViewportSize({ width: 1440, height: 1000 });
  await vault.goto("https://vault.test/passwords");
  await expect(vault.getByRole("heading", { name: "The Vault", level: 2 })).toBeVisible();
  await expect(vault.getByRole("columnheader", { name: "Favorite" })).toHaveCount(1);
  await expect(
    vault.getByRole("progressbar", { name: "2FA code time remaining" }).first()
  ).toBeVisible();
  const copy = vault.getByRole("button", { name: /^Copy 2FA code \d{3} \d{3}$/ }).first();
  await copy.focus();
  await expect(copy).toBeFocused();
  await copy.press("Enter");
  await expect
    .poll(() => vault.evaluate(() => (window as unknown as { copied?: string }).copied))
    .toMatch(/^\d{6}$/);
  await vault.close();
});

test("the web generator and optional fields expose keyboard controls and state", async () => {
  const session = await api(stack, "/master_password/unlock", {
    body: { master_password: MASTER_PASSWORD },
  });
  expect(session.status).toBe(200);
  const vault = await browser.context.newPage();
  await vault.addInitScript((token) => {
    sessionStorage.setItem("ciphermothSession", token);
  }, session.body.session_token);
  await vault.goto("https://vault.test/passwords");
  await vault.getByRole("button", { name: "Add", exact: true }).click();
  const dialog = vault.getByRole("dialog");
  await dialog.getByRole("button", { name: "Generate password", exact: true }).click();
  const length = dialog.getByRole("slider", { name: "Length", exact: true });
  await expect(length).toHaveValue("16");
  await length.focus();
  await length.press("ArrowRight");
  await expect(length).toHaveValue("17");
  await expect(dialog.getByLabel(/^Password/)).toHaveValue(/^.{17}$/);

  const uppercase = dialog.getByRole("button", { name: "A–Z", exact: true });
  await expect(uppercase).toHaveAttribute("aria-pressed", "true");
  await uppercase.focus();
  await uppercase.press("Enter");
  await expect(uppercase).toHaveAttribute("aria-pressed", "false");

  const tags = dialog.getByRole("button", { name: "Tags", exact: true });
  await expect(tags).toHaveAttribute("aria-expanded", "false");
  await tags.focus();
  await tags.press("Enter");
  await expect(tags).toHaveAttribute("aria-expanded", "true");
  await expect(dialog.getByLabel("Tags", { exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).toBeHidden();
  await vault.getByRole("button", { name: "Health", exact: true }).click();
  const health = vault.getByRole("dialog", { name: "Vault Health", exact: true });
  const score = health.getByRole("meter", { name: "Vault Health", exact: true });
  await expect(score).toHaveAttribute("aria-valuemin", "0");
  await expect(score).toHaveAttribute("aria-valuemax", "100");
  await expect(score).toHaveAttribute("aria-valuenow", /^(?:\d{1,2}|100)$/);
  await expect(health.getByRole("progressbar")).toHaveCount(0);
  await expect(health.getByRole("heading", { level: 4 })).toHaveCount(0);
  await vault.close();
});

test("the update notice keeps its visible name and respects the update opt-out", async () => {
  const session = await api(stack, "/master_password/unlock", {
    body: { master_password: MASTER_PASSWORD },
  });
  expect(session.status).toBe(200);
  const settings = await api(stack, "/settings", {
    method: "GET",
    token: session.body.session_token,
  });
  expect(settings.status).toBe(200);
  expect(
    (
      await api(stack, "/settings", {
        method: "PATCH",
        token: session.body.session_token,
        body: { ...settings.body, update_check_enabled: false },
      })
    ).status
  ).toBe(200);
  const vault = await browser.context.newPage();
  await vault.addInitScript((token) => {
    sessionStorage.setItem("ciphermothSession", token);
  }, session.body.session_token);
  let checks = 0;
  await vault.route("https://api.github.com/**", async (route) => {
    checks += 1;
    expect(route.request().headers()["x-ciphermoth-session"]).toBeUndefined();
    await route.fulfill({
      json: {
        tag_name: "v99.0.0",
        html_url: "https://github.com/mr-grj/ciphermoth/releases/tag/v99.0.0",
      },
    });
  });
  await vault.goto("https://vault.test/passwords");
  await vault.getByRole("button", { name: "Settings", exact: true }).click();
  await vault.getByRole("switch", { name: /Check for updates/ }).check();
  await vault.getByRole("button", { name: "Save", exact: true }).click();
  await expect(vault.getByRole("dialog")).toBeHidden();
  const update = vault.getByRole("button", { name: "Update", exact: true });
  await expect(update).toBeVisible();
  await update.focus();
  await update.press("Enter");
  const notice = vault.getByRole("dialog", { name: "A new moult is ready", exact: true });
  await expect(notice.getByText("v99.0.0", { exact: true })).toBeVisible();
  await expect(notice.getByRole("link")).toHaveAttribute("rel", "noopener noreferrer");
  await notice.getByRole("button", { name: "Close", exact: true }).click();

  await vault.getByRole("button", { name: "Settings", exact: true }).click();
  await vault.getByRole("switch", { name: /Check for updates/ }).uncheck();
  await vault.getByRole("button", { name: "Save", exact: true }).click();
  await expect(vault.getByRole("dialog")).toBeHidden();
  const before = checks;
  await vault.reload();
  await expect(vault.getByRole("gridcell", { name: "GitHub", exact: true })).toBeVisible();
  await vault.waitForTimeout(1000);
  expect(checks).toBe(before);
  await expect(vault.getByRole("button", { name: "Update", exact: true })).toHaveCount(0);
  await vault.close();
});

test("disconnect from the vault's Settings locks the extension", async () => {
  const web = await site("https://vault.test/login");
  await web.getByLabel("Master Password").fill(MASTER_PASSWORD);
  await web.getByRole("button", { name: "Unlock Vault" }).click();
  await web.getByRole("button", { name: "Settings" }).click();
  await web.getByRole("tab", { name: "Browser extension" }).click();
  const list = web.getByRole("list", { name: "Connected browsers" });
  await expect(list.getByText("Chromium")).toBeVisible();
  await web.getByRole("button", { name: "Disconnect Chromium" }).click();
  await expect(web.getByText("No browser is connected right now")).toBeVisible();
  const popup = await openPopup(browser, null);
  await expect(popup.getByPlaceholder("Master password")).toBeVisible();
  expect(await sessionToken(browser)).toBeNull();
});

test("idle expiry follows the vault's inactivity setting", async () => {
  await api(stack, "/settings", {
    method: "PATCH",
    token: webToken,
    body: {
      inactivity_ms: 30_000,
      warn_before_ms: 5_000,
      hidden_ms: 120_000,
      debounce_ms: 500,
      clipboard_clear_ms: 15_000,
      update_check_enabled: false,
    },
  });
  await unlocked(browser, stack);
  const options = await site(`chrome-extension://${browser.extensionId}/options.html`);
  await expect(options.getByText("Locks after 30 s of inactivity")).toBeVisible();
  await options.close();
  await new Promise((resolve) => setTimeout(resolve, 36_000));
  const popup = await openPopup(browser, null);
  await expect(popup.getByPlaceholder("Master password")).toBeVisible();
});

test("a browser restart forgets the session but keeps the connection", async () => {
  await unlocked(browser, stack);
  const token = (await sessionToken(browser))!;
  seenTokens.add(token);
  const profile = browser.profile;
  await browser.close();
  browser = await launch(stack, { profile });
  const popup = await openPopup(browser, null);
  await expect(popup.getByPlaceholder("Master password")).toBeVisible();
  expect(await sessionToken(browser)).toBeNull();
  expect(await browser.worker.evaluate(() => chrome.storage.local.get(null))).toEqual({
    config: expect.objectContaining({ vault: "https://vault.test" }),
    installId: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
  });
  // Unlocking again replaces the session this browser lost on restart: the
  // vault lists one Chromium, never a stale duplicate.
  await unlockInPopup(popup);
  await expect(popup.getByPlaceholder("Search logins")).toBeVisible();
  const web = await api(stack, "/master_password/unlock", {
    body: { master_password: MASTER_PASSWORD },
  });
  const listed = await api(stack, "/extension/sessions", {
    method: "GET",
    token: web.body.session_token,
  });
  expect(listed.body).toHaveLength(1);
  expect((await api(stack, "/extension/session", { token })).status).toBe(401);
});

test("storage canaries: no secret is left in the browser profile", async () => {
  // A last full use, then close the browser so everything is flushed to disk.
  await unlocked(browser, stack);
  const page = await site("https://github.test/login.html");
  const popup = await openPopup(browser, page);
  await row(popup, "GitHub").click();
  await expect.poll(() => page.inputValue("#pass")).toBe(GITHUB_PASSWORD);
  await popup.getByRole("button", { name: "Copy 2FA code for GitHub", exact: true }).click();
  seenTokens.add((await sessionToken(browser))!);
  const profile = browser.profile;
  await browser.close();

  const canaries = [
    MASTER_PASSWORD,
    GITHUB_PASSWORD,
    WORK_PASSWORD,
    INTRANET_PASSWORD,
    TOTP_SECRET,
    NOTE_BODY,
    "Notes for GitHub",
    "GitHub (work)",
    ...seenTokens,
  ];
  const files = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      try {
        return statSync(path).isDirectory() ? files(path) : [path];
      } catch {
        return [];
      }
    });
  const hits: string[] = [];
  for (const file of files(profile)) {
    let data: Buffer;
    try {
      data = readFileSync(file);
    } catch {
      continue;
    }
    for (const canary of canaries) {
      for (const encoded of [Buffer.from(canary, "utf8"), Buffer.from(canary, "utf16le")]) {
        if (data.includes(encoded))
          hits.push(`${canary.slice(0, 12)}… in ${file.slice(profile.length)}`);
      }
    }
  }
  expect(hits).toEqual([]);
  browser = await launch(stack, { profile });
});
