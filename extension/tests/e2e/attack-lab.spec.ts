// The attack lab (design section 8.3): hostile pages served on lookalike and
// attacker hosts. Each test takes the real user path (the popup, or the fill
// command) and asserts what the page received, with a page-side spy, and what
// left the page over the network.

import { type Page, expect, test } from "@playwright/test";

import {
  type Browser,
  type Stack,
  GITHUB_PASSWORD,
  allFrameValues,
  api,
  configure,
  fillCommand,
  launch,
  openPopup,
  seedVault,
  sessionToken,
  tabIdOf,
  startStack,
  unlocked,
} from "./harness";

let stack: Stack;
let browser: Browser;

test.beforeAll(async () => {
  stack = await startStack();
  await seedVault(stack);
  browser = await launch(stack, { otherExtension: true });
  await unlocked(browser, stack);
});

test.afterAll(async () => {
  await browser?.close();
  await stack?.stop();
});

test.afterEach(async () => {
  for (const page of browser.context.pages().slice(1)) await page.close();
});

const lab = async (name: string, host = "github.test", extra = ""): Promise<Page> => {
  const page = await browser.context.newPage();
  await page.goto(`https://${host}/lab/case.html?c=${name}${extra}`);
  return page;
};

const filled = (page: Page) => page.evaluate(() => (window as never as LabWindow).__lab.filled());
const labLog = (page: Page) => page.evaluate(() => (window as never as LabWindow).__lab.log);

interface LabWindow {
  __lab: { filled: () => string[]; log: unknown[][] };
}

const evilRequests = () =>
  stack.requests.filter((r) => r.host === "evil.test" && r.path === "/collect");

// Pick the login named `name` in the popup (the user's click).
const choose = async (popup: Page, name: string) => {
  await popup
    .getByRole("option", { name: new RegExp(`^${escape(name)}`) })
    .first()
    .click();
};
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const fillFromPopup = async (page: Page, name = "GitHub") => {
  const popup = await openPopup(browser, page);
  await expect(popup.getByRole("option").first()).toBeVisible();
  await choose(popup, name);
  return popup;
};

const promptText = (popup: Page) => popup.getByRole("alertdialog").innerText();

test.describe("1. DOM-based extension clickjacking", () => {
  const cases: [string, string[]][] = [
    ["cj-opacity-html", []],
    ["cj-opacity-body", []],
    ["cj-opacity-parent", []],
    ["cj-overlay", []],
    ["cj-clip-path", []],
    ["cj-mask", []],
    ["cj-popover", []],
    // Visible fields under a click-through veil, or next to a banner, are the
    // site's own fields on the right origin: filling them is what the user asked.
    ["cj-pointer-events", ["user", "pass"]],
    ["cj-cookie-banner", ["user", "pass"]],
  ];
  for (const [name, expected] of cases) {
    test(name, async () => {
      const page = await lab(name);
      const before = await page.evaluate(() => document.querySelectorAll("*").length);
      // The attack: the user clicks the decoy and around the page.
      for (const [x, y] of [
        [80, 160],
        [200, 220],
        [300, 500],
      ] as const) {
        await page.mouse.click(x, y);
      }
      await page.keyboard.press("Enter");
      expect(await filled(page)).toEqual([]);
      // Nothing of the extension's ever appears in a page.
      expect(await page.evaluate(() => document.querySelectorAll("*").length)).toBe(before);
      const popup = await fillFromPopup(page);
      if (expected.length) {
        await expect.poll(() => filled(page)).toEqual(expected);
      } else {
        await expect(popup.getByRole("alertdialog")).toContainText("hidden or covered");
        expect(await filled(page)).toEqual([]);
      }
      expect(await page.evaluate(() => document.querySelectorAll("*").length)).toBe(before);
    });
  }
});

test.describe("2. Hidden-field harvesting", () => {
  for (const name of [
    "hf-display-none",
    "hf-visibility-hidden",
    "hf-opacity-0",
    "hf-opacity-ancestor",
    "hf-filter-opacity",
    "hf-size-0",
    "hf-size-1",
    "hf-offscreen",
    "hf-clip",
    "hf-behind",
    "hf-aria-hidden",
    "hf-template",
  ]) {
    test(`${name} gets nothing`, async () => {
      const page = await lab(name);
      const popup = await fillFromPopup(page);
      await expect(popup.getByRole("alertdialog")).toContainText(
        /hidden or covered|No login fields/
      );
      expect(await filled(page)).toEqual([]);
    });
  }

  test("fields added after the fill get nothing", async () => {
    const page = await lab("hf-late");
    const popup = await fillFromPopup(page);
    await expect(popup.getByRole("alertdialog")).toContainText("No login fields");
    await page.waitForSelector("#pass");
    await page.waitForTimeout(500);
    expect(await filled(page)).toEqual([]);
  });

  test("only the visible pair is filled when hidden decoys exist", async () => {
    const page = await lab("hf-mixed");
    await fillFromPopup(page);
    await expect.poll(() => filled(page)).toEqual(["visible-user", "visible-pass"]);
  });
});

test.describe("3. Frames", () => {
  for (const name of ["if-attacker-child", "if-same-origin", "if-sandboxed", "if-srcdoc"]) {
    test(`${name}: no frame is ever filled`, async () => {
      const page = await lab(name);
      await page.waitForTimeout(500);
      const popup = await fillFromPopup(page);
      await expect(popup.getByRole("alertdialog")).toContainText("No login fields");
      for (const field of await allFrameValues(page)) expect(field.value).toBe("");
    });
  }

  test("an attacker page framing the victim gets nothing, even when the user insists", async () => {
    const page = await lab("if-framing-victim", "evil.test");
    await page.waitForTimeout(500);
    const popup = await openPopup(browser, page);
    await expect(popup.getByText("No logins saved for this site")).toBeVisible();
    await popup.getByPlaceholder("Search logins").fill("GitHub");
    await choose(popup, "GitHub");
    expect(await promptText(popup)).toContain("saved for github.test");
    await popup.getByRole("button", { name: "Fill anyway" }).click();
    await expect(popup.getByRole("alertdialog")).toContainText("No login fields");
    for (const field of await allFrameValues(page)) expect(field.value).toBe("");
  });
});

test.describe("4. Origin tricks", () => {
  for (const url of [
    "https://github.test.evil.test/login.html",
    "https://evil.test/github.test/login.html",
    "https://github.test@evil.test/login.html",
    "https://xn--githb-n2a.test/login.html",
    "http://github.test/login.html",
    "https://github.test:8443/login.html",
    "https://evil.github.io/login.html",
  ]) {
    test(`no match on ${url}`, async () => {
      const page = await browser.context.newPage();
      await page.goto(url);
      const popup = await openPopup(browser, page);
      await expect(popup.getByText("No logins saved for this site")).toBeVisible();
      expect(await page.evaluate(() => document.querySelector("#pass")?.getAttribute("id"))).toBe(
        "pass"
      );
      expect(await allFrameValues(page)).toEqual(
        expect.arrayContaining([expect.objectContaining({ value: "" })])
      );
    });
  }

  test("a private public suffix stays closed with subdomain matching on", async () => {
    await browser.worker.evaluate(async () => {
      const { config } = (await chrome.storage.local.get("config")) as { config: object };
      await chrome.storage.local.set({ config: { ...config, subdomains: true } });
    });
    try {
      for (const [host, expected] of [
        ["evil.github.io", 0],
        ["docs.moth.github.io", 1],
      ] as const) {
        const page = await browser.context.newPage();
        await page.goto(`https://${host}/login.html`);
        const popup = await openPopup(browser, page);
        if (expected) await expect(popup.getByRole("option")).toHaveCount(1);
        else await expect(popup.getByText("No logins saved for this site")).toBeVisible();
      }
    } finally {
      await configure(browser);
    }
  });

  for (const [label, open] of [
    [
      "data:",
      (page: Page) => page.goto("data:text/html,<input id=user><input type=password id=pass>"),
    ],
    ["about:blank opened by an allowed page", async (page: Page) => page.goto("about:blank")],
    [
      "blob:",
      async (page: Page) => {
        await page.goto("https://github.test/login.html");
        const url = await page.evaluate(() =>
          URL.createObjectURL(
            new Blob(['<input id="user"><input id="pass" type="password">'], { type: "text/html" })
          )
        );
        await page.goto(url);
      },
    ],
  ] as const) {
    test(`no page to fill on ${label}`, async () => {
      const page = await browser.context.newPage();
      await page.goto("https://github.test/nofields.html");
      const tabId = await tabIdOf(browser, page);
      await open(page);
      const popup = await openPopup(browser, tabId);
      await expect(popup.getByText("No web page in this tab")).toBeVisible();
      await popup.getByPlaceholder("Search logins").fill("GitHub");
      await choose(popup, "GitHub");
      await expect(popup.getByRole("status")).toContainText("no web page");
      for (const field of await allFrameValues(page)) expect(field.value).toBe("");
    });
  }

  test("a page that navigates away between opening the popup and filling gets nothing", async () => {
    const page = await browser.context.newPage();
    await page.goto("https://github.test/login.html");
    const popup = await openPopup(browser, page);
    await expect(popup.getByRole("option").first()).toBeVisible();
    await page.evaluate(() => (location.href = "https://evil.test/login.html"));
    await page.waitForURL("https://evil.test/login.html");
    await choose(popup, "GitHub");
    await expect(popup.getByRole("alertdialog")).toContainText("page changed");
    expect(await allFrameValues(page)).toEqual([
      expect.objectContaining({ id: "user", value: "" }),
      expect.objectContaining({ id: "pass", value: "" }),
    ]);
  });

  test("history.pushState on the same origin still fills only that origin", async () => {
    const page = await browser.context.newPage();
    await page.goto("https://github.test/login.html");
    const popup = await openPopup(browser, page);
    await expect(popup.getByRole("option").first()).toBeVisible();
    await page.evaluate(() => history.pushState({}, "", "/somewhere/else"));
    await choose(popup, "GitHub");
    await expect.poll(() => page.inputValue("#pass")).toBe(GITHUB_PASSWORD);
  });

  test("a page restored from the back-forward cache is filled for its own origin", async () => {
    const page = await browser.context.newPage();
    await page.goto("https://evil.test/login.html");
    await page.goto("https://github.test/login.html");
    await page.goBack();
    await page.goForward();
    await expect(page).toHaveURL("https://github.test/login.html");
    await fillFromPopup(page);
    await expect.poll(() => page.inputValue("#pass")).toBe(GITHUB_PASSWORD);
  });
});

test.describe("5. Form tricks", () => {
  test("nothing is filled before the user acts, then only the login fields", async () => {
    const page = await lab("ft-autofocus-steal");
    await page.waitForTimeout(300);
    expect(await filled(page)).toEqual([]);
    await fillFromPopup(page);
    await expect.poll(() => filled(page)).toEqual(["user", "pass"]);
  });

  test("a sign-up form (new-password) is refused", async () => {
    const page = await lab("ft-new-password");
    const popup = await fillFromPopup(page);
    await expect(popup.getByRole("alertdialog")).toContainText("sign-up or password change");
    expect(await filled(page)).toEqual([]);
  });

  test("read-only fields that unlock on focus are refused", async () => {
    const page = await lab("ft-readonly-flip");
    const popup = await fillFromPopup(page);
    await expect(popup.getByRole("alertdialog")).toBeVisible();
    expect(await filled(page)).toEqual([]);
  });

  test("type flipping, mirroring and observers see nothing before the user's fill", async () => {
    for (const name of ["ft-type-flip", "ft-mirror", "ft-mutation-exfil"]) {
      const before = evilRequests().length;
      const page = await lab(name);
      await page.waitForTimeout(500);
      expect(await filled(page)).toEqual([]);
      expect(evilRequests().slice(before)).toEqual([]);
      expect(await labLog(page)).toEqual([]);
      await page.close();
    }
    // Documented limit: once the user fills a visible field on the right
    // origin, the page owns what it got (design section 5, docs/EXTENSION.md).
    const page = await lab("ft-mirror");
    await fillFromPopup(page);
    await expect.poll(() => filled(page)).toContain("mirror");
  });
});

test.describe("6. Messaging", () => {
  test("a page cannot message the extension", async () => {
    const page = await lab("msg-runtime", "github.test", `&id=${browser.extensionId}`);
    await page.waitForTimeout(500);
    const log = await labLog(page);
    expect(log[0]).toEqual(["runtime", false]);
    expect(log.some((entry) => entry[0] === "reply" && entry[1] === "some")).toBe(false);
  });

  test("another extension cannot message, connect to or read the extension", async () => {
    const other = browser.context
      .serviceWorkers()
      .find((w) => !w.url().includes(browser.extensionId));
    expect(other).toBeTruthy();
    const results = (await other!.evaluate(
      (id) => (self as never as { attack: (id: string) => Promise<unknown> }).attack(id),
      browser.extensionId
    )) as Record<string, { error?: string; reply?: unknown; disconnected?: string }>;
    for (const type of ["status", "credential", "handoff-token"]) {
      expect(results[type]?.reply).toBeUndefined();
      expect(results[type]?.error).toMatch(/Could not establish connection|Receiving end/);
    }
    expect(results.connect?.disconnected ?? results.connect?.error).toBeTruthy();
    expect(JSON.stringify(results.storage)).not.toContain("token");
  });

  test("fake handoff tokens are ignored: no request, wrong nonce, a frame, a replay", async () => {
    const token = await sessionToken(browser);
    const fake = "f".repeat(43);
    const post = (page: Page, request: string) =>
      page.evaluate(
        ({ request, fake }) =>
          window.postMessage({ type: "ciphermoth:extension-session", request, token: fake }, "*"),
        { request, fake }
      );
    // No pending request: the bridge is not even on the page.
    const vault = await browser.context.newPage();
    await vault.goto("https://vault.test/login");
    await post(vault, "a".repeat(43));
    await vault.waitForTimeout(500);
    expect(await sessionToken(browser)).toBe(token);

    // A pending request, but the wrong nonce, a frame and a bogus token.
    const popup = await openPopup(browser, null);
    await popup.getByRole("button", { name: "Lock" }).click();
    await popup.getByRole("button", { name: /Unlock in CipherMoth/ }).click();
    const handoff = await browser.context.waitForEvent("page", (p) =>
      p.url().startsWith("https://vault.test/")
    );
    await handoff.waitForLoadState("domcontentloaded");
    const pending = await browser.worker.evaluate(async () => {
      const { handoff } = (await chrome.storage.session.get("handoff")) as {
        handoff: { request: string };
      };
      return handoff.request;
    });
    await post(handoff, "b".repeat(43));
    await handoff.evaluate(
      ({ request, fake }) => {
        const frame = document.createElement("iframe");
        frame.src = "/";
        document.body.append(frame);
        frame.addEventListener("load", () =>
          frame.contentWindow!.postMessage(
            { type: "ciphermoth:extension-session", request, token: fake },
            "*"
          )
        );
      },
      { request: pending, fake }
    );
    await handoff.waitForTimeout(800);
    expect(await sessionToken(browser)).toBeNull();
    // The right nonce with a token the server does not know: consumed, refused.
    await post(handoff, pending);
    await handoff.waitForTimeout(800);
    expect(await sessionToken(browser)).toBeNull();
    expect(
      await browser.worker.evaluate(
        async () => (await chrome.storage.session.get("handoff")).handoff
      )
    ).toBeUndefined();
    // Replaying the nonce with a real extension token: still refused.
    const login = await api(stack, "/master_password/unlock", {
      body: { master_password: "Moth-Test-Vault-2026!" },
    });
    const minted = await api(stack, "/extension/sessions", {
      body: { browser: "Chrome" },
      token: login.body.session_token,
    });
    await handoff.evaluate(
      ({ request, token }) =>
        window.postMessage({ type: "ciphermoth:extension-session", request, token }, "*"),
      { request: pending, token: minted.body.session_token }
    );
    await handoff.waitForTimeout(800);
    expect(await sessionToken(browser)).toBeNull();
    await unlocked(browser, stack);
  });
});

test.describe("7. Synthetic input", () => {
  test("page-made key presses and clicks never fill or open anything", async () => {
    const pagesBefore = browser.context.pages().length;
    const page = await lab("syn-keys");
    await page.waitForTimeout(800);
    expect(await filled(page)).toEqual([]);
    expect(browser.context.pages().length).toBe(pagesBefore + 1);
    // The real command (a browser-level shortcut) does fill: one match needed.
    const multi = await browser.context.newPage();
    await multi.goto("https://multi.test/login.html");
    expect(await fillCommand(browser, multi)).toBe("filled");
    await expect.poll(() => multi.inputValue("#pass")).toBe("multi-canary-9");
  });
});

test.describe("8. Extension pages", () => {
  test("pages can neither frame nor fetch extension resources", async () => {
    const page = await lab("ext-pages", "github.test", `&id=${browser.extensionId}`);
    await page.waitForTimeout(1500);
    const log = (await labLog(page)) as unknown[][];
    for (const file of ["manifest.json", "popup.html", "background.js", "bridge.js"]) {
      expect(log).toContainEqual(["fetch", file, "refused"]);
    }
    expect(log).not.toContainEqual(["frame-load", "readable"]);
    const frame = page.frames().find((f) => f.url().startsWith("chrome-extension://"));
    if (frame) {
      expect(
        await frame.evaluate(() => document.querySelector("#app")).catch(() => null)
      ).toBeNull();
    }
  });
});

test.describe("9. Network", () => {
  const connectVia = async (vault: string, apiAddress = "") => {
    const options = await browser.context.newPage();
    await options.goto(`chrome-extension://${browser.extensionId}/options.html`);
    await options.getByLabel("Vault address").fill(vault);
    if (apiAddress) {
      await options.getByText("API on another address?").click();
      await options.getByLabel("API address").fill(apiAddress);
    }
    await options.getByRole("button", { name: /Connect|Save/ }).click();
    return options;
  };

  test("a server that redirects never receives or forwards the token", async () => {
    await unlocked(browser, stack);
    const token = await sessionToken(browser);
    await browser.worker.evaluate(async () => {
      const { config } = (await chrome.storage.local.get("config")) as { config: object };
      await chrome.storage.local.set({ config: { ...config, api: "https://redirect.test/api" } });
    });
    const page = await browser.context.newPage();
    await page.goto("https://github.test/login.html");
    const popup = await openPopup(browser, page);
    await expect(popup.getByRole("alert").or(popup.getByRole("status"))).toBeVisible();
    const leaked = stack.requests.filter(
      (r) => r.host === "evil.test" && JSON.stringify(r.headers).includes(token ?? "-")
    );
    expect(leaked).toEqual([]);
    expect(stack.requests.some((r) => r.host === "evil.test" && r.path === "/stolen")).toBe(false);
    await configure(browser);
    await unlocked(browser, stack);
  });

  for (const [vault, message] of [
    ["https://badtls.test", /Can't reach your CipherMoth/],
    ["http://vault.test", /https:\/\//],
    ["https://huge.test", /No CipherMoth API/],
    ["https://badjson.test", /No CipherMoth API/],
    ["https://notcm.test", /No CipherMoth API/],
    ["https://old.test", /too old/],
    ["https://redirect.test", /Can't reach your CipherMoth/],
  ] as const) {
    test(`connecting to ${vault} fails closed`, async () => {
      const options = await connectVia(vault);
      await expect(options.getByRole("alert")).toContainText(message);
      const stored = await browser.worker.evaluate(async () => chrome.storage.local.get("config"));
      expect(JSON.stringify(stored)).toContain("https://vault.test");
    });
  }
});

test.describe("10. Clipboard", () => {
  const clipboard = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

  test("nothing is copied without a click, and a copy is cleared", async () => {
    const page = await browser.context.newPage();
    await page.goto("https://github.test/login.html");
    await page.evaluate(() => navigator.clipboard.writeText("before"));
    const popup = await openPopup(browser, page);
    await expect(popup.getByRole("option").first()).toBeVisible();
    expect(await clipboard(page)).toBe("before");
    await popup
      .getByRole("button", { name: "Copy password for GitHub", exact: true })
      .first()
      .click();
    await expect(popup.getByRole("status")).toContainText("Password copied");
    expect(await clipboard(page)).toBe(GITHUB_PASSWORD);
    await expect.poll(() => clipboard(page), { timeout: 15_000 }).toBe("");
  });

  test("clearing never wipes something the user copied afterwards", async () => {
    await browser.worker.evaluate(async () => {
      const { config } = (await chrome.storage.local.get("config")) as { config: object };
      await chrome.storage.local.set({ config: { ...config, strictClipboard: true } });
    });
    try {
      const page = await browser.context.newPage();
      await page.goto("https://github.test/login.html");
      const popup = await openPopup(browser, page);
      await popup
        .getByRole("button", { name: "Copy password for GitHub", exact: true })
        .first()
        .click();
      await expect(popup.getByRole("status")).toContainText("Password copied");
      await page.evaluate(() => navigator.clipboard.writeText("my own text"));
      await page.waitForTimeout(6_000);
      expect(await clipboard(page)).toBe("my own text");
    } finally {
      await configure(browser);
    }
  });
});
