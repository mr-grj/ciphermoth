import { describe, expect, it, vi } from "vitest";

import { memoryStorage } from "../test/globals";
import {
  CONNECTED_MESSAGE,
  HANDOFF_KEY,
  HANDOFF_TTL_MS,
  SESSION_MESSAGE,
  captureHandoff,
  clearHandoff,
  deliverToken,
  detectBrowser,
  installTarget,
  isConnectedIn,
  pendingHandoff,
} from "./extensionHandoff";

const NONCE = "kM3x1y8Qe0bWv7c2Z9pL4tR6sN5aH1jD0fG3uY8iO2w";
const NOW = 1_800_000_000_000;

const at = (hash) => {
  const history = { replaceState: vi.fn() };
  const location = { hash, pathname: "/", search: "" };
  const storage = memoryStorage();
  return { history, location, storage, now: NOW };
};

describe("captureHandoff", () => {
  it("keeps a valid request and drops the fragment from the address bar", () => {
    const env = at(
      `#/connect-extension?request=${NONCE}&browser=Firefox&client=AbCdEfGhIjKlMnOpQrStUv`
    );
    expect(captureHandoff(env)).toEqual({
      request: NONCE,
      browser: "Firefox",
      client: "AbCdEfGhIjKlMnOpQrStUv",
      expires: NOW + HANDOFF_TTL_MS,
    });
    expect(env.history.replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(pendingHandoff({ storage: env.storage, now: NOW + 1 })?.request).toBe(NONCE);
  });

  it.each([
    "#/connect-extension",
    "#/connect-extension?request=short&browser=Chrome",
    `#/connect-extension?request=${NONCE}!&browser=Chrome`,
    `#/connect-extension?request=${NONCE}${NONCE}`,
  ])("refuses a malformed request %s but still clears the fragment", (hash) => {
    const env = at(hash);
    expect(captureHandoff(env)).toBeNull();
    expect(env.history.replaceState).toHaveBeenCalled();
    expect(env.storage.getItem(HANDOFF_KEY)).toBeNull();
  });

  it("names an unknown browser generically", () => {
    const env = at(`#/connect-extension?request=${NONCE}&browser=<script>`);
    expect(captureHandoff(env).browser).toBe("Browser");
  });

  it("drops a malformed installation id but keeps the request", () => {
    const env = at(`#/connect-extension?request=${NONCE}&browser=Chrome&client=short!`);
    expect(captureHandoff(env).client).toBeNull();
  });

  it.each(["", "#/passwords", "#/connect-extensions?request=x", "#connect-extension"])(
    "ignores other fragments (%s)",
    (hash) => {
      const env = at(hash);
      expect(captureHandoff(env)).toBeNull();
      expect(env.history.replaceState).not.toHaveBeenCalled();
    }
  );
});

describe("pendingHandoff", () => {
  it("expires after five minutes and forgets tampered values", () => {
    const storage = memoryStorage();
    captureHandoff({ ...at(`#/connect-extension?request=${NONCE}`), storage });
    expect(pendingHandoff({ storage, now: NOW + HANDOFF_TTL_MS - 1 })).not.toBeNull();
    expect(pendingHandoff({ storage, now: NOW + HANDOFF_TTL_MS })).toBeNull();
    expect(storage.getItem(HANDOFF_KEY)).toBeNull();

    storage.setItem(HANDOFF_KEY, "{not json");
    expect(pendingHandoff({ storage, now: NOW })).toBeNull();
    storage.setItem(
      HANDOFF_KEY,
      JSON.stringify({ request: NONCE, browser: "Netscape", expires: NOW + 1 })
    );
    expect(pendingHandoff({ storage, now: NOW })).toBeNull();
  });

  it("is cleared on request", () => {
    const storage = memoryStorage();
    captureHandoff({ ...at(`#/connect-extension?request=${NONCE}`), storage });
    clearHandoff(storage);
    expect(pendingHandoff({ storage, now: NOW })).toBeNull();
  });
});

const fakeWindow = (origin = "https://vault.test") => {
  const listeners = new Set();
  const target = {
    location: { origin },
    posted: [],
    addEventListener: (type, fn) => listeners.add(fn),
    removeEventListener: (type, fn) => listeners.delete(fn),
    postMessage: (data, targetOrigin) => target.posted.push({ data, targetOrigin }),
    dispatch: (event) => [...listeners].forEach((fn) => fn(event)),
    listeners,
  };
  return target;
};

describe("deliverToken", () => {
  it("posts only to its own origin and resolves on the bridge's acknowledgement", async () => {
    const target = fakeWindow();
    const delivered = deliverToken({ request: NONCE, token: "tok" }, { target, timeoutMs: 1000 });
    expect(target.posted).toEqual([
      {
        data: { type: SESSION_MESSAGE, request: NONCE, token: "tok" },
        targetOrigin: "https://vault.test",
      },
    ]);
    const ack = { type: CONNECTED_MESSAGE, request: NONCE };
    target.dispatch({ source: {}, origin: "https://vault.test", data: ack });
    target.dispatch({ source: target, origin: "https://evil.test", data: ack });
    target.dispatch({
      source: target,
      origin: "https://vault.test",
      data: { ...ack, request: "x" },
    });
    target.dispatch({ source: target, origin: "https://vault.test", data: ack });
    await expect(delivered).resolves.toBe(true);
    expect(target.listeners.size).toBe(0);
  });

  it("gives up when nobody answers", async () => {
    vi.useFakeTimers();
    const target = fakeWindow();
    const delivered = deliverToken({ request: NONCE, token: "tok" }, { target, timeoutMs: 50 });
    vi.advanceTimersByTime(60);
    await expect(delivered).resolves.toBe(false);
    expect(target.listeners.size).toBe(0);
    vi.useRealTimers();
  });
});

describe("detectBrowser and installTarget", () => {
  const ua = {
    Chrome: "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    Edge: "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0 Safari/537.36 Edg/131.0",
    Opera: "Mozilla/5.0 Chrome/131.0 Safari/537.36 OPR/115.0",
    Firefox: "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    Vivaldi: "Mozilla/5.0 Chrome/131.0 Safari/537.36 Vivaldi/7.0",
  };
  it.each(Object.entries(ua))("detects %s", (name, userAgent) => {
    expect(detectBrowser({ userAgent })).toBe(name);
  });
  it("detects Brave and unknown browsers", () => {
    expect(detectBrowser({ userAgent: ua.Chrome, brave: {} })).toBe("Brave");
    expect(detectBrowser({ userAgent: "Safari/605" })).toBeNull();
  });
  it("knows a browser is connected only from the vault's list", () => {
    const sessions = [{ id: "a", browser: "Chrome" }];
    expect(isConnectedIn(sessions, "Chrome")).toBe(true);
    expect(isConnectedIn(sessions, "Firefox")).toBe(false);
    expect(isConnectedIn(sessions, null)).toBe(false);
    expect(isConnectedIn([], "Chrome")).toBe(false);
  });

  it("points at the store listing, or at the docs without one", () => {
    for (const browser of ["Chrome", "Brave", "Edge", "Vivaldi"]) {
      expect(installTarget(browser)).toEqual({
        url: "https://chromewebstore.google.com/detail/ciphermoth/gjdobbdnepjkgfpcmhjdagkcjholjkkd",
        label: `Add to ${browser}`,
      });
    }
    expect(installTarget("Firefox")).toEqual({
      url: "https://addons.mozilla.org/firefox/addon/ciphermoth/",
      label: "Add to Firefox",
    });
    expect(installTarget("Opera")).toEqual({
      url: expect.stringContaining("docs/EXTENSION.md"),
      label: "Install in Opera",
    });
    expect(installTarget(null).label).toBe("Install the extension");
  });
});
