// The browser extension's handoff (docs/EXTENSION.md). React-free so the whole
// protocol is in one auditable place.
//
// The extension opens this web app at
//   <vault>/#/connect-extension?request=<nonce>&browser=<name>
// The fragment never reaches a server. We keep the request in this tab's
// sessionStorage while the user unlocks (unlocking reloads the page), drop the
// fragment from the address bar, and after the user confirms, post the new
// extension token to this window for the extension's bridge script, which only
// the extension that made the nonce accepts. Anyone can link here, but without
// a waiting extension nothing receives the token, and the app then disconnects
// the session it opened.

import { GITHUB_REPO } from "./updateCheck";

export const HANDOFF_KEY = "ciphermothExtensionHandoff";
export const HANDOFF_ROUTE = "#/connect-extension";
export const HANDOFF_TTL_MS = 5 * 60 * 1000;
export const SESSION_MESSAGE = "ciphermoth:extension-session";
export const CONNECTED_MESSAGE = "ciphermoth:extension-connected";
export const ACK_TIMEOUT_MS = 4000;

export const BROWSERS = [
  "Chrome",
  "Chromium",
  "Edge",
  "Brave",
  "Opera",
  "Vivaldi",
  "Firefox",
  "Browser",
];

const NONCE = /^[A-Za-z0-9_-]{43}$/;
const CLIENT = /^[A-Za-z0-9_-]{22,43}$/;

const valid = (handoff) =>
  Boolean(handoff) &&
  typeof handoff.request === "string" &&
  NONCE.test(handoff.request) &&
  BROWSERS.includes(handoff.browser) &&
  (handoff.client === null || handoff.client === undefined || CLIENT.test(handoff.client)) &&
  Number.isFinite(handoff.expires);

// Read the handoff out of the address bar, once, before the app renders. The
// fragment is removed whatever it holds.
export const captureHandoff = ({
  location = window.location,
  history = window.history,
  storage = sessionStorage,
  now = Date.now(),
} = {}) => {
  const hash = location.hash || "";
  if (hash !== HANDOFF_ROUTE && !hash.startsWith(`${HANDOFF_ROUTE}?`)) return null;
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  const params = new URLSearchParams(hash.slice(HANDOFF_ROUTE.length + 1));
  const handoff = {
    request: params.get("request"),
    browser: BROWSERS.includes(params.get("browser")) ? params.get("browser") : "Browser",
    client: CLIENT.test(params.get("client") ?? "") ? params.get("client") : null,
    expires: now + HANDOFF_TTL_MS,
  };
  if (!valid(handoff)) return null;
  storage.setItem(HANDOFF_KEY, JSON.stringify(handoff));
  return handoff;
};

export const pendingHandoff = ({ storage = sessionStorage, now = Date.now() } = {}) => {
  let handoff = null;
  try {
    handoff = JSON.parse(storage.getItem(HANDOFF_KEY));
  } catch {
    handoff = null;
  }
  if (!valid(handoff) || handoff.expires <= now) {
    storage.removeItem(HANDOFF_KEY);
    return null;
  }
  return handoff;
};

export const clearHandoff = (storage = sessionStorage) => storage.removeItem(HANDOFF_KEY);

// Post the token to the extension's bridge in this window and wait for its
// acknowledgement. Resolves true when the extension took it.
export const deliverToken = (
  { request, token },
  { target = window, timeoutMs = ACK_TIMEOUT_MS } = {}
) =>
  new Promise((resolve) => {
    const origin = target.location.origin;
    let timer;
    const onMessage = (event) => {
      const data = event.data;
      if (
        event.source !== target ||
        event.origin !== origin ||
        !data ||
        data.type !== CONNECTED_MESSAGE ||
        data.request !== request
      )
        return;
      finish(true);
    };
    const finish = (ok) => {
      clearTimeout(timer);
      target.removeEventListener("message", onMessage);
      resolve(ok);
    };
    target.addEventListener("message", onMessage);
    timer = setTimeout(() => finish(false), timeoutMs);
    target.postMessage({ type: SESSION_MESSAGE, request, token }, origin);
  });

// The browser this page runs in, for the install button.
export const detectBrowser = (nav = globalThis.navigator) => {
  const ua = nav?.userAgent || "";
  if (/\bFirefox\//.test(ua)) return "Firefox";
  if (/\bEdg\//.test(ua)) return "Edge";
  if (/\bOPR\//.test(ua)) return "Opera";
  if (/\bVivaldi\//.test(ua)) return "Vivaldi";
  if (nav?.brave) return "Brave";
  if (/\bChrome\//.test(ua)) return "Chrome";
  return null;
};

// Store listings do not exist yet: until one is published its entry stays null
// and the install button points at the release assets and docs/EXTENSION.md.
export const STORE_LINKS = {
  Chrome: null,
  Edge: null,
  Brave: null,
  Opera: null,
  Vivaldi: null,
  Firefox: null,
};
export const RELEASES_URL = `https://github.com/${GITHUB_REPO}/releases/latest`;
export const EXTENSION_DOCS_URL = `https://github.com/${GITHUB_REPO}/blob/master/docs/EXTENSION.md`;

export const installTarget = (browser) => {
  const store = browser ? STORE_LINKS[browser] : null;
  if (store) return { url: store, label: `Add to ${browser}` };
  return {
    url: EXTENSION_DOCS_URL,
    label: browser ? `Install in ${browser}` : "Install the extension",
  };
};

// Whether the vault lists a connected browser with this browser's name. Pages
// cannot detect extensions (on purpose), so this is the honest hint; it may be
// the same browser on another computer.
export const isConnectedIn = (sessions, browser) =>
  Boolean(browser) && Array.isArray(sessions) && sessions.some((s) => s.browser === browser);
