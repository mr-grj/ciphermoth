// Build-time constants (scripts/build.mjs). __E2E__ is true only in the test
// build, which the store packages never are; production code paths that read
// it are removed as dead code.
declare const __E2E__: boolean;
declare const __TARGET__: "chromium" | "firefox";
declare const __VERSION__: string;
declare const __NATIVE_HOST__: string;

export const E2E = __E2E__;
export const TARGET = __TARGET__;
export const VERSION = __VERSION__;
// Desktop mode's native-messaging host (scripts/build.mjs nativeHost).
export const NATIVE_HOST = __NATIVE_HOST__;

export const FEATURE = "browser-extension";
export const SESSION_HEADER = "x-ciphermoth-session";
export const REQUEST_TIMEOUT_MS = 15_000;
// Checking a handed-over token. The web app waits for the extension's answer
// (ACK_TIMEOUT_MS in frontend/src/lib/extensionHandoff.js, 10 s) and then ends
// the session it opened, so this must answer well before that.
export const HANDOFF_CHECK_TIMEOUT_MS = 5_000;
export const MAX_RESPONSE_BYTES = 1024 * 1024;
export const HANDOFF_TTL_MS = 5 * 60 * 1000;
export const CLIPBOARD_CLEAR_MS = E2E ? 3_000 : 30_000;
export const BADGE_MS = 2_000;
export const BRIDGE_SCRIPT_ID = "ciphermoth-vault-bridge";
export const SESSION_MESSAGE = "ciphermoth:extension-session";
export const CONNECTED_MESSAGE = "ciphermoth:extension-connected";
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const BROWSERS = [
  "Chrome",
  "Chromium",
  "Edge",
  "Brave",
  "Opera",
  "Vivaldi",
  "Firefox",
  "Browser",
] as const;
export type BrowserName = (typeof BROWSERS)[number];
