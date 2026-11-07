import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// The desktop app's browser-extension switch and paired browsers (desktop
// only). The pairing itself happens in Rust; the window only shows the code
// and passes the user's answer back.

// The app reports seconds since the epoch; the vault UI formats ISO strings.
const isoFromSeconds = (seconds) =>
  Number.isSafeInteger(seconds) && seconds > 0 ? new Date(seconds * 1000).toISOString() : null;

export const toExtensionStatus = (raw) => ({
  enabled: raw?.enabled === true,
  listening: raw?.listening === true,
  browsers: Array.isArray(raw?.browsers) ? raw.browsers.filter((b) => typeof b === "string") : [],
  pairings: (Array.isArray(raw?.pairings) ? raw.pairings : []).map((p) => ({
    id: String(p.id),
    browser: String(p.browser),
    created: isoFromSeconds(p.created),
    lastUsed: isoFromSeconds(p.last_used),
  })),
  error: typeof raw?.error === "string" ? raw.error : null,
});

// "482913" -> "482 913", as the extension's popup shows it.
export const formatPairingCode = (code) =>
  /^\d{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : "";

export const extensionStatus = async () => toExtensionStatus(await invoke("extension_status"));

export const allowExtensions = async (enabled) =>
  toExtensionStatus(await invoke("extension_set_enabled", { enabled }));

export const unpairBrowser = async (id) =>
  toExtensionStatus(await invoke("extension_unpair", { id }));

export const answerPairing = (id, allow) =>
  invoke("extension_pairing_answer", { id, allow }).catch(() => {});

// A browser asks to pair: `{ id, browser, code }`; `onClosed(id)` when the app
// stopped waiting (answered, timed out, locked).
export const onPairingRequest = async (onRequest, onClosed) => {
  const stopRequest = await listen("extension-pairing", (event) => onRequest(event.payload));
  const stopClosed = await listen("extension-pairing-closed", (event) =>
    onClosed(event.payload.id)
  );
  return () => {
    stopRequest();
    stopClosed();
  };
};
