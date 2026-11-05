// Clearing what the popup copied. The popup writes the clipboard itself (it has
// the user's click) and tells us only a SHA-256 digest of the value, so no
// secret waits here for the timer. When it fires, the clipboard is cleared,
// unless the user turned on "only clear what CipherMoth copied" (it needs the
// clipboardRead permission) and the clipboard now holds something else.
//
// Chromium's service worker has no clipboard: an offscreen document does the
// work. Firefox's background page has one.

import { getConfig, getPendingClear, setPendingClear } from "./storage";
import { ext } from "../shared/browser";
import { CLIPBOARD_CLEAR_MS, TARGET } from "../shared/constants";
import { clearClipboard } from "../offscreen/clipboard-core";

export const CLIPBOARD_ALARM = "ciphermoth-clipboard-clear";
const OFFSCREEN_URL = "offscreen.html";

export const scheduleClear = async (digest: string): Promise<void> => {
  if (!/^[0-9a-f]{64}$/.test(digest)) return;
  await setPendingClear({ digest });
  await ext.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + CLIPBOARD_CLEAR_MS });
};

const canRead = async (): Promise<boolean> =>
  ext.permissions.contains({ permissions: ["clipboardRead"] }).catch(() => false);

// Chromium only (Firefox has no offscreen API and never reaches this).
const ensureOffscreen = async (): Promise<void> => {
  const api = ext as unknown as {
    offscreen: { createDocument: (options: Record<string, unknown>) => Promise<void> };
  };
  const contexts = await ext.runtime.getContexts?.({
    contextTypes: ["OFFSCREEN_DOCUMENT" as chrome.runtime.ContextType],
  });
  if (contexts?.length) return;
  await api.offscreen.createDocument({
    url: OFFSCREEN_URL,
    reasons: ["CLIPBOARD"],
    justification: "Clear a password CipherMoth copied, after 30 seconds.",
  });
};

export const runClear = async (): Promise<void> => {
  const pending = await getPendingClear();
  await setPendingClear(null);
  if (!pending) return;
  const config = await getConfig();
  const onlyOurs = (config?.strictClipboard ?? false) && (await canRead());
  const request = { digest: pending.digest, onlyOurs };
  if (TARGET === "firefox") {
    await clearClipboard(request);
    return;
  }
  await ensureOffscreen();
  await ext.runtime
    .sendMessage({ target: "offscreen", action: "clear-clipboard", ...request })
    .catch(() => {});
};
