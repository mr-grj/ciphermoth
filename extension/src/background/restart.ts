// Chromium fixes the methods of chrome.runtime when the service worker starts:
// with nativeMessaging granted later (the options page asks for it when the
// user picks the app), connectNative is missing until the worker restarts, and
// pairing failed with a TypeError (found in Brave, 2026-11-08). Reloading the
// extension starts a new worker; it closes the extension's pages, so a one-shot
// marker in storage.local (not a secret) reopens the settings afterwards.

import { ext } from "../shared/browser";

export const REOPEN_OPTIONS = "reopenOptions";

// A worker that started after the grant and still has no connectNative must not
// reload again on every request.
const RESTART_GRACE_MS = 60_000;
const started = Date.now();

export const nativeMessagingReady = (): boolean =>
  typeof (ext.runtime as Partial<typeof ext.runtime>).connectNative === "function";

// Reload the extension; the reply to the current message goes out first.
export const restart = async ({
  reopenOptions,
  force = false,
}: {
  reopenOptions: boolean;
  force?: boolean;
}): Promise<boolean> => {
  if (!force && Date.now() - started < RESTART_GRACE_MS) return false;
  if (reopenOptions) await ext.storage.local.set({ [REOPEN_OPTIONS]: true });
  setTimeout(() => ext.runtime.reload(), 200);
  return true;
};

// At start: reopen the settings the restart closed.
export const resumeAfterRestart = async (): Promise<void> => {
  const stored = (await ext.storage.local.get(REOPEN_OPTIONS)) as Record<string, unknown>;
  if (stored[REOPEN_OPTIONS] !== true) return;
  await ext.storage.local.remove(REOPEN_OPTIONS);
  await ext.runtime.openOptionsPage();
};
