// Chromium's offscreen document: a hidden extension page whose only job is to
// clear the clipboard for the service worker, which has none.

import { clearClipboard } from "./clipboard-core";

chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  const request = message as {
    target?: unknown;
    action?: unknown;
    digest?: unknown;
    onlyOurs?: unknown;
  } | null;
  if (
    sender.id !== chrome.runtime.id ||
    sender.tab !== undefined ||
    !request ||
    request.target !== "offscreen" ||
    request.action !== "clear-clipboard" ||
    typeof request.digest !== "string" ||
    typeof request.onlyOurs !== "boolean"
  )
    return false;
  clearClipboard({ digest: request.digest, onlyOurs: request.onlyOurs })
    .then((cleared) => respond({ cleared }))
    .finally(() => setTimeout(() => window.close(), 100));
  return true;
});
