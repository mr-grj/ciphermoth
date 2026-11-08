// The background: the only part that talks to CipherMoth and the only part that
// can inject the fill script. It answers messages from the extension's own
// pages (popup, options) and from the vault bridge, nothing else: there is no
// onMessageExternal and externally_connectable is empty.

import { ApiError } from "./api";
import { CLIPBOARD_ALARM, runClear, scheduleClear } from "./clipboard";
import { credential, fill, pageInfo, totp } from "./fill";
import { HANDOFF_ALARM, cancelHandoff, receiveToken, startHandoff } from "./handoff";
import { cancelPairing, launchApp, showApp, startPairing, unpair } from "./desktop";
import {
  SESSION_ALARM,
  browserName,
  configure,
  currentStatus,
  forget,
  forgetSession,
  lock,
  matches,
  messageOf,
  search,
  targetFor,
  unlock,
  useDesktop,
} from "./session";
import { resumeAfterRestart } from "./restart";
import { getConfig, getHandoff, restrictSessionStorage, setConfig } from "./storage";
import { ext } from "../shared/browser";
import { E2E } from "../shared/constants";
import { type Message, type Reply, parseMessage } from "../shared/messages";

// The popup or the options page: one of our own pages, never a content script
// (whose sender URL is the web page's).
const extensionPage = (sender: chrome.runtime.MessageSender): boolean =>
  sender.id === ext.runtime.id &&
  typeof sender.url === "string" &&
  sender.url.startsWith(ext.runtime.getURL(""));

const ok = <T>(value: T): Reply<T> => ({ ok: true, value });
const failed = (error: unknown): Reply<never> => ({
  ok: false,
  error: messageOf(error),
  ...(error instanceof ApiError && error.code ? { code: error.code } : {}),
});

const handle = async (
  message: Message,
  sender: chrome.runtime.MessageSender
): Promise<Reply<unknown>> => {
  if (message.type === "handoff-token") {
    // Only from a content script (the bridge) in a tab, never from our pages.
    if (sender.tab === undefined) return failed(new Error("Refused."));
    return ok(await receiveToken(message, sender));
  }
  if (!extensionPage(sender)) return failed(new Error("Refused."));
  switch (message.type) {
    case "status": {
      const status = await currentStatus();
      return ok({ ...status, handoffPending: Boolean(await getHandoff()) });
    }
    case "configure": {
      const target = targetFor(message.vault, message.api);
      if (typeof target === "string") return failed(new Error(target));
      return ok(await configure(target));
    }
    case "forget":
      await forget();
      return ok(null);
    case "unlock":
      return ok(await unlock(message.password));
    case "handoff":
      await startHandoff();
      return ok(null);
    case "lock":
      await lock();
      return ok(null);
    case "page":
      return ok(await pageInfo(message.tabId));
    case "matches": {
      const page = await pageInfo(message.tabId);
      if (!page.origin) return ok({ page, logins: [], truncated: false });
      return ok({ page, ...(await matches(page.origin)) });
    }
    case "search":
      return ok(await search(message.query));
    case "fill":
      return ok(await fill(message.tabId, message.id, message.origin, message.confirmed));
    case "credential":
      return ok(await credential(message.id, message.origin, message.confirmed));
    case "totp":
      return ok(await totp(message.id, message.origin, message.confirmed));
    case "copied":
      await scheduleClear(message.digest);
      return ok(null);
    case "use-desktop":
      return ok(await useDesktop());
    case "pair":
      await startPairing(browserName());
      return ok(await currentStatus());
    case "cancel-pair":
      cancelPairing();
      return ok(null);
    case "unpair":
      // Stays in desktop mode, ready to pair again.
      await unpair();
      return ok(await currentStatus());
    case "open-app":
      await launchApp();
      return ok(null);
    case "show-app":
      await showApp();
      return ok(null);
    case "settings": {
      const config = await getConfig();
      if (!config) return failed(new Error("Connect to your CipherMoth first."));
      await setConfig({
        ...config,
        subdomains: message.subdomains,
        strictClipboard: message.strictClipboard,
      });
      return ok(null);
    }
  }
};

ext.runtime.onMessage.addListener((raw: unknown, sender, respond) => {
  const message = parseMessage(raw);
  if (!message) return false;
  handle(message, sender).then(respond, (error: unknown) => respond(failed(error)));
  return true;
});

const openPopup = async (tabId?: number): Promise<void> => {
  try {
    await ext.action.openPopup();
  } catch {
    // Not allowed here: point at the button instead.
    await ext.action.setBadgeBackgroundColor({ color: "#e0982f", ...(tabId ? { tabId } : {}) });
    await ext.action.setBadgeText({ text: "…", ...(tabId ? { tabId } : {}) });
  }
};

// The fill shortcut: a browser-level command (a page cannot synthesize it),
// which also grants activeTab. With exactly one match on a secure page it fills
// directly; otherwise it opens the popup on the list.
export const fillCommand = async (tab: chrome.tabs.Tab | undefined): Promise<string> => {
  const tabId = tab?.id;
  if (tabId === undefined) return "no-tab";
  const status = await currentStatus();
  if (status.phase !== "unlocked") {
    await openPopup(tabId);
    return status.phase;
  }
  const page = await pageInfo(tabId);
  if (!page.origin) {
    await openPopup(tabId);
    return "no-page";
  }
  const found = await matches(page.origin).catch(() => null);
  const only = found?.logins.length === 1 ? found.logins[0] : undefined;
  if (!only || page.insecure) {
    await openPopup(tabId);
    return "choose";
  }
  const outcome = await fill(tabId, only.id, page.origin, false).catch(() => null);
  if (!outcome || outcome.reason !== "filled") {
    await openPopup(tabId);
    return outcome?.reason ?? "error";
  }
  return "filled";
};

ext.commands.onCommand.addListener((command, tab) => {
  if (command === "fill-login") void fillCommand(tab);
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SESSION_ALARM) void forgetSession();
  if (alarm.name === HANDOFF_ALARM) void cancelHandoff();
  if (alarm.name === CLIPBOARD_ALARM) void runClear();
});

ext.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install" && !E2E) void ext.runtime.openOptionsPage();
});

void restrictSessionStorage();
void resumeAfterRestart();

if (E2E) {
  // Test build only (scripts/build.mjs --test): lets Playwright press the
  // shortcut, which it cannot do at the browser level.
  (globalThis as unknown as Record<string, unknown>).__ciphermothE2E = {
    fillCommand: async (tabId: number) => fillCommand(await ext.tabs.get(tabId)),
  };
}
