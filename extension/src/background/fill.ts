// Fill and copy. A login's username and password exist here only for the one
// call that places them in the page (or hands them to the popup to copy), and
// are dropped right after.

import { asCredential, asTotp, type Credential, type Totp } from "./api";
import { vaultCall } from "./session";
import { getConfig } from "./storage";
import { ext } from "../shared/browser";
import { BADGE_MS } from "../shared/constants";
import type { FillOutcome, FillReason, PageInfo } from "../shared/messages";
import { displayHost, normalizeOrigin } from "../shared/url";
import { fillLogin } from "../fill/fill-script";

// The page in a tab, as the browser reports it: the activeTab grant (a click
// on the toolbar button, or the shortcut) is what lets us see its address.
export const pageInfo = async (tabId: number): Promise<PageInfo> => {
  const tab = await ext.tabs.get(tabId).catch(() => null);
  const url = tab?.url;
  let origin: string | null = null;
  if (url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === "https:" || parsed.protocol === "http:") origin = parsed.origin;
    } catch {
      origin = null;
    }
  }
  const normalized = origin ? normalizeOrigin(origin) : null;
  return {
    tabId,
    origin: normalized ? origin : null,
    host: normalized ? displayHost(normalized) : null,
    insecure: normalized?.scheme === "http",
  };
};

const loginBody = async (id: number, origin: string, confirmed: boolean) => {
  const config = await getConfig();
  return { id, origin, subdomains: config?.subdomains ?? false, confirmed_mismatch: confirmed };
};

export const credential = async (
  id: number,
  origin: string,
  confirmed: boolean
): Promise<Credential> =>
  asCredential(await vaultCall("credential", await loginBody(id, origin, confirmed)));

export const totp = async (id: number, origin: string, confirmed: boolean): Promise<Totp> =>
  asTotp(await vaultCall("totp", await loginBody(id, origin, confirmed)));

const REASONS: ReadonlySet<string> = new Set<FillReason>([
  "filled",
  "username-only",
  "password-only",
  "no-fields",
  "new-password",
  "hidden",
  "origin",
  "frame",
]);

const asOutcome = (value: unknown): FillOutcome => {
  const result = value as { filled?: unknown; reason?: unknown } | null;
  if (
    !result ||
    !Array.isArray(result.filled) ||
    !result.filled.every((f) => f === "username" || f === "password") ||
    typeof result.reason !== "string" ||
    !REASONS.has(result.reason)
  )
    return { filled: [], reason: "blocked" };
  return { filled: result.filled as FillOutcome["filled"], reason: result.reason as FillReason };
};

export const showFilledBadge = async (tabId: number): Promise<void> => {
  await ext.action.setBadgeBackgroundColor({ color: "#7dd3c0", tabId }).catch(() => {});
  await ext.action.setBadgeText({ text: "✓", tabId }).catch(() => {});
  setTimeout(() => {
    ext.action.setBadgeText({ text: "", tabId }).catch(() => {});
  }, BADGE_MS);
};

export const fill = async (
  tabId: number,
  id: number,
  origin: string,
  confirmed: boolean
): Promise<FillOutcome> => {
  const page = await pageInfo(tabId);
  if (page.origin !== origin) return { filled: [], reason: "origin" };
  let login: Credential | null = await credential(id, origin, confirmed);
  let outcome: FillOutcome;
  try {
    const [injection] = await ext.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: fillLogin,
      args: [{ origin, username: login.username, password: login.password }],
    });
    outcome = asOutcome(injection?.result);
  } catch {
    outcome = { filled: [], reason: "blocked" };
  } finally {
    login = null;
  }
  if (outcome.filled.length) await showFilledBadge(tabId);
  return outcome;
};
