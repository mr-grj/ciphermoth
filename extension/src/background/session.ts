// The connection to the user's CipherMoth and the extension session on it.
//
// The session token lives in storage.session only (memory, extension pages
// only). The server enforces everything that matters: the token's scope (fill
// only), its idle timeout (the vault's inactivity setting), the 12-hour limit,
// and every way it ends (lock, disconnect in Settings, master password change,
// server restart). This side only forgets a token the server stopped
// accepting, or once its deadline passed.

import {
  ApiError,
  NOT_CIPHERMOTH,
  UNREACHABLE,
  asLogins,
  asMeta,
  asSessionStatus,
  asUnlock,
  request,
} from "./api";
import { api as desktopApi, desktopPhase, forgetDesktop, lockApp, unpair } from "./desktop";
import {
  type Config,
  getConfig,
  getServer,
  getSession,
  installId,
  setConfig,
  setSession,
} from "./storage";
import { ext } from "../shared/browser";
import { type BrowserName, FEATURE, HANDOFF_CHECK_TIMEOUT_MS, TARGET } from "../shared/constants";
import type { Logins } from "./api";
import type { Status } from "../shared/messages";
import { type Target, permissionOrigins } from "../shared/target";

export { permissionOrigins, targetFor } from "../shared/target";

export const SESSION_ALARM = "ciphermoth-session-expired";

export const browserName = (): BrowserName => {
  if (TARGET === "firefox") return "Firefox";
  const nav = navigator as Navigator & {
    brave?: unknown;
    userAgentData?: { brands?: { brand: string }[] };
  };
  const brands = (nav.userAgentData?.brands ?? []).map((b) => b.brand);
  if (nav.brave || brands.includes("Brave")) return "Brave";
  if (brands.includes("Microsoft Edge") || /\bEdg\//.test(nav.userAgent)) return "Edge";
  if (brands.includes("Opera") || /\bOPR\//.test(nav.userAgent)) return "Opera";
  if (/\bVivaldi\//.test(nav.userAgent)) return "Vivaldi";
  if (brands.includes("Google Chrome")) return "Chrome";
  if (brands.includes("Chromium")) return "Chromium";
  return "Browser";
};

const status = (config: Config | null, patch: Partial<Status>): Status => ({
  phase: "setup",
  mode: config?.mode ?? null,
  vault: config?.mode === "server" ? config.vault : null,
  api: config?.mode === "server" ? config.api : null,
  pairingCode: null,
  serverVersion: null,
  idleTimeoutMs: null,
  subdomains: config?.subdomains ?? false,
  strictClipboard: config?.strictClipboard ?? false,
  handoffPending: false,
  error: null,
  ...patch,
});

const remember = async (token: string, idleTimeoutMs: number, expiresInMs: number) => {
  const expiresAt = Date.now() + expiresInMs;
  await setSession({ token, idleTimeoutMs, expiresAt });
  await ext.alarms.create(SESSION_ALARM, { when: expiresAt });
};

export const forgetSession = async (): Promise<void> => {
  await setSession(null);
  await ext.alarms.clear(SESSION_ALARM);
};

// A call with the session token. A session the server no longer accepts is
// forgotten; every accepted call is activity and moves the deadline.
export const authed = async (path: string, body?: unknown): Promise<unknown> => {
  const config = await getServer();
  const session = await getSession();
  if (!config || !session) throw new ApiError("CipherMoth is locked.", 401, "invalid_session");
  try {
    const data = await request(config.api, path, { body, token: session.token });
    await remember(session.token, session.idleTimeoutMs, session.idleTimeoutMs);
    return data;
  } catch (error) {
    if (
      error instanceof ApiError &&
      (error.status === 401 || (error.status === 403 && error.code === "extension_scope"))
    )
      await forgetSession();
    throw error;
  }
};

// A request to whichever CipherMoth this installation uses: the server's
// /api/extension/<route> with the session token, or the desktop app over the
// paired channel (which holds the session itself).
export const vaultCall = async (
  route: "matches" | "search" | "credential" | "totp",
  body: unknown
): Promise<unknown> => {
  const config = await getConfig();
  if (config?.mode === "desktop") return desktopApi(route, body);
  return authed(`/extension/${route}`, body);
};

const desktopStatus = async (config: Config): Promise<Status> => {
  const { phase, code, error } = await desktopPhase();
  return status(config, { phase, pairingCode: code, error });
};

export const currentStatus = async (): Promise<Status> => {
  const config = await getConfig();
  if (!config) return status(null, { phase: "setup" });
  if (config.mode === "desktop") return desktopStatus(config);
  const session = await getSession();
  if (!session) return status(config, { phase: "locked" });
  try {
    const live = asSessionStatus(await authed("/extension/session"));
    await remember(session.token, live.idleTimeoutMs, live.expiresInMs);
    return status(config, { phase: "unlocked", idleTimeoutMs: live.idleTimeoutMs });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return status(config, { phase: "locked" });
    }
    return status(config, { phase: "offline", error: messageOf(error) });
  }
};

export const messageOf = (error: unknown): string => {
  if (error instanceof ApiError) {
    if (error.code === UNREACHABLE) {
      return "Can't reach your CipherMoth. Check that it is running and that this browser trusts its certificate.";
    }
    return error.message;
  }
  return "Something went wrong.";
};

// Check that the API is a CipherMoth recent enough for the extension, then
// save the configuration. The host permissions were granted by the page that
// asked (it had the user's click).
export const configure = async (target: Target): Promise<Status> => {
  let meta;
  try {
    meta = asMeta(await request(target.api, "/meta", { method: "GET" }));
  } catch (error) {
    if (error instanceof ApiError && (error.code === NOT_CIPHERMOTH || error.status === 404)) {
      throw new ApiError(
        `No CipherMoth API at ${target.api}. If your API runs on another address (port 8000 by default), enter it under “API address”.`,
        0,
        NOT_CIPHERMOTH
      );
    }
    throw error;
  }
  if (!meta.features.includes(FEATURE)) {
    return status(null, {
      phase: "too-old",
      serverVersion: meta.version,
      error: `This CipherMoth (${meta.version}) is too old for the browser extension. Update it first.`,
    });
  }
  const previous = await getConfig();
  if (previous?.mode === "desktop") {
    // Leaving desktop mode ends its connection (the app stays unlocked) and
    // drops the permission; the pairing is kept for switching back.
    forgetDesktop();
    await ext.permissions.remove({ permissions: ["nativeMessaging"] }).catch(() => false);
  } else if (previous && (previous.vault !== target.vault || previous.api !== target.api)) {
    await lock();
  }
  const config: Config = {
    mode: "server",
    vault: target.vault,
    api: target.api,
    subdomains: previous?.subdomains ?? false,
    strictClipboard: previous?.strictClipboard ?? false,
  };
  await setConfig(config);
  return status(config, { phase: "locked", serverVersion: meta.version });
};

export const unlock = async (password: string): Promise<Status> => {
  const config = await getServer();
  if (!config) return status(null, { phase: "setup" });
  let result;
  try {
    result = asUnlock(
      await request(config.api, "/extension/unlock", {
        body: { master_password: password, browser: browserName(), client: await installId() },
      })
    );
  } catch (error) {
    if (error instanceof ApiError && error.status === 404 && error.code === null) {
      if (!/master password/i.test(error.message)) {
        return status(config, {
          phase: "too-old",
          error: "Update CipherMoth to use the extension.",
        });
      }
    }
    throw error;
  }
  if (!result.valid || !result.token || result.idleTimeoutMs === null) {
    throw new ApiError("Wrong master password.", 200, "wrong_password");
  }
  await remember(result.token, result.idleTimeoutMs, result.idleTimeoutMs);
  return status(config, { phase: "unlocked", idleTimeoutMs: result.idleTimeoutMs });
};

// Adopt a token the web app handed over. It is checked with the server before
// it is kept.
export const adoptToken = async (token: string): Promise<boolean> => {
  const config = await getServer();
  if (!config) return false;
  try {
    const live = asSessionStatus(
      await request(config.api, "/extension/session", {
        token,
        timeoutMs: HANDOFF_CHECK_TIMEOUT_MS,
      })
    );
    await remember(token, live.idleTimeoutMs, live.expiresInMs);
    return true;
  } catch {
    return false;
  }
};

export const lock = async (): Promise<void> => {
  if ((await getConfig())?.mode === "desktop") return lockApp();
  const config = await getServer();
  const session = await getSession();
  await forgetSession();
  if (config && session) {
    await request(config.api, "/extension/lock", { token: session.token }).catch(() => {});
  }
};

// Switch to the CipherMoth app on this computer: the server's session ends and
// its site access is removed (design decision 39). A pairing made before is
// kept, so switching back needs no new code.
export const useDesktop = async (): Promise<Status> => {
  const previous = await getConfig();
  const server = await getServer();
  if (server) {
    await lock();
    await ext.permissions.remove({ origins: permissionOrigins(server) }).catch(() => false);
  }
  const config: Config = {
    mode: "desktop",
    vault: "",
    api: "",
    subdomains: previous?.subdomains ?? false,
    strictClipboard: previous?.strictClipboard ?? false,
  };
  await setConfig(config);
  return desktopStatus(config);
};

export const forget = async (): Promise<void> => {
  const config = await getConfig();
  if (config?.mode === "desktop") {
    await unpair();
    await setConfig(null);
    await ext.permissions.remove({ permissions: ["nativeMessaging"] }).catch(() => false);
    return;
  }
  await lock();
  await setConfig(null);
  if (config) {
    const origins = permissionOrigins(config);
    await ext.permissions.remove({ origins }).catch(() => false);
  }
};

export const matches = async (origin: string): Promise<Logins> => {
  const config = await getConfig();
  return asLogins(await vaultCall("matches", { origin, subdomains: config?.subdomains ?? false }));
};

export const search = async (query: string): Promise<Logins> =>
  asLogins(await vaultCall("search", { query: query.slice(0, 200) }));
