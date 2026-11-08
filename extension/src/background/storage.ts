// Where the extension keeps state (docs/EXTENSION.md, "Where state lives").
//
// storage.local holds only the configuration (the vault's addresses, two
// preferences), a random installation id and, for a moment, the restart.ts
// marker that reopens the settings. No secret, token or entry name.
// storage.session lives in memory only, is cleared when the browser exits and
// is readable by extension pages only (TRUSTED_CONTEXTS): the session token,
// its deadline, a pending handoff and the digest of the last copied value.

import { ext, randomToken } from "../shared/browser";

// One connection per installation (design decision 39): the user's server
// (vault and API addresses) or the desktop app on this computer (no address;
// vault and api are empty). A configuration saved before desktop mode existed
// has no mode and is a server.
export interface Config {
  mode: "server" | "desktop";
  vault: string;
  api: string;
  subdomains: boolean;
  strictClipboard: boolean;
}

export interface Session {
  token: string;
  idleTimeoutMs: number;
  expiresAt: number;
}

export interface PendingHandoff {
  request: string;
  tabId: number;
  vault: string;
  returnTo: number | null;
  expires: number;
}

export interface PendingClear {
  digest: string;
}

interface SessionArea {
  session?: Session;
  handoff?: PendingHandoff;
  clipboard?: PendingClear;
}

const local = () => ext.storage.local;
const memory = () => ext.storage.session;

export const restrictSessionStorage = async (): Promise<void> => {
  const area = memory() as chrome.storage.SessionStorageArea & {
    setAccessLevel?: (options: { accessLevel: string }) => Promise<void>;
  };
  await area.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
};

export const getConfig = async (): Promise<Config | null> => {
  const { config } = (await local().get("config")) as { config?: Partial<Config> };
  if (!config) return null;
  const preferences = {
    subdomains: config.subdomains === true,
    strictClipboard: config.strictClipboard === true,
  };
  if (config.mode === "desktop") return { mode: "desktop", vault: "", api: "", ...preferences };
  if (typeof config.vault !== "string" || typeof config.api !== "string" || !config.vault)
    return null;
  return { mode: "server", vault: config.vault, api: config.api, ...preferences };
};

// The server connection, or null in desktop mode (or when not set up).
export const getServer = async (): Promise<Config | null> => {
  const config = await getConfig();
  return config?.mode === "server" ? config : null;
};

export const setConfig = (config: Config | null): Promise<void> =>
  config ? local().set({ config }) : local().remove("config");

// A random id for this installation (browser profile), sent when a session
// opens so the server ends this installation's previous one. Not a secret: it
// opens nothing, it only lets a new unlock replace an old session whose token
// was lost (browser restart, extension reload).
export const installId = async (): Promise<string> => {
  const { installId: stored } = (await local().get("installId")) as { installId?: unknown };
  if (typeof stored === "string" && /^[A-Za-z0-9_-]{22}$/.test(stored)) return stored;
  const fresh = randomToken(16);
  await local().set({ installId: fresh });
  return fresh;
};

const read = async <K extends keyof SessionArea>(key: K): Promise<SessionArea[K]> =>
  ((await memory().get(key)) as SessionArea)[key];

const write = async <K extends keyof SessionArea>(
  key: K,
  value: SessionArea[K] | null
): Promise<void> => (value ? memory().set({ [key]: value }) : memory().remove(key));

export const getSession = () => read("session");
export const setSession = (session: Session | null) => write("session", session);
export const getHandoff = () => read("handoff");
export const setHandoff = (handoff: PendingHandoff | null) => write("handoff", handoff);
export const getPendingClear = () => read("clipboard");
export const setPendingClear = (clear: PendingClear | null) => write("clipboard", clear);
