// Where the extension keeps state (docs/EXTENSION.md, "Where state lives").
//
// storage.local holds only the configuration: the vault's addresses and two
// preferences. No secret, token or entry name is ever written there.
// storage.session lives in memory only, is cleared when the browser exits and
// is readable by extension pages only (TRUSTED_CONTEXTS): the session token,
// its deadline, a pending handoff and the digest of the last copied value.

import { ext } from "../shared/browser";

export interface Config {
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
  const { config } = (await local().get("config")) as { config?: Config };
  if (!config || typeof config.vault !== "string" || typeof config.api !== "string") return null;
  return {
    vault: config.vault,
    api: config.api,
    subdomains: config.subdomains === true,
    strictClipboard: config.strictClipboard === true,
  };
};

export const setConfig = (config: Config | null): Promise<void> =>
  config ? local().set({ config }) : local().remove("config");

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
