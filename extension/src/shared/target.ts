import { normalizeOrigin, originString, serverOrigin } from "./url";

export interface Target {
  vault: string;
  api: string;
}

const apiFor = (vault: string, api: string | null): string | null => {
  if (!api) return `${vault}/api`;
  const origin = serverOrigin(api);
  if (!origin) return null;
  const raw = api.includes("://") ? api : `https://${api}`;
  let path: string;
  try {
    path = new URL(raw).pathname.replace(/\/+$/, "");
  } catch {
    return null;
  }
  return `${originString(origin)}${path || "/api"}`;
};

// The vault (web app) origin and the API base the user typed, or a message
// saying what is wrong. HTTPS is required except on this computer.
export const targetFor = (vaultInput: string, apiInput: string | null): Target | string => {
  const vault = serverOrigin(vaultInput);
  if (!vault) {
    return normalizeOrigin(vaultInput)
      ? "Use an https:// address (plain http only works for localhost)."
      : "That doesn't look like a web address.";
  }
  const vaultOrigin = originString(vault);
  const api = apiFor(vaultOrigin, apiInput?.trim() || null);
  if (!api) return "Use an https:// address for the API (plain http only works for localhost).";
  return { vault: vaultOrigin, api };
};

// The match pattern for an origin's host. Firefox refuses ports in match
// patterns, and a pattern without one covers every port of that host in both
// browsers (Chrome shows the host only, too). Where the exact origin matters,
// the code checks it itself (the handoff compares the sender's full origin).
export const hostPattern = (origin: string): string => {
  const url = new URL(origin);
  return `${url.protocol}//${url.hostname}/*`;
};

// The host permissions a target needs: the vault's host (for the handoff's
// bridge script) and the API's, if it is elsewhere. Nothing else, ever.
export const permissionOrigins = (target: Target): string[] => [
  ...new Set([hostPattern(target.vault), hostPattern(target.api)]),
];

// The patterns of `origins` that `keep` (another target's patterns) does not
// need, so removing them never takes access a working connection uses.
export const notNeededBy = (origins: string[], keep: string[]): string[] =>
  origins.filter((origin) => !keep.includes(origin));
