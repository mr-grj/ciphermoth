// The only network code in the extension: requests to the user's own CipherMoth
// API, nowhere else. Every request refuses redirects (the session token must
// never follow one to another host), sends no cookies, is never cached, times
// out, and reads at most MAX_RESPONSE_BYTES of a JSON answer whose shape is
// checked before anything uses it. TLS errors fail closed: fetch has no way to
// accept a certificate the browser does not trust.

import {
  MAX_RESPONSE_BYTES,
  REQUEST_TIMEOUT_MS,
  SESSION_HEADER,
  TOKEN_PATTERN,
} from "../shared/constants";
import type { Login } from "../shared/messages";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | null = null
  ) {
    super(message);
  }
}

export const UNREACHABLE = "offline";
export const NOT_CIPHERMOTH = "not_ciphermoth";

const readCapped = async (response: Response): Promise<string> => {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE_BYTES) throw new Error("too large");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("too large");
    }
    chunks.push(value);
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
};

export interface CallOptions {
  method?: "GET" | "POST";
  body?: unknown;
  token?: string | null;
  timeoutMs?: number;
}

export const request = async (
  apiBase: string,
  path: string,
  { method = "POST", body, token = null, timeoutMs = REQUEST_TIMEOUT_MS }: CallOptions = {}
): Promise<unknown> => {
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers[SESSION_HEADER] = token;
  let response: Response;
  try {
    response = await fetch(`${apiBase}${path}`, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new ApiError("Can't reach your CipherMoth.", 0, UNREACHABLE);
  }
  let data: unknown;
  try {
    const type = response.headers.get("content-type") ?? "";
    if (!type.toLowerCase().startsWith("application/json")) throw new Error("not json");
    data = JSON.parse(await readCapped(response));
  } catch {
    throw new ApiError(
      "This address answered, but not like a CipherMoth server.",
      response.status,
      NOT_CIPHERMOTH
    );
  }
  if (!response.ok) {
    const record = (data ?? {}) as { detail?: unknown; code?: unknown };
    const detail = typeof record.detail === "string" ? record.detail.slice(0, 300) : null;
    const code = typeof record.code === "string" ? record.code : null;
    throw new ApiError(detail ?? `CipherMoth answered ${response.status}.`, response.status, code);
  }
  return data;
};

// Shape checks for every answer the extension reads.

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const stringOrNull = (value: unknown): value is string | null =>
  value === null || typeof value === "string";

const invalid = (): never => {
  throw new ApiError("CipherMoth sent an answer this extension cannot read.", 200, NOT_CIPHERMOTH);
};

export interface Meta {
  version: string;
  features: string[];
}

export const asMeta = (data: unknown): Meta => {
  if (
    !isRecord(data) ||
    typeof data.version !== "string" ||
    !Array.isArray(data.features) ||
    !data.features.every((feature) => typeof feature === "string")
  )
    return invalid();
  return { version: data.version.slice(0, 40), features: data.features as string[] };
};

export interface Unlock {
  valid: boolean;
  token: string | null;
  idleTimeoutMs: number | null;
}

export const asUnlock = (data: unknown): Unlock => {
  if (!isRecord(data) || typeof data.valid !== "boolean") return invalid();
  if (!data.valid) return { valid: false, token: null, idleTimeoutMs: null };
  if (
    typeof data.session_token !== "string" ||
    !TOKEN_PATTERN.test(data.session_token) ||
    !Number.isSafeInteger(data.idle_timeout_ms)
  )
    return invalid();
  return {
    valid: true,
    token: data.session_token,
    idleTimeoutMs: data.idle_timeout_ms as number,
  };
};

export interface SessionStatus {
  idleTimeoutMs: number;
  expiresInMs: number;
}

export const asSessionStatus = (data: unknown): SessionStatus => {
  if (
    !isRecord(data) ||
    !Number.isSafeInteger(data.idle_timeout_ms) ||
    !Number.isSafeInteger(data.expires_in_ms)
  )
    return invalid();
  return {
    idleTimeoutMs: data.idle_timeout_ms as number,
    expiresInMs: data.expires_in_ms as number,
  };
};

const asLogin = (value: unknown): Login => {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.id) ||
    typeof value.name !== "string" ||
    !stringOrNull(value.username) ||
    !stringOrNull(value.host) ||
    typeof value.favorite !== "boolean" ||
    typeof value.has_totp !== "boolean"
  )
    return invalid();
  return {
    id: value.id as number,
    name: value.name,
    username: value.username,
    host: value.host,
    favorite: value.favorite,
    has_totp: value.has_totp,
  };
};

export interface Logins {
  logins: Login[];
  truncated: boolean;
}

export const asLogins = (data: unknown): Logins => {
  if (
    !isRecord(data) ||
    !Array.isArray(data.logins) ||
    data.logins.length > 50 ||
    typeof data.truncated !== "boolean"
  )
    return invalid();
  return { logins: data.logins.map(asLogin), truncated: data.truncated };
};

export interface Credential {
  username: string | null;
  password: string;
}

export const asCredential = (data: unknown): Credential => {
  if (!isRecord(data) || !stringOrNull(data.username) || typeof data.password !== "string")
    return invalid();
  return { username: data.username, password: data.password };
};

export interface Totp {
  code: string;
  expiresIn: number;
}

export const asTotp = (data: unknown): Totp => {
  if (
    !isRecord(data) ||
    typeof data.code !== "string" ||
    !/^\d{6,8}$/.test(data.code) ||
    !Number.isSafeInteger(data.expires_in)
  )
    return invalid();
  return { code: data.code, expiresIn: data.expires_in as number };
};
