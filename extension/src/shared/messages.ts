// Every message between the extension's own pages (popup, options), the vault
// bridge content script and the background, with strict validation: a message
// with an unknown type, a missing field, an extra field or a field of the wrong
// type is dropped. Nothing outside the extension can send these at all
// (externally_connectable is empty and there is no onMessageExternal).

import { BROWSERS, type BrowserName, TOKEN_PATTERN } from "./constants";

type Shape = Record<string, "string" | "number" | "boolean" | "string?" | "id" | "tab">;

const SHAPES = {
  status: {},
  configure: { vault: "string", api: "string?" },
  forget: {},
  unlock: { password: "string" },
  handoff: {},
  lock: {},
  page: { tabId: "tab" },
  matches: { tabId: "tab" },
  search: { query: "string" },
  fill: { tabId: "tab", id: "id", origin: "string", confirmed: "boolean" },
  credential: { id: "id", origin: "string", confirmed: "boolean" },
  totp: { id: "id", origin: "string", confirmed: "boolean" },
  copied: { digest: "string" },
  settings: { subdomains: "boolean", strictClipboard: "boolean" },
  "handoff-token": { request: "string", token: "string" },
} as const satisfies Record<string, Shape>;

export type MessageType = keyof typeof SHAPES;

type FieldType<T> = T extends "string"
  ? string
  : T extends "string?"
    ? string | null
    : T extends "number" | "id" | "tab"
      ? number
      : T extends "boolean"
        ? boolean
        : never;

export type Message = {
  [K in MessageType]: { type: K } & {
    -readonly [F in keyof (typeof SHAPES)[K]]: FieldType<(typeof SHAPES)[K][F]>;
  };
}[MessageType];

export type MessageOf<K extends MessageType> = Extract<Message, { type: K }>;

const MAX_STRING = 4096;

const fieldOk = (kind: string, value: unknown): boolean => {
  switch (kind) {
    case "string":
      return typeof value === "string" && value.length <= MAX_STRING;
    case "string?":
      return value === null || (typeof value === "string" && value.length <= MAX_STRING);
    case "boolean":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "id":
      return Number.isSafeInteger(value) && (value as number) >= 1;
    case "tab":
      return Number.isSafeInteger(value) && (value as number) >= 0;
    default:
      return false;
  }
};

export const parseMessage = (raw: unknown): Message | null => {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  if (Object.getPrototypeOf(raw) !== Object.prototype) return null;
  const record = raw as Record<string, unknown>;
  const type = record.type;
  if (typeof type !== "string" || !Object.hasOwn(SHAPES, type)) return null;
  const shape: Shape = SHAPES[type as MessageType];
  const keys = Object.keys(record);
  if (keys.length !== Object.keys(shape).length + 1) return null;
  for (const key of keys) {
    if (key === "type") continue;
    const kind = shape[key];
    if (kind === undefined || !fieldOk(kind, record[key])) return null;
  }
  if (type === "handoff-token") {
    if (!TOKEN_PATTERN.test(record.request as string)) return null;
    if (!TOKEN_PATTERN.test(record.token as string)) return null;
  }
  return record as Message;
};

export const isBrowserName = (value: unknown): value is BrowserName =>
  typeof value === "string" && (BROWSERS as readonly string[]).includes(value);

// What the background answers.

export interface Login {
  id: number;
  name: string;
  username: string | null;
  host: string | null;
  favorite: boolean;
  has_totp: boolean;
}

export type Phase = "setup" | "locked" | "unlocked" | "too-old" | "offline";

export interface Status {
  phase: Phase;
  vault: string | null;
  api: string | null;
  serverVersion: string | null;
  idleTimeoutMs: number | null;
  subdomains: boolean;
  strictClipboard: boolean;
  handoffPending: boolean;
  error: string | null;
}

export interface PageInfo {
  tabId: number;
  origin: string | null;
  host: string | null;
  insecure: boolean;
}

export type FillReason =
  | "filled"
  | "username-only"
  | "password-only"
  | "no-fields"
  | "new-password"
  | "hidden"
  | "origin"
  | "frame"
  | "blocked";

export interface FillOutcome {
  filled: ("username" | "password")[];
  reason: FillReason;
}

export type Reply<T> = { ok: true; value: T } | { ok: false; error: string; code?: string };
