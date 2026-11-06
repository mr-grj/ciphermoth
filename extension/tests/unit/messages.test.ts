import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { HANDOFF_CHECK_TIMEOUT_MS, REQUEST_TIMEOUT_MS } from "../../src/shared/constants";
import { parseMessage } from "../../src/shared/messages";

const TOKEN = "kM3x1y8Qe0bWv7c2Z9pL4tR6sN5aH1jD0fG3uY8iO2w";

describe("parseMessage", () => {
  it.each([
    { type: "status" },
    { type: "unlock", password: "Moth-Test-Vault-2026!" },
    { type: "configure", vault: "https://v.example", api: null },
    { type: "matches", tabId: 0 },
    { type: "fill", tabId: 3, id: 7, origin: "https://github.com", confirmed: false },
    { type: "copied", digest: "ab".repeat(32) },
    { type: "settings", subdomains: true, strictClipboard: false },
    { type: "handoff-token", request: TOKEN, token: TOKEN },
  ])("accepts %j", (message) => {
    expect(parseMessage(message)).toEqual(message);
  });

  it.each([
    null,
    "status",
    [],
    { type: "nope" },
    { type: "status", extra: 1 },
    { type: "unlock" },
    { type: "unlock", password: 1 },
    { type: "unlock", password: "x".repeat(5000) },
    { type: "fill", tabId: 3, id: 0, origin: "https://x", confirmed: false },
    { type: "fill", tabId: 3, id: 1.5, origin: "https://x", confirmed: false },
    { type: "fill", tabId: -1, id: 1, origin: "https://x", confirmed: false },
    { type: "fill", tabId: 3, id: 1, origin: "https://x", confirmed: "yes" },
    { type: "fill", tabId: 3, id: 1, origin: "https://x", confirmed: false, password: "p" },
    { type: "handoff-token", request: "short", token: TOKEN },
    { type: "handoff-token", request: TOKEN, token: `${TOKEN}=` },
    { type: "handoff-token", request: TOKEN },
    { type: "configure", vault: "https://v", api: undefined },
    { type: "matches", tabId: "1" },
    Object.assign(Object.create({ inherited: true }), { type: "status" }),
  ])("refuses %j", (message) => {
    expect(parseMessage(message)).toBeNull();
  });
});

describe("handoff timing", () => {
  it("checks a handed-over token well before the web app gives up waiting", () => {
    // The web app ends the session it opened when no acknowledgement arrives in
    // time; an extension still checking the token would then keep a dead one.
    const app = readFileSync(
      join(import.meta.dirname, "../../../frontend/src/lib/extensionHandoff.js"),
      "utf8"
    );
    const match = /export const ACK_TIMEOUT_MS = ([\d_]+);/.exec(app);
    expect(match).not.toBeNull();
    const ackTimeout = Number((match?.[1] ?? "0").replaceAll("_", ""));
    expect(ackTimeout).toBeGreaterThanOrEqual(HANDOFF_CHECK_TIMEOUT_MS + 3_000);
    expect(HANDOFF_CHECK_TIMEOUT_MS).toBeLessThan(REQUEST_TIMEOUT_MS);
  });
});
