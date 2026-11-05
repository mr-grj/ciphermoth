import { createStore } from "easy-peasy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "../api/client";
import { routes } from "../test/adapter";
import { stubBrowser } from "../test/globals";
import { setSessionToken } from "../utils";
import Extension from "./extension";

const TOKEN = "kM3x1y8Qe0bWv7c2Z9pL4tR6sN5aH1jD0fG3uY8iO2w";
const SESSIONS = [
  { id: "h1", browser: "Firefox", created: "2026-11-05T10:00:00+00:00", last_used: null },
];
const originalAdapter = apiClient.defaults.adapter;
let seen;

const build = (table) => {
  seen = [];
  apiClient.defaults.adapter = routes(table, seen);
  const store = createStore({ extension: Extension });
  return { actions: store.getActions().extension, state: () => store.getState().extension };
};

beforeEach(() => {
  vi.unstubAllGlobals();
  stubBrowser();
  setSessionToken(TOKEN);
});

afterEach(() => {
  apiClient.defaults.adapter = originalAdapter;
});

describe("extension model", () => {
  it("lists connected browsers", async () => {
    const { actions, state } = build({ "GET /extension/sessions": [200, SESSIONS] });
    await actions.loadSessions();
    expect(state().sessions).toEqual(SESSIONS);
    expect(state().loaded).toBe(true);
    expect(seen[0].headers["x-ciphermoth-session"]).toBe(TOKEN);
  });

  it("disconnects by handle and reloads, also when it was already gone", async () => {
    const { actions, state } = build({
      "DELETE /extension/sessions/h%2F1": [404, { detail: "No such browser extension session." }],
      "GET /extension/sessions": [200, []],
    });
    await actions.disconnect("h/1");
    expect(seen.map((c) => `${c.method} ${c.url}`)).toEqual([
      "delete /extension/sessions/h%2F1",
      "get /extension/sessions",
    ]);
    expect(state().sessions).toEqual([]);
  });

  it("connects for the handoff and surfaces the server's message", async () => {
    const { actions } = build({
      "POST /extension/sessions": [200, { session_token: "t", id: "h", idle_timeout_ms: 1 }],
    });
    await expect(actions.connect("Chrome")).resolves.toMatchObject({ id: "h" });
    expect(JSON.parse(seen[0].data)).toEqual({ browser: "Chrome" });

    const failing = build({ "POST /extension/sessions": [429, { detail: "Too many attempts." }] });
    await expect(failing.actions.connect("Chrome")).rejects.toThrow("Too many attempts.");
  });
});
