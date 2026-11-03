import { createStore } from "easy-peasy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "../api/client";
import * as keys from "../platform/securityKeys";
import { routes } from "../test/adapter";
import { stubBrowser } from "../test/globals";
import { setSessionToken } from "../utils";
import Security, { confirmation } from "./security";

vi.mock("../platform/securityKeys", async (original) => ({
  ...(await original()),
  securityKeyAnswer: vi.fn(),
  registerSecurityKey: vi.fn(),
  securityKeySupport: vi.fn(async () => ({ available: true })),
}));

const TOKEN = "kM3x1y8Qe0bWv7c2Z9pL4tR6sN5aH1jD0fG3uY8iO2w";
const ANSWER = { credential_id: "old", prf_output: "p" };
const CHALLENGE = { challenge: "c", timeout_ms: 1, keys: [] };
const STATUS = { security_keys: [], security_key_required: true, recovery_code: false };
const originalAdapter = apiClient.defaults.adapter;
let seen;

const build = (required, table = {}) => {
  seen = [];
  apiClient.defaults.adapter = routes(
    {
      "GET /master_password/status": [200, { initialized: true, security_key_required: required }],
      "POST /security/challenge": [200, CHALLENGE],
      ...table,
    },
    seen
  );
  return createStore({ security: Security }).getActions().security;
};

const posted = (url) => JSON.parse(seen.find((config) => config.url === url).data);

beforeEach(() => {
  vi.unstubAllGlobals();
  stubBrowser();
  setSessionToken(TOKEN);
  vi.mocked(keys.securityKeyAnswer).mockReset().mockResolvedValue(ANSWER);
  vi.mocked(keys.registerSecurityKey).mockReset();
});

afterEach(() => {
  apiClient.defaults.adapter = originalAdapter;
});

describe("confirmation", () => {
  it("is the master password alone while no key is required", async () => {
    build(false);
    expect(await confirmation("pw")).toEqual({ master_password: "pw" });
    expect(keys.securityKeyAnswer).not.toHaveBeenCalled();
  });

  it("adds a key's answer to a fresh challenge when one is required", async () => {
    build(true);
    expect(await confirmation("pw")).toEqual({ master_password: "pw", security_key: ANSWER });
    expect(keys.securityKeyAnswer).toHaveBeenCalledWith(CHALLENGE, expect.any(String));
  });
});

describe("addKey", () => {
  const options = { challenge: "r" };
  const registered = { registration: { client_data_json: "x" }, assertion: { prf_output: "n" } };

  it("confirms with an existing key, waits for the swap, then registers the new one", async () => {
    const order = [];
    const actions = build(true, {
      "POST /security/keys/options": [200, options],
      "POST /security/keys": [200, STATUS],
    });
    vi.mocked(keys.securityKeyAnswer).mockImplementation(async () => {
      order.push("confirm");
      return ANSWER;
    });
    vi.mocked(keys.registerSecurityKey).mockImplementation(async () => {
      order.push("register");
      return registered;
    });
    const swapKeys = vi.fn(async () => order.push("swap"));
    await actions.addKey({ name: "Backup", masterPassword: "pw", swapKeys });
    expect(order).toEqual(["confirm", "swap", "register"]);
    expect(posted("/security/keys")).toEqual({
      name: "Backup",
      confirmation: { master_password: "pw", security_key: ANSWER },
      ...registered,
    });
  });

  it("asks for no swap when the first key is added", async () => {
    const actions = build(false, {
      "POST /security/keys/options": [200, options],
      "POST /security/keys": [200, { ...STATUS, security_key_required: true }],
    });
    vi.mocked(keys.registerSecurityKey).mockResolvedValue(registered);
    const swapKeys = vi.fn();
    await actions.addKey({ name: "YubiKey", masterPassword: "pw", swapKeys });
    expect(swapKeys).not.toHaveBeenCalled();
  });

  it("keeps a dismissed key prompt quiet", async () => {
    const actions = build(true);
    vi.mocked(keys.securityKeyAnswer).mockRejectedValue(new keys.SecurityKeyCancelled("x"));
    await expect(
      actions.addKey({ name: "k", masterPassword: "pw", swapKeys: vi.fn() })
    ).rejects.toBeInstanceOf(keys.SecurityKeyCancelled);
  });

  it("shows the server's reason", async () => {
    const actions = build(false, {
      "POST /security/keys/options": [200, options],
      "POST /security/keys": [400, { detail: "This security key is already registered." }],
    });
    vi.mocked(keys.registerSecurityKey).mockResolvedValue(registered);
    await expect(
      actions.addKey({ name: "k", masterPassword: "pw", swapKeys: vi.fn() })
    ).rejects.toThrow("This security key is already registered.");
  });
});

describe("recovery code", () => {
  it("returns the code once and keeps the status", async () => {
    const actions = build(false, {
      "POST /security/recovery-code": [200, { recovery_code: "ABCD", status: STATUS }],
    });
    expect(await actions.createRecoveryCode("pw")).toBe("ABCD");
    expect(posted("/security/recovery-code")).toEqual({ master_password: "pw" });
  });
});

describe("changeMasterPassword", () => {
  it("sends the key's answer with both passwords, then ends the session", async () => {
    const actions = build(true, { "PATCH /master_password/update": [200, {}] });
    await actions.changeMasterPassword({ current: "old", next: "new" });
    expect(posted("/master_password/update")).toEqual({
      master_password: "old",
      new_master_password: "new",
      security_key: ANSWER,
    });
    expect(window.location.replace).toHaveBeenCalledWith("/login");
  });
});
