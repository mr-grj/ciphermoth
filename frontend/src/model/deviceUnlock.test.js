import { createStore } from "easy-peasy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "../api/client";
import * as biometrics from "../platform/biometrics";
import { routes } from "../test/adapter";
import { stubBrowser } from "../test/globals";
import { getSessionToken } from "../utils";
import DeviceUnlock from "./deviceUnlock";

vi.mock("../platform/biometrics", async (original) => ({
  ...(await original()),
  biometricSecret: vi.fn(),
  biometricSupport: vi.fn(async () => ({ available: true })),
  createBiometricCredential: vi.fn(),
  ownEnrollment: (enrollments) => enrollments[0] ?? null,
  rememberCredential: vi.fn(),
}));

const TOKEN = "kM3x1y8Qe0bWv7c2Z9pL4tR6sN5aH1jD0fG3uY8iO2w";
const STATUS = "/master_password/device-unlock";
const ENROLLED = {
  enrollments: [{ credential_id: "device", kind: "passkey", material: "salt" }],
  password_required: false,
  password_interval_days: 14,
};
const originalAdapter = apiClient.defaults.adapter;

const build = async (table) => {
  apiClient.defaults.adapter = routes({ [`GET ${STATUS}`]: [200, ENROLLED], ...table });
  const store = createStore({ deviceUnlock: DeviceUnlock });
  await store.getActions().deviceUnlock.load();
  return store;
};

beforeEach(() => {
  vi.unstubAllGlobals();
  stubBrowser();
  vi.mocked(biometrics.biometricSecret).mockReset();
  vi.mocked(biometrics.biometricSecret).mockResolvedValue("secret");
});

afterEach(() => {
  apiClient.defaults.adapter = originalAdapter;
});

describe("unlock", () => {
  it("opens a session from the authenticator's secret", async () => {
    const store = await build({
      [`POST ${STATUS}/unlock`]: [200, { valid: true, session_token: TOKEN }],
    });
    expect(await store.getActions().deviceUnlock.unlock()).toBeNull();
    expect(getSessionToken()).toBe(TOKEN);
  });

  it("stays quiet when the prompt is dismissed", async () => {
    const store = await build({});
    biometrics.biometricSecret.mockRejectedValue(new biometrics.BiometricCancelled());
    expect(await store.getActions().deviceUnlock.unlock()).toBeNull();
    expect(getSessionToken()).toBeFalsy();
    expect(store.getState().deviceUnlock.unlocking).toBe(false);
  });

  it("explains changed fingerprints and stops offering the button", async () => {
    const store = await build({});
    biometrics.biometricSecret.mockRejectedValue(new biometrics.BiometricKeyChanged());
    expect(await store.getActions().deviceUnlock.unlock()).toMatch(/fingerprints changed/);
    expect(store.getState().deviceUnlock.keyChanged).toBe(true);
  });

  it("switches to the password when the server says the reminder is due", async () => {
    const store = await build({
      [`POST ${STATUS}/unlock`]: [200, { valid: false, password_required: true }],
    });
    apiClient.defaults.adapter = routes({
      [`POST ${STATUS}/unlock`]: [200, { valid: false, password_required: true }],
      [`GET ${STATUS}`]: [200, { ...ENROLLED, password_required: true }],
    });
    expect(await store.getActions().deviceUnlock.unlock()).toBeNull();
    expect(store.getState().deviceUnlock.passwordRequired).toBe(true);
    expect(getSessionToken()).toBeFalsy();
  });

  it("falls back to the password when the secret opens nothing", async () => {
    const store = await build({
      [`POST ${STATUS}/unlock`]: [200, { valid: false, password_required: false }],
    });
    expect(await store.getActions().deviceUnlock.unlock()).toMatch(/master password/);
  });
});

describe("enroll", () => {
  const credential = { credential_id: "new", kind: "passkey", material: "m", secret: "s" };

  it("surfaces a wrong master password so the credential can be retried", async () => {
    const store = await build({
      [`POST ${STATUS}/enroll`]: [403, { detail: "Incorrect master password." }],
    });
    await expect(
      store.getActions().deviceUnlock.enroll({ credential, masterPassword: "x" })
    ).rejects.toThrow("Incorrect master password.");
    expect(biometrics.rememberCredential).not.toHaveBeenCalled();
  });

  it("remembers the credential and retires the one it replaces", async () => {
    const seen = [];
    const store = await build({});
    apiClient.defaults.adapter = routes(
      {
        [`POST ${STATUS}/enroll`]: [200, ENROLLED],
        [`DELETE ${STATUS}/device`]: [200, ENROLLED],
      },
      seen
    );
    await store.getActions().deviceUnlock.enroll({ credential, masterPassword: "x" });
    expect(biometrics.rememberCredential).toHaveBeenCalledWith("new");
    expect(seen.map((c) => c.method)).toEqual(["post", "delete"]);
    expect(JSON.parse(seen[0].data).master_password).toBe("x");
  });
});
