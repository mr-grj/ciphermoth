import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { stubBrowser } from "../test/globals";
import {
  BiometricCancelled,
  biometricSecret,
  biometricSupport,
  createBiometricCredential,
  ownEnrollment,
  rememberCredential,
} from "./biometrics";

const SECRET = new Uint8Array(32).fill(7);
const SECRET_TEXT = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

const passkeys = (prf, credentials = {}) => {
  vi.stubGlobal("navigator", {
    userAgent: "Macintosh",
    credentials: {
      create: vi.fn(async () => ({
        rawId: new Uint8Array([1, 2, 3]).buffer,
        getClientExtensionResults: () => ({ prf }),
      })),
      get: vi.fn(async () => ({
        getClientExtensionResults: () => ({ prf: { results: { first: SECRET.buffer } } }),
      })),
      ...credentials,
    },
  });
};

const browserWindow = ({ hostname = "vault.example", secure = true } = {}) => {
  vi.stubGlobal("window", { isSecureContext: secure, location: { hostname } });
  window.PublicKeyCredential = true;
  vi.stubGlobal("PublicKeyCredential", {
    isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
  });
  window.PublicKeyCredential = globalThis.PublicKeyCredential;
};

beforeEach(() => {
  vi.unstubAllGlobals();
  stubBrowser();
  const store = new Map();
  vi.stubGlobal("localStorage", {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, value),
    removeItem: (key) => store.delete(key),
  });
});

afterEach(() => vi.unstubAllGlobals());

describe("biometricSupport", () => {
  it("offers passkeys on a secure host name", async () => {
    browserWindow();
    expect(await biometricSupport()).toEqual({ available: true });
  });

  it("explains an insecure origin", async () => {
    browserWindow({ secure: false });
    const support = await biometricSupport();
    expect(support.available).toBe(false);
    expect(support.reason).toMatch(/HTTPS/);
  });

  it("explains an IP address, which cannot own a passkey", async () => {
    browserWindow({ hostname: "192.168.1.20" });
    const support = await biometricSupport();
    expect(support.available).toBe(false);
    expect(support.reason).toMatch(/IP address/);
  });

  it("does not offer a browser that reports no PRF support", async () => {
    browserWindow();
    PublicKeyCredential.getClientCapabilities = async () => ({ "extension:prf": false });
    expect((await biometricSupport()).available).toBe(false);
  });
});

describe("createBiometricCredential", () => {
  it("uses the secret an authenticator returns at creation", async () => {
    passkeys({ enabled: true, results: { first: SECRET.buffer } });
    const created = await createBiometricCredential();
    expect(created.kind).toBe("passkey");
    expect(created.credential_id).toBe("AQID");
    expect(created.secret).toBe(SECRET_TEXT);
    expect(navigator.credentials.get).not.toHaveBeenCalled();
  });

  it("asks once more when creation only reports support", async () => {
    passkeys({ enabled: true });
    expect((await createBiometricCredential()).secret).toBe(SECRET_TEXT);
    expect(navigator.credentials.get).toHaveBeenCalledOnce();
  });

  it("requires user verification on a platform authenticator", async () => {
    passkeys({ enabled: true, results: { first: SECRET.buffer } });
    await createBiometricCredential();
    const { publicKey } = navigator.credentials.create.mock.calls[0][0];
    expect(publicKey.authenticatorSelection).toMatchObject({
      authenticatorAttachment: "platform",
      userVerification: "required",
    });
  });

  it("refuses an authenticator without PRF", async () => {
    passkeys({ enabled: false });
    await expect(createBiometricCredential()).rejects.toThrow(/cannot derive/);
  });

  it("treats a dismissed prompt as a cancel", async () => {
    passkeys(undefined, {
      create: vi.fn(async () => {
        throw new DOMException("dismissed", "NotAllowedError");
      }),
    });
    await expect(createBiometricCredential()).rejects.toBeInstanceOf(BiometricCancelled);
  });
});

describe("biometricSecret", () => {
  const enrollment = { credential_id: "AQID", material: "AAECAw", kind: "passkey" };

  it("asks for the stored credential and salt, with user verification", async () => {
    passkeys({});
    expect(await biometricSecret(enrollment)).toBe(SECRET_TEXT);
    const { publicKey } = navigator.credentials.get.mock.calls[0][0];
    expect(publicKey.userVerification).toBe("required");
    expect([...publicKey.allowCredentials[0].id]).toEqual([1, 2, 3]);
    expect([...publicKey.extensions.prf.eval.first]).toEqual([0, 1, 2, 3]);
  });

  it("refuses a result that is not a 32-byte secret", async () => {
    passkeys(
      {},
      {
        get: vi.fn(async () => ({
          getClientExtensionResults: () => ({ prf: { results: { first: new ArrayBuffer(8) } } }),
        })),
      }
    );
    await expect(biometricSecret(enrollment)).rejects.toThrow(/cannot derive/);
  });
});

describe("ownEnrollment", () => {
  const passkey = { credential_id: "mine", kind: "passkey", material: "x" };
  const other = { credential_id: "theirs", kind: "passkey", material: "x" };

  it("finds only the passkey this browser enrolled", () => {
    expect(ownEnrollment([passkey, other])).toBeNull();
    rememberCredential("mine");
    expect(ownEnrollment([other, passkey])).toBe(passkey);
    rememberCredential(null);
    expect(ownEnrollment([passkey])).toBeNull();
  });

  it("works without browser storage", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    });
    rememberCredential("mine");
    expect(ownEnrollment([passkey])).toBeNull();
  });
});
