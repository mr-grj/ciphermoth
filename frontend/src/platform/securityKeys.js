import { invoke } from "@tauri-apps/api/core";

import { fromBase64Url, toBase64Url } from "../lib/base64url";
import { IS_DESKTOP } from "./index";

// FIDO2 security keys (a YubiKey, for example) as a second factor. In a browser
// this is WebAuthn with the PRF extension; the desktop app talks to the key over
// USB through its core, because its web view has no WebAuthn. Both return the
// same structures, which the server verifies.
//
// The key always verifies its user (userVerification "required": its PIN, or a
// fingerprint on keys that have one). A key returns a different PRF secret with
// and without verification, and browsers verify a key with a PIN whenever PRF is
// asked for, so every client must ask the same way.

export class SecurityKeyCancelled extends Error {}

const IP_ADDRESS = /^(\d+\.){3}\d+$|^\[.*\]$/;

// What the UI shows while a key is being asked: ``{ message }``, and on the
// desktop app, which draws its own prompt (browsers show theirs), ``pin`` while
// it asks for the key's PIN.
const listeners = new Set();
let waiting = null;

const setWaiting = (state) => {
  waiting = state;
  for (const listener of listeners) listener(state);
};

export const onSecurityKeyPrompt = (listener) => {
  listeners.add(listener);
  listener(waiting);
  return () => listeners.delete(listener);
};

export const cancelSecurityKey = () =>
  IS_DESKTOP ? invoke("security_key_cancel").catch(() => {}) : Promise.resolve();

const asking = async (message, work) => {
  setWaiting({ message });
  try {
    return await work();
  } finally {
    setWaiting(null);
  }
};

const askPin = (error) =>
  new Promise((resolve, reject) => {
    setWaiting({
      message: "Enter your security key's PIN",
      pin: {
        error,
        submit: resolve,
        cancel: () => reject(new SecurityKeyCancelled("Cancelled.")),
      },
    });
  });

// One operation in the desktop app: the PIN first (the key checks it and counts
// wrong tries), then the touch. ``session.pin`` lets the two steps of a
// registration, which use the same key, ask for it once.
const nativeRun = async (command, args, message, session = {}) => {
  let error = null;
  try {
    for (;;) {
      if (session.pin === undefined) session.pin = await askPin(error);
      setWaiting({ message });
      try {
        return await invoke(command, { ...args, pin: session.pin || null });
      } catch (failure) {
        if (failure !== "pin-invalid") throw nativeError(failure);
        error = "That PIN is not right. Try again.";
        session.pin = undefined;
      }
    }
  } finally {
    setWaiting(null);
  }
};

export const securityKeySupport = async () => {
  if (IS_DESKTOP) return { available: true };
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    return {
      available: false,
      reason: "Security keys need a browser with WebAuthn, over HTTPS or on localhost.",
    };
  }
  if (IP_ADDRESS.test(window.location.hostname)) {
    return {
      available: false,
      reason: "Security keys need a host name, not an IP address. Open CipherMoth by name.",
    };
  }
  try {
    const capabilities = await PublicKeyCredential.getClientCapabilities?.();
    if (capabilities && capabilities["extension:prf"] === false) {
      return {
        available: false,
        reason:
          "This browser cannot use a security key for encryption. Use Chrome, Edge or Firefox, or the desktop app.",
      };
    }
  } catch {
    // Older browsers without getClientCapabilities find out when registering.
  }
  return { available: true };
};

const browserError = (error) => {
  // A dismissed prompt and a timeout look the same, by design of WebAuthn.
  if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
    return new SecurityKeyCancelled("Cancelled.");
  }
  if (error?.name === "InvalidStateError") {
    return new Error("This security key is already registered.");
  }
  if (error?.name === "SecurityError") {
    return new Error("This page's address cannot use security keys. Open CipherMoth by host name.");
  }
  return error instanceof Error ? error : new Error("The security key could not be used.");
};

const nativeError = (message) =>
  message === "cancelled"
    ? new SecurityKeyCancelled("Cancelled.")
    : new Error(String(message || "The security key could not be used."));

const hostMatches = (rpId) => {
  const host = window.location.hostname;
  return host === rpId || host.endsWith(`.${rpId}`);
};

// The registered keys this client can ask: a browser only those registered on
// this host name (WebAuthn scopes credentials to it), the desktop app all of them.
export const usableKeys = (keys) => (IS_DESKTOP ? keys : keys.filter((k) => hostMatches(k.rp_id)));

const browserAnswer = async (challenge) => {
  const usable = usableKeys(challenge.keys);
  if (!usable.length) {
    const where = challenge.keys[0]?.rp_id;
    throw new Error(
      `Your security keys were registered at ${where}. Open CipherMoth at that address, or use your recovery code.`
    );
  }
  const rpId = usable[0].rp_id;
  const group = usable.filter((k) => k.rp_id === rpId);
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64Url(challenge.challenge),
      rpId,
      allowCredentials: group.map((k) => ({
        type: "public-key",
        id: fromBase64Url(k.credential_id),
      })),
      userVerification: "required",
      timeout: challenge.timeout_ms,
      hints: ["security-key"],
      extensions: {
        prf: {
          evalByCredential: Object.fromEntries(
            group.map((k) => [k.credential_id, { first: fromBase64Url(k.prf_salt) }])
          ),
        },
      },
    },
  });
  const secret = credential.getClientExtensionResults().prf?.results?.first;
  if (!secret || secret.byteLength !== 32) {
    throw new Error(
      "This browser did not get the key's secret. Use Chrome, Edge or Firefox, or the desktop app."
    );
  }
  return {
    credential_id: toBase64Url(credential.rawId),
    client_data_json: toBase64Url(credential.response.clientDataJSON),
    authenticator_data: toBase64Url(credential.response.authenticatorData),
    signature: toBase64Url(credential.response.signature),
    prf_output: toBase64Url(secret),
  };
};

// An answer from a registered key to a challenge from the server.
export const securityKeyAnswer = (challenge, message = "Touch your security key", session) => {
  if (IS_DESKTOP) return nativeRun("security_key_answer", { challenge }, message, session);
  return asking(message, async () => {
    try {
      return await browserAnswer(challenge);
    } catch (error) {
      throw browserError(error);
    }
  });
};

const browserCreate = async (options) => {
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: options.rp_name },
      user: {
        id: fromBase64Url(options.user_id),
        name: "CipherMoth vault",
        displayName: "CipherMoth vault",
      },
      challenge: fromBase64Url(options.challenge),
      pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key", alg })),
      excludeCredentials: options.exclude_credentials.map((id) => ({
        type: "public-key",
        id: fromBase64Url(id),
      })),
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
        residentKey: "discouraged",
        requireResidentKey: false,
        userVerification: "required",
      },
      hints: ["security-key"],
      attestation: "none",
      timeout: options.timeout_ms,
      extensions: { prf: {} },
    },
  });
  if (!credential.getClientExtensionResults().prf?.enabled) {
    throw new Error(
      "This key cannot protect the vault: it lacks the FIDO2 hmac-secret feature, or this browser cannot use it. A YubiKey 5 in Chrome, Edge or Firefox works."
    );
  }
  return {
    credential_id: toBase64Url(credential.rawId),
    rp_id: window.location.hostname,
    registration: {
      client_data_json: toBase64Url(credential.response.clientDataJSON),
      attestation_object: toBase64Url(credential.response.attestationObject),
    },
  };
};

// Register a new key: create its credential, then ask it once for its secret
// for the salt the server chose. ``onStep`` hears "touch-again" in between.
export const registerSecurityKey = async (options, onStep = () => {}) => {
  const message = "Insert your new security key and touch it";
  const session = {};
  const created = IS_DESKTOP
    ? await nativeRun("security_key_register", { options }, message, session)
    : await asking(message, async () => {
        try {
          return await browserCreate(options);
        } catch (error) {
          throw browserError(error);
        }
      });
  onStep("touch-again");
  const assertion = await securityKeyAnswer(
    {
      challenge: options.secret_challenge,
      timeout_ms: options.timeout_ms,
      keys: [
        {
          credential_id: created.credential_id,
          rp_id: created.rp_id,
          prf_salt: options.prf_salt,
        },
      ],
    },
    "Touch your new security key once more",
    session
  );
  return { registration: created.registration, assertion };
};
