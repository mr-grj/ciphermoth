import { invoke } from "@tauri-apps/api/core";

import { IS_DESKTOP } from "./index";

// One interface over the two authenticators that can produce the 32-byte unlock
// secret: the Mac's Secure Enclave in the desktop app, a passkey's PRF output in a
// browser. Each asks for the fingerprint itself; this code never sees one.

const SECRET_BYTES = 32;
const CREDENTIAL_HINT = "ciphermothBiometricCredential";
// The same user handle every time, so turning this on again replaces the old passkey.
const PASSKEY_USER = new TextEncoder().encode("ciphermoth-vault");
const TIMEOUT_MS = 60_000;

export class BiometricCancelled extends Error {}
export class BiometricKeyChanged extends Error {}

const toBase64Url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const fromBase64Url = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));

const readHint = () => {
  try {
    return localStorage.getItem(CREDENTIAL_HINT);
  } catch {
    return null;
  }
};

const writeHint = (credentialId) => {
  try {
    if (credentialId) localStorage.setItem(CREDENTIAL_HINT, credentialId);
    else localStorage.removeItem(CREDENTIAL_HINT);
  } catch {
    // Without the hint this browser just offers the master password.
  }
};

export const biometricLabel = () => {
  const platform = globalThis.navigator?.userAgent ?? "";
  if (/Macintosh/.test(platform)) return "Touch ID";
  if (IS_DESKTOP) return "biometrics";
  if (/iPhone|iPad/.test(platform)) return "Face ID";
  if (/Windows/.test(platform)) return "Windows Hello";
  return "biometrics";
};

const IP_ADDRESS = /^(\d+\.){3}\d+$|^\[.*\]$/;

const passkeySupport = async () => {
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    return { available: false, reason: "Needs a browser with passkeys, over HTTPS or localhost." };
  }
  if (IP_ADDRESS.test(window.location.hostname)) {
    return { available: false, reason: "Passkeys need a host name, not an IP address." };
  }
  const authenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (!authenticator) {
    return { available: false, reason: "No fingerprint, face or PIN unlock on this device." };
  }
  const capabilities = await PublicKeyCredential.getClientCapabilities?.();
  if (capabilities && capabilities["extension:prf"] === false) {
    return { available: false, reason: "This browser cannot derive a key from a passkey." };
  }
  return { available: true };
};

export const biometricSupport = async () => {
  try {
    if (IS_DESKTOP) {
      return (await invoke("biometric_available"))
        ? { available: true }
        : { available: false, reason: "Not available on this device right now." };
    }
    return await passkeySupport();
  } catch {
    return { available: false, reason: "Biometric unlock could not be checked on this device." };
  }
};

const nativeError = (code) => {
  if (code === "cancelled") return new BiometricCancelled();
  if (code === "invalid") return new BiometricKeyChanged();
  return new Error("Biometric unlock could not be used. Your master password still works.");
};

const passkeyError = (error) => {
  // Browsers report a dismissed prompt and a timeout the same way, by design.
  if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
    return new BiometricCancelled();
  }
  return new Error("The passkey could not be used. Your master password still works.");
};

const passkeySecret = async (credentialId, salt) => {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: fromBase64Url(credentialId) }],
      userVerification: "required",
      timeout: TIMEOUT_MS,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first || first.byteLength !== SECRET_BYTES) {
    throw new Error("This passkey cannot derive a key. Your master password still works.");
  }
  return toBase64Url(first);
};

const enrollPasskey = async () => {
  const salt = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: "CipherMoth" },
      user: { id: PASSKEY_USER, name: "CipherMoth vault", displayName: "CipherMoth vault" },
      challenge: randomBytes(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      attestation: "none",
      timeout: TIMEOUT_MS,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const prf = credential.getClientExtensionResults().prf;
  if (!prf?.enabled && !prf?.results?.first) {
    throw new Error("This browser or device cannot derive a key from a passkey.");
  }
  const credentialId = toBase64Url(credential.rawId);
  return {
    credential_id: credentialId,
    kind: "passkey",
    material: toBase64Url(salt),
    // Authenticators that only report support at creation need one more check.
    secret: prf.results?.first
      ? toBase64Url(prf.results.first)
      : await passkeySecret(credentialId, salt),
  };
};

export const createBiometricCredential = async () => {
  if (IS_DESKTOP) {
    try {
      const enrolled = await invoke("biometric_enroll");
      return { ...enrolled, kind: "secure-enclave" };
    } catch (code) {
      throw nativeError(code);
    }
  }
  try {
    return await enrollPasskey();
  } catch (error) {
    throw error?.name && error.name !== "Error" ? passkeyError(error) : error;
  }
};

export const biometricSecret = async ({ credential_id: credentialId, material }) => {
  if (IS_DESKTOP) {
    try {
      return await invoke("biometric_derive", { material });
    } catch (code) {
      throw nativeError(code);
    }
  }
  try {
    return await passkeySecret(credentialId, fromBase64Url(material));
  } catch (error) {
    throw error?.name && error.name !== "Error" ? passkeyError(error) : error;
  }
};

// The enrollment this device can use. A server may hold others, for other browsers,
// and asking a browser for a passkey it does not have only shows a confusing prompt.
export const ownEnrollment = (enrollments) => {
  if (IS_DESKTOP) return enrollments.findLast((e) => e.kind === "secure-enclave") ?? null;
  const hint = readHint();
  return enrollments.find((e) => e.kind === "passkey" && e.credential_id === hint) ?? null;
};

export const rememberCredential = (credentialId) => {
  if (!IS_DESKTOP) writeHint(credentialId);
};
