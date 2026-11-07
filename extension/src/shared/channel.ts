// The paired channel to the CipherMoth desktop app, in WebCrypto (the same
// construction as desktop/src-tauri/extension-link/src/channel.rs; both are
// checked against testdata/vectors/extension-channel.json).
//
// Pairing: an X25519 exchange where this side commits to its key before it
// learns the app's, so a process in the middle cannot pick keys that make both
// sides show the same six digits. The pairing key is kept as a non-extractable
// HKDF key; it never encrypts anything itself. Each connection derives a fresh
// AES-256-GCM key (also non-extractable) from new nonces of both sides, and every
// message carries the next counter of its direction in the nonce and the
// associated data, so replayed, reordered or reflected messages fail.

export const LABEL = "ciphermoth/extension/v1";
export const TO_APP = 0x01;
export const TO_EXTENSION = 0x02;

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;
const encoder = new TextEncoder();

// WebCrypto is typed for ArrayBuffer-backed views only.
type Bytes = Uint8Array<ArrayBuffer>;

export const bytes = (length: number): Bytes =>
  globalThis.crypto.getRandomValues(new Uint8Array(length));

export const concat = (...parts: Uint8Array[]): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const lp = (data: Uint8Array): Bytes => {
  const out = new Uint8Array(2 + data.length);
  new DataView(out.buffer).setUint16(0, data.length);
  out.set(data, 2);
  return out;
};

const text = (value: string): Bytes => encoder.encode(value);

const sha256 = async (data: Bytes): Promise<Bytes> =>
  new Uint8Array(await subtle().digest("SHA-256", data));

export const toBase64Url = (data: Uint8Array): string => {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Unpadded base64url of exactly `length` bytes, or null.
export const fromBase64Url = (value: unknown, length?: number): Bytes | null => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1)
    return null;
  if (value.length > 128 * 1024) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  let binary: string;
  try {
    binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  } catch {
    return null;
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (toBase64Url(out) !== value) return null;
  return length === undefined || out.length === length ? out : null;
};

export const supportsX25519 = async (): Promise<boolean> => {
  try {
    await subtle().generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
};

export interface Exchange {
  privateKey: CryptoKey;
  publicKey: Bytes;
}

export const newExchange = async (): Promise<Exchange> => {
  const pair = (await subtle().generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  return {
    privateKey: pair.privateKey,
    publicKey: new Uint8Array(await subtle().exportKey("raw", pair.publicKey)),
  };
};

export const commit = (publicKey: Bytes, nonce: Bytes): Promise<Bytes> =>
  sha256(concat(lp(text(`${LABEL}/commit`)), publicKey, nonce));

export const transcript = (
  browser: string,
  extensionPublic: Bytes,
  extensionNonce: Bytes,
  appPublic: Bytes,
  appNonce: Bytes
): Promise<Bytes> =>
  sha256(
    concat(
      lp(text(`${LABEL}/pair`)),
      lp(text(browser)),
      extensionPublic,
      extensionNonce,
      appPublic,
      appNonce
    )
  );

const hkdfBits = async (ikm: CryptoKey, salt: Bytes, info: string, bits: number) =>
  new Uint8Array(
    await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: text(info) }, ikm, bits)
  );

export interface Paired {
  sas: string;
  // Non-extractable: it can only derive connection keys.
  pairingKey: CryptoKey;
}

export class WeakKey extends Error {}

export const finish = async (own: CryptoKey, peerPublic: Bytes, salt: Bytes): Promise<Paired> => {
  let shared: Uint8Array;
  try {
    const peer = await subtle().importKey("raw", peerPublic, { name: "X25519" }, true, []);
    shared = new Uint8Array(
      await subtle().deriveBits({ name: "X25519", public: peer } as EcdhKeyDeriveParams, own, 256)
    );
  } catch {
    // WebCrypto refuses an all-zero result (a low-order point) itself.
    throw new WeakKey("weak key");
  }
  if (shared.every((b) => b === 0)) throw new WeakKey("weak key");
  const ikm = await subtle().importKey("raw", shared as Bytes, "HKDF", false, ["deriveBits"]);
  shared.fill(0);
  const sas = new DataView((await hkdfBits(ikm, salt, `${LABEL}/sas`, 32)).buffer).getUint32(0);
  const raw = await hkdfBits(ikm, salt, `${LABEL}/channel`, 256);
  const pairingKey = await subtle().importKey("raw", raw, "HKDF", false, [
    "deriveBits",
    "deriveKey",
  ]);
  raw.fill(0);
  return { sas: String(sas % 1_000_000).padStart(6, "0"), pairingKey };
};

export const connectionKey = async (
  pairingKey: CryptoKey,
  pairingId: Bytes,
  extensionNonce: Bytes,
  appNonce: Bytes
): Promise<CryptoKey> => {
  const salt = await sha256(
    concat(lp(text(`${LABEL}/connection`)), pairingId, extensionNonce, appNonce)
  );
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: text(`${LABEL}/connection`) },
    pairingKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

const nonceAndAd = (direction: number, counter: number): [Bytes, Bytes] => {
  const nonce = new Uint8Array(12);
  const ad = new Uint8Array(9);
  nonce[0] = direction;
  ad[0] = direction;
  new DataView(nonce.buffer).setBigUint64(4, BigInt(counter));
  new DataView(ad.buffer).setBigUint64(1, BigInt(counter));
  return [nonce, ad];
};

export const seal = async (
  key: CryptoKey,
  direction: number,
  counter: number,
  plaintext: Bytes
): Promise<Bytes> => {
  const [iv, additionalData] = nonceAndAd(direction, counter);
  return new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext)
  );
};

export const open = async (
  key: CryptoKey,
  direction: number,
  counter: number,
  ciphertext: Bytes
): Promise<Bytes> => {
  const [iv, additionalData] = nonceAndAd(direction, counter);
  return new Uint8Array(
    await subtle().decrypt({ name: "AES-GCM", iv, additionalData }, key, ciphertext)
  );
};

export class Refused extends Error {}

// One connection, the extension's side: it sends toward the app and reads
// only the app's next message.
export class Channel {
  private sent = 0;
  private received = 0;
  // Messages are sealed and opened one at a time, in order.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly key: CryptoKey) {}

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const next = this.queue.then(work, work);
    this.queue = next.catch(() => undefined);
    return next;
  }

  seal(plaintext: Bytes): Promise<{ c: number; d: string }> {
    return this.serial(async () => {
      const counter = this.sent++;
      return { c: counter, d: toBase64Url(await seal(this.key, TO_APP, counter, plaintext)) };
    });
  }

  open(counter: unknown, data: unknown): Promise<Bytes> {
    return this.serial(async () => {
      const sealed = fromBase64Url(data);
      if (counter !== this.received || !sealed) throw new Refused("out of order");
      try {
        const plain = await open(this.key, TO_EXTENSION, counter as number, sealed);
        this.received++;
        return plain;
      } catch {
        throw new Refused("not authentic");
      }
    });
  }
}
