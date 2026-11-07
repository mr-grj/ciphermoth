import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  Channel,
  Refused,
  WeakKey,
  commit,
  connectionKey,
  finish,
  fromBase64Url,
  newExchange,
  open,
  seal,
  toBase64Url,
  transcript,
} from "../../src/shared/channel";

interface Message {
  direction: number;
  counter: number;
  plaintext: string;
  ciphertext: string;
}

interface Case {
  browser: string;
  extension_private_hex: string;
  app_private_hex: string;
  extension_public: string;
  app_public: string;
  extension_nonce: string;
  app_nonce: string;
  commit: string;
  transcript_hex: string;
  sas: string;
  pairing_id: string;
  hello_extension_nonce: string;
  hello_app_nonce: string;
  messages: Message[];
}

const vectors = JSON.parse(
  readFileSync(join(__dirname, "../../../testdata/vectors/extension-channel.json"), "utf8")
) as {
  cases: Case[];
  refused: { reason: string; direction: number; counter: number; ciphertext: string }[];
  low_order_points: string[];
};

const hex = (value: string) =>
  new Uint8Array(value.match(/../g)!.map((pair) => parseInt(pair, 16)));
const b64 = (value: string) => fromBase64Url(value)!;
const utf8 = (value: string) => new TextEncoder().encode(value);

// X25519 private keys import only as PKCS#8 (RFC 8410).
const importPrivate = (raw: Uint8Array) =>
  crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array([...hex("302e020100300506032b656e04220420"), ...raw]),
    { name: "X25519" },
    true,
    ["deriveBits"]
  );

const publicOf = async (key: CryptoKey) => {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return b64(jwk.x!);
};

const connection = async (vector: Case) => {
  const own = await importPrivate(hex(vector.extension_private_hex));
  const t = await transcript(
    vector.browser,
    b64(vector.extension_public),
    b64(vector.extension_nonce),
    b64(vector.app_public),
    b64(vector.app_nonce)
  );
  const paired = await finish(own, b64(vector.app_public), t);
  const key = await connectionKey(
    paired.pairingKey,
    b64(vector.pairing_id),
    b64(vector.hello_extension_nonce),
    b64(vector.hello_app_nonce)
  );
  return { paired, key, t };
};

describe("the desktop channel against the frozen vectors", () => {
  for (const vector of vectors.cases) {
    it(`reproduces ${vector.browser}`, async () => {
      const own = await importPrivate(hex(vector.extension_private_hex));
      expect(toBase64Url(await publicOf(own))).toBe(vector.extension_public);
      const app = await importPrivate(hex(vector.app_private_hex));
      expect(toBase64Url(await publicOf(app))).toBe(vector.app_public);
      expect(
        toBase64Url(await commit(b64(vector.extension_public), b64(vector.extension_nonce)))
      ).toBe(vector.commit);
      const { paired, key, t } = await connection(vector);
      expect([...t]).toEqual([...hex(vector.transcript_hex)]);
      expect(paired.sas).toBe(vector.sas);
      expect(paired.pairingKey.extractable).toBe(false);
      expect(key.extractable).toBe(false);
      // The app's side derives the same code from its own key.
      const fromApp = await finish(app, b64(vector.extension_public), t);
      expect(fromApp.sas).toBe(vector.sas);

      const channel = new Channel(key);
      for (const message of vector.messages) {
        const sealed = await seal(key, message.direction, message.counter, utf8(message.plaintext));
        expect(toBase64Url(sealed)).toBe(message.ciphertext);
        if (message.direction === 1) {
          expect(await channel.seal(utf8(message.plaintext))).toEqual({
            c: message.counter,
            d: message.ciphertext,
          });
        } else {
          const plain = await channel.open(message.counter, message.ciphertext);
          expect(new TextDecoder().decode(plain)).toBe(message.plaintext);
        }
      }
    });
  }

  it("refuses tampered, replayed, reflected and foreign messages", async () => {
    const { key } = await connection(vectors.cases[0]!);
    for (const refused of vectors.refused) {
      await expect(
        open(key, refused.direction, refused.counter, b64(refused.ciphertext)),
        refused.reason
      ).rejects.toThrow();
    }
  });

  it("refuses low-order points", async () => {
    const own = await newExchange();
    for (const point of vectors.low_order_points) {
      await expect(finish(own.privateKey, b64(point), new Uint8Array(32))).rejects.toThrow(WeakKey);
    }
  });

  it("reads only the next message, in order", async () => {
    const { key } = await connection(vectors.cases[0]!);
    const reply = vectors.cases[0]!.messages.filter((m) => m.direction === 2);
    const channel = new Channel(key);
    await expect(channel.open(1, reply[1]!.ciphertext)).rejects.toThrow(Refused);
    await channel.open(0, reply[0]!.ciphertext);
    await expect(channel.open(0, reply[0]!.ciphertext)).rejects.toThrow(Refused);
    await expect(channel.open(1, "not base64!")).rejects.toThrow(Refused);
    await channel.open(1, reply[1]!.ciphertext);
  });

  it("keeps the exchange key unexportable and checks base64url strictly", async () => {
    const own = await newExchange();
    await expect(crypto.subtle.exportKey("pkcs8", own.privateKey)).rejects.toThrow();
    expect(own.publicKey).toHaveLength(32);
    expect(fromBase64Url("AAA=")).toBeNull();
    expect(fromBase64Url("AA+/")).toBeNull();
    expect(fromBase64Url("AAAA", 3)).toEqual(new Uint8Array(3));
    expect(fromBase64Url("AAAA", 4)).toBeNull();
    expect(fromBase64Url("AAB")).toBeNull(); // non-canonical trailing bits
  });
});
