// Unpadded base64url, the encoding WebAuthn and the API use for binary values.

export const toBase64Url = (bytes) => {
  const view =
    bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(
          bytes.buffer ?? bytes,
          bytes.byteOffset ?? 0,
          bytes.byteLength ?? bytes.length
        );
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const fromBase64Url = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
