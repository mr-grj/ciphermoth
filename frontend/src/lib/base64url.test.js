import { describe, expect, it } from "vitest";

import { fromBase64Url, toBase64Url } from "./base64url";

describe("base64url", () => {
  it("round-trips every byte value without padding", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    const text = toBase64Url(bytes);
    expect(text).not.toMatch(/[+/=]/);
    expect(Array.from(fromBase64Url(text))).toEqual(Array.from(bytes));
  });

  it("accepts ArrayBuffers and views", () => {
    const bytes = Uint8Array.from([251, 255, 0]);
    expect(toBase64Url(bytes.buffer)).toBe("-_8A");
    expect(toBase64Url(new DataView(bytes.buffer))).toBe("-_8A");
  });
});
