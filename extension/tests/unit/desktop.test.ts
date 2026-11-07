import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { MESSAGES } from "../../src/background/desktop";

const RUST = join(import.meta.dirname, "../../../desktop/src-tauri");
const read = (path: string) => readFileSync(join(RUST, path), "utf8");

describe("desktop mode error codes", () => {
  // An unknown code becomes "protocol" ("update both"), which hid an unpaired
  // browser once: every code the app or the host sends must be known here.
  it("knows every refusal of the app and every error of the host", () => {
    const refusals = [
      ...read("extension-link/src/server.rs").matchAll(/refuse\([^,]+, "([a-z_]+)"\)/g),
    ];
    const hostErrors = [...read("native-host/src/main.rs").matchAll(/"code": "([a-z_]+)"/g)];
    const codes = new Set([...refusals, ...hostErrors].map((match) => match[1]!));
    expect(codes.size).toBeGreaterThanOrEqual(10);
    for (const code of codes) expect(MESSAGES, code).toHaveProperty(code);
  });
});
