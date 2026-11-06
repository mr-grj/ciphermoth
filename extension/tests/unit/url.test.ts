import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hostPattern, notNeededBy, permissionOrigins, targetFor } from "../../src/shared/target";
import {
  displayHost,
  normalize,
  normalizeOrigin,
  sameOrigin,
  serverOrigin,
  unicodeHost,
} from "../../src/shared/url";

interface Vectors {
  normalize: { input: string; origin: string | null; note?: string }[];
  match: { page: string; saved: string; subdomains: boolean; match: boolean; note?: string }[];
}

const vectors: Vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../testdata/vectors/url-matching.json"), "utf8")
);

describe("shared URL vectors (testdata/vectors/url-matching.json)", () => {
  it.each(vectors.normalize.map((c) => [c.input, c] as const))("normalize %j", (_, c) => {
    expect(normalize(c.input), c.note).toBe(c.origin);
  });

  it.each(
    vectors.match.filter((c) => !c.subdomains).map((c) => [`${c.page} | ${c.saved}`, c] as const)
  )("exact match %s", (_, c) => {
    expect(sameOrigin(c.page, c.saved), c.note).toBe(c.match);
  });

  it("never matches what the server refuses with subdomains on", () => {
    for (const c of vectors.match.filter((v) => v.subdomains && !v.match)) {
      expect(sameOrigin(c.page, c.saved), `${c.page} | ${c.saved}`).toBe(false);
    }
  });
});

describe("display", () => {
  it("shows hosts like the server's host field", () => {
    expect(displayHost(normalizeOrigin("https://GitHub.com:443/x")!)).toBe("github.com");
    expect(displayHost(normalizeOrigin("http://intranet.test:8080")!)).toBe(
      "http://intranet.test:8080"
    );
  });

  it("decodes punycode for the tooltip only", () => {
    expect(unicodeHost("xn--bcher-kva.de")).toBe("bücher.de");
    expect(unicodeHost("xn--l-7sba6dbr.com")).toBe("раураl.com");
    expect(unicodeHost("github.com")).toBeNull();
    expect(unicodeHost("xn--zz.com")).toBeNull();
  });
});

describe("server addresses", () => {
  it.each([
    ["https://vault.example", "https://vault.example"],
    ["vault.example", "https://vault.example"],
    ["http://localhost:8000", "http://localhost:8000"],
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000"],
    ["http://[::1]:3000", "http://[::1]:3000"],
  ])("accepts %s", (input, origin) => {
    const parsed = serverOrigin(input);
    expect(parsed && normalize(`${parsed.scheme}://${parsed.host}:${parsed.port ?? ""}`)).toBe(
      origin
    );
  });

  it.each(["http://vault.example", "http://192.168.1.5:3000", "ftp://vault", "javascript:x"])(
    "refuses %s",
    (input) => {
      expect(serverOrigin(input)).toBeNull();
    }
  );

  it("derives the API base and asks for exactly the needed origins", () => {
    expect(targetFor("https://vault.example/passwords", null)).toEqual({
      vault: "https://vault.example",
      api: "https://vault.example/api",
    });
    const split = targetFor("http://localhost:3000", "http://localhost:8000");
    expect(split).toEqual({ vault: "http://localhost:3000", api: "http://localhost:8000/api" });
    // Firefox refuses ports in match patterns; a host pattern covers all ports.
    expect(permissionOrigins(split as { vault: string; api: string })).toEqual([
      "http://localhost/*",
    ]);
    expect(
      permissionOrigins(targetFor("https://vault.example:8443", "https://api.example") as never)
    ).toEqual(["https://vault.example/*", "https://api.example/*"]);
    expect(hostPattern("http://[::1]:3000")).toBe("http://[::1]/*");
    for (const pattern of permissionOrigins(split as never)) expect(pattern).not.toMatch(/:\d/);
    expect(
      permissionOrigins(targetFor("https://v.example", "https://v.example/api/") as never)
    ).toEqual(["https://v.example/*"]);
    expect(targetFor("http://vault.example", null)).toMatch(/https/);
    expect(targetFor("https://vault.example", "http://api.example")).toMatch(/https/);
    expect(targetFor("not a url", null)).toMatch(/web address/);
  });

  it("never drops access the stored connection still uses", () => {
    const patterns = (vault: string, api: string | null) =>
      permissionOrigins(targetFor(vault, api) as { vault: string; api: string });
    const held = patterns("https://vault.example", "https://api.example");
    // Saving the same address again and failing (server down) drops nothing.
    expect(notNeededBy(patterns("https://vault.example", "https://api.example"), held)).toEqual([]);
    // Another port of the same host is covered by the same pattern.
    expect(notNeededBy(patterns("https://vault.example:8443", null), held)).toEqual([]);
    // A failed new address drops only what it added.
    expect(notNeededBy(patterns("https://new.example", "https://api.example"), held)).toEqual([
      "https://new.example/*",
    ]);
    // Moving to a new address drops what only the old one used.
    expect(notNeededBy(held, patterns("https://new.example", "https://api.example"))).toEqual([
      "https://vault.example/*",
    ]);
    expect(notNeededBy(patterns("https://vault.example", null), [])).toEqual([
      "https://vault.example/*",
    ]);
  });
});
