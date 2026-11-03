import { describe, expect, it } from "vitest";

import { formatAgo, parseUtc } from "./dates";

describe("dates", () => {
  it("reads the API's naive timestamps as UTC", () => {
    expect(parseUtc("2026-11-03T19:08:48.274272").toISOString()).toBe("2026-11-03T19:08:48.274Z");
    expect(parseUtc("2026-11-03T19:08:48Z").toISOString()).toBe("2026-11-03T19:08:48.000Z");
    expect(parseUtc("garbage")).toBeNull();
    expect(parseUtc(null)).toBeNull();
  });

  it("says how long ago", () => {
    const now = Date.parse("2026-11-03T20:00:00Z");
    expect(formatAgo("2026-11-03T19:59:50", now)).toBe("just now");
    expect(formatAgo("2026-11-03T19:00:00", now)).toMatch(/hour/);
    expect(formatAgo("2026-10-31T20:00:00", now)).toMatch(/3 days ago/);
  });
});
