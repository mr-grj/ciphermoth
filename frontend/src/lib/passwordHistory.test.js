import { describe, expect, it } from "vitest";

import {
  entrySubtitle,
  formatWhen,
  hasHistory,
  historyTimeline,
  relativeTime,
  restorePayload,
  usedFor,
} from "./passwordHistory";

const entry = {
  id: 3,
  password_name: "Bank",
  kind: "login",
  username: "moth@example.com",
  password_value: "third-Value!",
  url: "https://bank.example/login",
  totp_secret: "JBSWY3DPEHPK3PXP",
  description: "main account",
  tags: ["money"],
  custom_fields: [{ label: "PIN", value: "1234", hidden: true }],
  folder: "Finance",
  favorite: true,
  backed_up: false,
  updated: "2026-11-01T00:00:00Z",
  attachment_count: 2,
  password_history: [
    { value: "second-Value!", changed_at: "2026-10-01T10:00:00+00:00" },
    { value: "third-Value!", changed_at: "2026-06-01T10:00:00+00:00" },
    { value: "first-Value!", changed_at: "2025-01-01T10:52:00+00:00" },
  ],
};

describe("password history", () => {
  it("lists the current password, then each earlier one with its span", () => {
    const rows = historyTimeline(entry);
    expect(rows.map((row) => row.value)).toEqual([
      "third-Value!",
      "second-Value!",
      "third-Value!",
      "first-Value!",
    ]);
    expect(rows[0]).toMatchObject({ current: true, since: new Date("2026-10-01T10:00:00Z") });
    expect(rows[1]).toMatchObject({
      current: false,
      until: new Date("2026-10-01T10:00:00Z"),
      since: new Date("2026-06-01T10:00:00Z"),
      sameAsCurrent: false,
    });
    // A value used again later is marked, so restoring it is not offered twice.
    expect(rows[2].sameAsCurrent).toBe(true);
    // Nobody recorded when the oldest value was set.
    expect(rows[3].since).toBeNull();
    expect(new Set(rows.map((row) => row.key)).size).toBe(rows.length);
  });

  it("copes with an entry without history and with unreadable dates", () => {
    expect(historyTimeline({ password_value: "x" })).toEqual([
      { key: "current", value: "x", current: true, since: null },
    ]);
    const [, row] = historyTimeline({
      password_value: "x",
      password_history: [{ value: "y", changed_at: "not a date" }],
    });
    expect(row.until).toBeNull();
    expect(formatWhen(row.until)).toBe("");
    expect(relativeTime(row.until)).toBe("");
  });

  it("is offered for logins with history only", () => {
    expect(hasHistory(entry)).toBe(true);
    expect(hasHistory({ ...entry, password_history: [] })).toBe(false);
    expect(hasHistory({ ...entry, kind: "note" })).toBe(false);
    expect(hasHistory(null)).toBe(false);
  });

  it("formats dates and spans", () => {
    const when = new Date("2025-01-01T10:52:00Z");
    expect(formatWhen(when, { locale: "en-US", timeZone: "UTC" })).toBe("Jan 1, 2025, 10:52 AM");
    expect(formatWhen(when, { locale: "en-US", timeZone: "UTC", dateStyle: "long" })).toBe(
      "January 1, 2025 at 10:52 AM"
    );
    const now = new Date("2026-11-05T12:00:00Z");
    expect(relativeTime(new Date("2026-11-05T11:59:30Z"), now, "en-US")).toBe("just now");
    expect(relativeTime(new Date("2026-11-04T11:00:00Z"), now, "en-US")).toBe("yesterday");
    expect(relativeTime(new Date("2026-08-01T00:00:00Z"), now, "en-US")).toBe("3 months ago");
    expect(relativeTime(when, now, "en-US")).toBe("last year");
    expect(usedFor(new Date("2026-06-01T00:00:00Z"), new Date("2026-10-01T00:00:00Z"))).toBe(
      "used for 4 months"
    );
    expect(usedFor(new Date("2026-06-01T00:00:00Z"), new Date("2026-06-01T05:00:00Z"))).toBe(
      "used for less than a day"
    );
    expect(usedFor(new Date("2025-01-01T00:00:00Z"), new Date("2026-01-02T00:00:00Z"))).toBe(
      "used for 1 year"
    );
    expect(usedFor(null, when)).toBe("");
  });

  it("restores a value and keeps every other field", () => {
    expect(restorePayload(entry, "second-Value!")).toEqual({
      password: { password_name: "Bank" },
      new_password: {
        password_name: "Bank",
        kind: "login",
        username: "moth@example.com",
        password_value: "second-Value!",
        url: "https://bank.example/login",
        totp_secret: "JBSWY3DPEHPK3PXP",
        description: "main account",
        tags: ["money"],
        custom_fields: [{ label: "PIN", value: "1234", hidden: true }],
        folder: "Finance",
        favorite: true,
      },
    });
    const bare = restorePayload({ password_name: "x", password_value: "a" }, "b");
    expect(bare.new_password).toMatchObject({
      kind: "login",
      username: null,
      tags: [],
      custom_fields: [],
      folder: null,
      favorite: false,
    });
  });

  it("names the entry by username, else the website's host", () => {
    expect(entrySubtitle(entry)).toBe("moth@example.com");
    expect(entrySubtitle({ url: "https://grrajdeanu.technology/x" })).toBe("grrajdeanu.technology");
    expect(entrySubtitle({ url: "bank.example:8443/login" })).toBe("bank.example:8443");
    expect(entrySubtitle({ url: "not a url" })).toBe("not a url");
    expect(entrySubtitle({})).toBe("");
  });
});
