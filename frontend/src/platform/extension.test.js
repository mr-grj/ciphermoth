import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

const { formatPairingCode, toExtensionStatus } = await import("./extension");

describe("desktop extension status", () => {
  it("normalizes what the app reports", () => {
    const status = toExtensionStatus({
      enabled: true,
      listening: true,
      browsers: ["Chrome", 3, "Firefox"],
      pairings: [{ id: "abc", browser: "Brave", created: 1_800_000_000, last_used: null }],
      error: null,
    });
    expect(status.browsers).toEqual(["Chrome", "Firefox"]);
    expect(status.pairings).toEqual([
      { id: "abc", browser: "Brave", created: "2027-01-15T08:00:00.000Z", lastUsed: null },
    ]);
  });

  it("is off when the app says nothing usable", () => {
    expect(toExtensionStatus(null)).toEqual({
      enabled: false,
      listening: false,
      browsers: [],
      pairings: [],
      error: null,
    });
  });

  it("formats the pairing code as the popup does, and nothing else", () => {
    expect(formatPairingCode("482913")).toBe("482 913");
    expect(formatPairingCode("004000")).toBe("004 000");
    for (const bad of ["48291", "4829130", "48a913", "", undefined]) {
      expect(formatPairingCode(bad)).toBe("");
    }
  });
});
