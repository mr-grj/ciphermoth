import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const alarms: { name: string; when: number }[] = [];
const memory = new Map<string, unknown>();

beforeEach(() => {
  alarms.length = 0;
  memory.clear();
  vi.stubGlobal("chrome", {
    alarms: {
      create: async (name: string, info: { when: number }) => alarms.push({ name, ...info }),
    },
    storage: {
      session: {
        get: async (key: string) => ({ [key]: memory.get(key) }),
        set: async (items: Record<string, unknown>) =>
          Object.entries(items).forEach(([k, v]) => memory.set(k, v)),
        remove: async (key: string) => memory.delete(key),
      },
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("clipboard timer", () => {
  it("keeps only a digest and clears 30 s after the copy", async () => {
    const { scheduleClear, CLIPBOARD_ALARM } = await import("../../src/background/clipboard");
    const before = Date.now();
    await scheduleClear("ab".repeat(32));
    expect(memory.get("clipboard")).toEqual({ digest: "ab".repeat(32) });
    expect(alarms).toHaveLength(1);
    expect(alarms[0]?.name).toBe(CLIPBOARD_ALARM);
    expect(alarms[0]!.when - before).toBeGreaterThanOrEqual(30_000);
    expect(alarms[0]!.when - before).toBeLessThan(31_000);
  });

  it("ignores anything that is not a SHA-256 digest", async () => {
    const { scheduleClear } = await import("../../src/background/clipboard");
    for (const bad of ["", "hunter2", "AB".repeat(32), "ab".repeat(33)]) await scheduleClear(bad);
    expect(alarms).toHaveLength(0);
    expect(memory.size).toBe(0);
  });
});

describe("clearing", () => {
  const fakeDom = (clipboard: { text: string }) => {
    const listeners = new Set<
      (e: {
        clipboardData: { setData: (t: string, v: string) => void };
        preventDefault: () => void;
      }) => void
    >();
    vi.stubGlobal("navigator", {
      clipboard: {
        readText: async () => clipboard.text,
        writeText: async (value: string) => {
          clipboard.text = value;
        },
      },
    });
    vi.stubGlobal("document", {
      addEventListener: (_: string, fn: never) => listeners.add(fn),
      removeEventListener: (_: string, fn: never) => listeners.delete(fn),
      execCommand: (command: string) => {
        if (command !== "copy") return false;
        listeners.forEach((fn) =>
          fn({
            clipboardData: { setData: (_t, v) => (clipboard.text = v) },
            preventDefault: () => {},
          })
        );
        return true;
      },
    });
  };

  it("never wipes a later copy when it may read the clipboard", async () => {
    const { clearClipboard } = await import("../../src/offscreen/clipboard-core");
    const { sha256Hex } = await import("../../src/shared/browser");
    const clipboard = { text: "something the user copied later" };
    fakeDom(clipboard);
    const digest = await sha256Hex("the password");
    expect(await clearClipboard({ digest, onlyOurs: true })).toBe(false);
    expect(clipboard.text).toBe("something the user copied later");

    clipboard.text = "the password";
    expect(await clearClipboard({ digest, onlyOurs: true })).toBe(true);
    expect(clipboard.text).toBe("");
  });

  it("clears unconditionally when it may not read", async () => {
    const { clearClipboard } = await import("../../src/offscreen/clipboard-core");
    const clipboard = { text: "anything" };
    fakeDom(clipboard);
    expect(await clearClipboard({ digest: "00".repeat(32), onlyOurs: false })).toBe(true);
    expect(clipboard.text).toBe("");
  });
});
