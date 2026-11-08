// A pairing the app refuses before there is a code (the app locked, pairing
// another browser) is reported once, to the caller. It used to be kept for the
// next status as well: the settings showed it twice, and again after unlocking.

import { afterEach, describe, expect, it, vi } from "vitest";

const refusingApp = (code: string) => {
  const sent: unknown[] = [];
  const connectNative = vi.fn(() => {
    const listeners: ((message: unknown) => void)[] = [];
    return {
      onMessage: { addListener: (f: (message: unknown) => void) => listeners.push(f) },
      onDisconnect: { addListener: () => undefined },
      postMessage: (message: { t: string }) => {
        sent.push(message);
        if (message.t === "pair_commit")
          queueMicrotask(() => listeners.forEach((f) => f({ t: "refused", code })));
      },
      disconnect: vi.fn(),
    };
  });
  vi.stubGlobal("chrome", {
    runtime: { id: "test", connectNative, getURL: (p: string) => `chrome-extension://test/${p}` },
    permissions: { contains: async () => true },
  });
  return { sent, connectNative };
};

afterEach(() => vi.unstubAllGlobals());

describe("a pairing refused before the code", () => {
  it("rejects with the app's reason and keeps nothing to report again", async () => {
    const app = refusingApp("locked");
    vi.resetModules();
    const desktop = await import("../../src/background/desktop");
    await expect(desktop.startPairing("Brave")).rejects.toMatchObject({
      code: "locked",
      message: desktop.MESSAGES.locked,
    });
    expect(app.sent).toEqual([expect.objectContaining({ t: "pair_commit", browser: "Brave" })]);
    expect(desktop.pairingState()).toBeNull();
  });
});
