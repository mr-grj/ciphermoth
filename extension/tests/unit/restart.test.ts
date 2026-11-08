// Chromium leaves chrome.runtime.connectNative out of a service worker that
// started before nativeMessaging was granted (found in Brave, 2026-11-08):
// pairing right after picking the app failed with a TypeError. The background
// restarts itself then, and reopens the settings the restart closed.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

interface FakeChrome {
  local: Record<string, unknown>;
  granted: boolean;
  reload: ReturnType<typeof vi.fn>;
  openOptionsPage: ReturnType<typeof vi.fn>;
  connectNative?: ReturnType<typeof vi.fn>;
}

let fake: FakeChrome;

const install = ({ connectNative = false, granted = true } = {}) => {
  fake = {
    local: {},
    granted,
    reload: vi.fn(),
    openOptionsPage: vi.fn(async () => undefined),
  };
  const area = {
    get: async (key: string | null) =>
      key === null ? { ...fake.local } : key in fake.local ? { [key]: fake.local[key] } : {},
    set: async (items: Record<string, unknown>) => void Object.assign(fake.local, items),
    remove: async (key: string) => void delete fake.local[key],
  };
  const runtime: Record<string, unknown> = {
    id: "test",
    reload: fake.reload,
    openOptionsPage: fake.openOptionsPage,
    getURL: (path: string) => `chrome-extension://test/${path}`,
  };
  if (connectNative) runtime.connectNative = vi.fn();
  vi.stubGlobal("chrome", {
    runtime,
    permissions: { contains: async () => fake.granted, remove: async () => true },
    storage: { local: area, session: area },
    alarms: { clear: async () => true, create: () => undefined },
  });
};

const load = async () => {
  vi.resetModules();
  return {
    desktop: await import("../../src/background/desktop"),
    session: await import("../../src/background/session"),
    restart: await import("../../src/background/restart"),
  };
};

beforeEach(() => vi.useFakeTimers({ now: new Date("2026-11-08T12:00:00Z") }));
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("a worker without connectNative", () => {
  it("restarts itself once it has run a while, and says so", async () => {
    install();
    const { desktop } = await load();
    await vi.advanceTimersByTimeAsync(61_000);
    await expect(desktop.launchApp()).rejects.toMatchObject({ code: "restarting" });
    expect(fake.reload).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(250);
    expect(fake.reload).toHaveBeenCalledOnce();
    expect(fake.local).toEqual({});
  });

  it("does not reload again right after a restart (no loop)", async () => {
    install();
    const { desktop } = await load();
    await expect(desktop.launchApp()).rejects.toMatchObject({ code: "restarting" });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fake.reload).not.toHaveBeenCalled();
  });

  it("asks for the permission when it was taken away", async () => {
    install({ granted: false });
    const { desktop } = await load();
    await vi.advanceTimersByTimeAsync(61_000);
    const error = await desktop.launchApp().catch((e: unknown) => e);
    expect(error).toMatchObject({ code: "no_permission" });
    expect(String((error as Error).message)).toMatch(/permission/);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fake.reload).not.toHaveBeenCalled();
  });
});

describe("picking the app in the settings", () => {
  it("restarts at once and leaves a marker to reopen the settings", async () => {
    install();
    const { session, restart } = await load();
    const status = await session.useDesktop();
    expect(status.mode).toBe("desktop");
    expect(status.phase).toBe("unpaired");
    expect(fake.local[restart.REOPEN_OPTIONS]).toBe(true);
    await vi.advanceTimersByTimeAsync(250);
    expect(fake.reload).toHaveBeenCalledOnce();
  });

  it("does not restart a worker that can already talk to the app", async () => {
    install({ connectNative: true });
    const { session, restart } = await load();
    await session.useDesktop().catch(() => undefined);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fake.reload).not.toHaveBeenCalled();
    expect(fake.local).not.toHaveProperty(restart.REOPEN_OPTIONS);
  });
});

describe("after the restart", () => {
  it("reopens the settings once and removes the marker", async () => {
    install({ connectNative: true });
    const { restart } = await load();
    fake.local[restart.REOPEN_OPTIONS] = true;
    await restart.resumeAfterRestart();
    expect(fake.openOptionsPage).toHaveBeenCalledOnce();
    expect(fake.local).toEqual({});
    await restart.resumeAfterRestart();
    expect(fake.openOptionsPage).toHaveBeenCalledOnce();
  });
});
