import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

const { dispatchMenuAction, onMenuAction } = await import("./menu");

const withDialog = (open) => vi.stubGlobal("document", { querySelector: () => (open ? {} : null) });

afterEach(() => vi.unstubAllGlobals());

describe("menu actions", () => {
  it("run the registered handler, and only while it is registered", () => {
    withDialog(false);
    const handler = vi.fn();
    const stop = onMenuAction("new-login", handler);
    expect(dispatchMenuAction("new-login")).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    stop();
    expect(dispatchMenuAction("new-login")).toBe(false);
    expect(dispatchMenuAction("unknown")).toBe(false);
  });

  it("let the newest registration win and survive an older one's cleanup", () => {
    withDialog(false);
    const older = vi.fn();
    const newer = vi.fn();
    const stopOlder = onMenuAction("find", older);
    const stopNewer = onMenuAction("find", newer);
    stopOlder();
    dispatchMenuAction("find");
    expect(older).not.toHaveBeenCalled();
    expect(newer).toHaveBeenCalledTimes(1);
    stopNewer();
  });

  it("wait while a dialog is open, except locking and the theme", () => {
    withDialog(true);
    const add = vi.fn();
    const lock = vi.fn();
    const theme = vi.fn();
    const stops = [
      onMenuAction("new-login", add),
      onMenuAction("lock", lock),
      onMenuAction("toggle-theme", theme),
    ];
    expect(dispatchMenuAction("new-login")).toBe(false);
    dispatchMenuAction("lock");
    dispatchMenuAction("toggle-theme");
    expect(add).not.toHaveBeenCalled();
    expect(lock).toHaveBeenCalledTimes(1);
    expect(theme).toHaveBeenCalledTimes(1);
    stops.forEach((stop) => stop());
  });
});
