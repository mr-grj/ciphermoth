import { beforeEach, describe, expect, it, vi } from "vitest";
import { createStore } from "easy-peasy";

vi.mock("../platform", () => ({ IS_DESKTOP: true }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../lib/updateCheck", () => ({ getUpdateStatus: vi.fn() }));
vi.mock("../api/client", () => ({ default: { get: vi.fn() } }));
import { invoke } from "@tauri-apps/api/core";
import { getUpdateStatus } from "../lib/updateCheck";
import Updates from "./updates";

describe("desktop update checks", () => {
  beforeEach(() => vi.clearAllMocks());
  it("uses only the native fixed-source command and retains confirmation details", async () => {
    const status = {
      current: "3.1.0",
      latest: "3.2.0",
      notes: "Fixes",
      updateAvailable: true,
      canInstall: true,
      releaseUrl: "https://github.com/mr-grj/ciphermoth/releases/tag/v3.2.0",
    };
    invoke.mockResolvedValue(status);
    const store = createStore(Updates);
    await store.getActions().checkForUpdates();
    expect(invoke).toHaveBeenCalledExactlyOnceWith("update_check");
    expect(getUpdateStatus).not.toHaveBeenCalled();
    expect(store.getState()).toMatchObject({ ...status, checking: false });
    // Detecting an update never starts an installation.
    expect(invoke.mock.calls.some(([name]) => name === "update_install")).toBe(false);
  });
  it("keeps the vault usable when GitHub is unreachable", async () => {
    invoke.mockRejectedValue(new Error("Offline"));
    const store = createStore(Updates);
    await expect(store.getActions().checkForUpdates()).resolves.toBeNull();
    expect(store.getState()).toMatchObject({ checking: false, updateAvailable: false });
  });
  it("retains the Debian manual-update distinction", async () => {
    invoke.mockResolvedValue({
      current: "3.1.0",
      latest: "3.2.0",
      updateAvailable: true,
      canInstall: false,
    });
    const store = createStore(Updates);
    await store.getActions().checkForUpdates();
    expect(store.getState()).toMatchObject({ updateAvailable: true, canInstall: false });
  });
});
