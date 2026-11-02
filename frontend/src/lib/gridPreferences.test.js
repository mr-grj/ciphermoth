import { afterEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_PAGE_SIZE, loadPageSize, savePageSize } from "./gridPreferences";

const storage = (initial = {}) => {
  const store = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, value),
  });
};

afterEach(() => vi.unstubAllGlobals());

describe("page size preference", () => {
  it("remembers an offered size", () => {
    storage();
    savePageSize(100);
    expect(loadPageSize()).toBe(100);
  });

  it("ignores a size the grid does not offer", () => {
    storage({ ciphermothVaultPageSize: "7000" });
    expect(loadPageSize()).toBe(DEFAULT_PAGE_SIZE);
  });

  it("works without browser storage", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    });
    expect(loadPageSize()).toBe(DEFAULT_PAGE_SIZE);
    expect(() => savePageSize(50)).not.toThrow();
  });
});
