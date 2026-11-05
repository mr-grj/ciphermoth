import { describe, expect, it } from "vitest";

import { duplicateName, fromControl, isDeleteKey, isHistoryKey } from "./shortcuts";

const key = (k, mods = {}) => ({ key: k, altKey: false, ctrlKey: false, shiftKey: false, ...mods });

describe("isDeleteKey", () => {
  it("accepts Delete, Backspace and Cmd+Backspace", () => {
    expect(isDeleteKey(key("Delete"))).toBe(true);
    expect(isDeleteKey(key("Backspace"))).toBe(true);
    expect(isDeleteKey(key("Backspace", { metaKey: true }))).toBe(true);
  });

  it("leaves modified and other keys alone", () => {
    expect(isDeleteKey(key("Delete", { shiftKey: true }))).toBe(false);
    expect(isDeleteKey(key("Backspace", { altKey: true }))).toBe(false);
    expect(isDeleteKey(key("Backspace", { ctrlKey: true }))).toBe(false);
    expect(isDeleteKey(key("d"))).toBe(false);
  });
});

describe("fromControl", () => {
  it("asks the event target whether it sits in a control", () => {
    expect(fromControl({ target: { closest: () => ({}) } })).toBe(true);
    expect(fromControl({ target: { closest: () => null } })).toBe(false);
    expect(fromControl({ target: {} })).toBe(false);
  });
});

describe("duplicateName", () => {
  it("adds (copy), then numbers further copies", () => {
    expect(duplicateName("GitHub", ["GitHub"])).toBe("GitHub (copy)");
    expect(duplicateName("GitHub", ["GitHub", "GitHub (copy)"])).toBe("GitHub (copy 2)");
    expect(duplicateName("GitHub", ["GitHub (copy)", "GitHub (copy 2)"])).toBe("GitHub (copy 3)");
  });
});

describe("isHistoryKey", () => {
  it("accepts H alone, never with a modifier", () => {
    expect(isHistoryKey(key("h"))).toBe(true);
    expect(isHistoryKey(key("H"))).toBe(true);
    for (const mod of ["altKey", "ctrlKey", "shiftKey", "metaKey"]) {
      expect(isHistoryKey(key("h", { [mod]: true }))).toBe(false);
    }
    expect(isHistoryKey(key("j"))).toBe(false);
  });
});
