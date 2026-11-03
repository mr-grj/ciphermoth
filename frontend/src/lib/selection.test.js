import { describe, expect, it } from "vitest";

import {
  entriesWord,
  gridSelectionModel,
  mergeSelection,
  pruneSelection,
  selectedAmong,
} from "./selection";

const include = (...ids) => ({ type: "include", ids: new Set(ids) });
const exclude = (...ids) => ({ type: "exclude", ids: new Set(ids) });

describe("selectedAmong", () => {
  it("reads include models against the visible rows only", () => {
    expect(selectedAmong(include("a", "z"), ["a", "b"])).toEqual(["a"]);
  });

  it("never lets an exclude model reach rows that were not shown", () => {
    expect(selectedAmong(exclude("b"), ["a", "b", "c"])).toEqual(["a", "c"]);
    expect(selectedAmong(exclude(), [])).toEqual([]);
  });

  it("treats a missing model as nothing selected", () => {
    expect(selectedAmong(undefined, ["a"])).toEqual([]);
  });
});

describe("mergeSelection", () => {
  it("keeps rows hidden by a filter selected", () => {
    const next = mergeSelection(new Set(["hidden", "a"]), ["a", "b"], include("b"));
    expect([...next].sort()).toEqual(["b", "hidden"]);
  });

  it("selects every visible row on select-all, and only those", () => {
    const next = mergeSelection(new Set(["hidden"]), ["a", "b"], exclude());
    expect([...next].sort()).toEqual(["a", "b", "hidden"]);
  });

  it("clears only the visible rows when select-all is unticked", () => {
    const next = mergeSelection(new Set(["hidden", "a", "b"]), ["a", "b"], include());
    expect([...next]).toEqual(["hidden"]);
  });

  it("keeps selections on other pages, which the grid still holds as rows", () => {
    const rows = ["a", "b", "c", "d"];
    const page1 = mergeSelection(new Set(), rows, include("a"));
    const page2 = mergeSelection(page1, rows, include("a", "d"));
    expect([...page2].sort()).toEqual(["a", "d"]);
  });
});

describe("pruneSelection", () => {
  it("drops ids that no longer exist", () => {
    expect([...pruneSelection(new Set(["a", "gone"]), ["a", "b"])]).toEqual(["a"]);
  });

  it("returns the same set when nothing changed", () => {
    const selected = new Set(["a"]);
    expect(pruneSelection(selected, ["a", "b"])).toBe(selected);
  });
});

describe("gridSelectionModel", () => {
  it("shows the grid only the visible part of the selection", () => {
    const model = gridSelectionModel(new Set(["a", "hidden"]), ["a", "b"]);
    expect(model.type).toBe("include");
    expect([...model.ids]).toEqual(["a"]);
  });
});

describe("entriesWord", () => {
  it("pluralises", () => {
    expect(entriesWord(1)).toBe("1 entry");
    expect(entriesWord(3)).toBe("3 entries");
  });
});
