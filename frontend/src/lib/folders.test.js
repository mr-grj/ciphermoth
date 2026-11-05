import { describe, expect, it } from "vitest";

import {
  MAX_FOLDER_LENGTH,
  bestRow,
  existingFolder,
  folderCounts,
  folderLength,
  folderProblem,
  matchingFolders,
  pickerRows,
  shortFolder,
  undoMoves,
} from "./folders";

describe("folder names", () => {
  it("refuses empty and blank names", () => {
    for (const input of ["", "   ", "\t\n"]) {
      expect(folderProblem(input)).toBe("Type a folder name.");
    }
  });

  it("allows up to the server's limit after trimming, counting code points", () => {
    expect(folderProblem("F".repeat(MAX_FOLDER_LENGTH))).toBeNull();
    expect(folderProblem(`  ${"F".repeat(MAX_FOLDER_LENGTH)}  `)).toBeNull();
    expect(folderProblem("F".repeat(MAX_FOLDER_LENGTH + 1))).toBe(
      "Folder names can be up to 200 characters."
    );
    // An emoji is two UTF-16 units but one character to the server.
    const emoji = "🦋".repeat(MAX_FOLDER_LENGTH);
    expect(emoji.length).toBe(2 * MAX_FOLDER_LENGTH);
    expect(folderLength(emoji)).toBe(MAX_FOLDER_LENGTH);
    expect(folderProblem(emoji)).toBeNull();
  });

  it("finds the existing folder a typed name means", () => {
    const folders = ["Work", "work", "Personal"];
    expect(existingFolder(" work ", folders)).toBe("work");
    expect(existingFolder("WORK", folders)).toBe("Work");
    expect(existingFolder("personal", folders)).toBe("Personal");
    expect(existingFolder("Pers", folders)).toBeNull();
    expect(existingFolder("  ", folders)).toBeNull();
  });

  it("filters folders by a case-insensitive substring", () => {
    const folders = ["Banking", "Work / Banking", "Home"];
    expect(matchingFolders("bank", folders)).toEqual(["Banking", "Work / Banking"]);
    expect(matchingFolders("  ", folders)).toEqual(folders);
    expect(matchingFolders("zzz", folders)).toEqual([]);
  });

  it("counts entries per folder", () => {
    const counts = folderCounts([
      { folder: "A" },
      { folder: "A" },
      { folder: null },
      { folder: "" },
      { folder: "B" },
    ]);
    expect([...counts]).toEqual([
      ["A", 2],
      ["B", 1],
    ]);
  });

  it("shortens long names without splitting a character", () => {
    expect(shortFolder("Work")).toBe("Work");
    expect(shortFolder("x".repeat(40))).toBe("x".repeat(40));
    expect(shortFolder("x".repeat(41))).toBe(`${"x".repeat(39)}…`);
    const short = shortFolder("🦋".repeat(50), 10);
    expect([...short]).toHaveLength(10);
    expect(short).toBe(`${"🦋".repeat(9)}…`);
  });
});

describe("undoing a move", () => {
  it("groups the moved entries by the folder they came from", () => {
    const entries = [
      { password_name: "a", folder: "Home" },
      { password_name: "b", folder: null },
      { password_name: "c", folder: "Home" },
      { password_name: "d", folder: "Work" },
      { password_name: "e", folder: "" },
    ];
    expect(undoMoves(entries, "Work")).toEqual([
      { folder: "Home", names: ["a", "c"] },
      { folder: null, names: ["b", "e"] },
    ]);
    expect(undoMoves(entries, null)).toEqual([
      { folder: "Home", names: ["a", "c"] },
      { folder: "Work", names: ["d"] },
    ]);
    expect(undoMoves([{ password_name: "x", folder: "W" }], "W")).toEqual([]);
  });
});

describe("the move picker", () => {
  const folders = ["Banking", "Work", "Work / Banking"];
  const keys = (rows) => rows.map((row) => row.key);

  it("offers No folder and every folder before anything is typed", () => {
    expect(keys(pickerRows("", folders))).toEqual([
      "none",
      "folder:Banking",
      "folder:Work",
      "folder:Work / Banking",
    ]);
    expect(bestRow("", folders, pickerRows("", folders))).toBeNull();
  });

  it("puts existing matches first and a new folder last", () => {
    const rows = pickerRows("wor", folders);
    expect(keys(rows)).toEqual(["folder:Work", "folder:Work / Banking", "new"]);
    expect(rows.at(-1)).toEqual({ key: "new", folder: "wor", isNew: true });
    expect(bestRow("wor", folders, rows).folder).toBe("Work");
  });

  it("offers no new folder for a name that exists in another case", () => {
    const rows = pickerRows(" BANKING ", folders);
    expect(keys(rows)).toEqual(["folder:Banking", "folder:Work / Banking"]);
    expect(bestRow(" BANKING ", folders, rows).folder).toBe("Banking");
  });

  it("creates a folder for a new name", () => {
    const rows = pickerRows("  Streaming ", folders);
    expect(rows).toEqual([{ key: "new", folder: "Streaming", isNew: true }]);
    expect(bestRow("  Streaming ", folders, rows).isNew).toBe(true);
  });

  it("offers nothing to create for a blank or over-long name", () => {
    expect(keys(pickerRows("   ", folders))).toContain("none");
    expect(pickerRows("x".repeat(201), folders)).toEqual([]);
    expect(bestRow("x".repeat(201), folders, [])).toBeNull();
  });

  it("highlights nothing when the typed folder is where the entries already are", () => {
    // The page leaves the current folder out of the pickable rows.
    const pickable = pickerRows("work", folders).filter((row) => row.folder !== "Work");
    expect(keys(pickable)).toEqual(["folder:Work / Banking"]);
    expect(bestRow("work", folders, pickable)).toBeNull();
  });
});
