// Folder names for the move dialog and the entry form, React-free so the rules are
// easy to test. They mirror the server: trimmed, never empty, at most 200 characters.

export const MAX_FOLDER_LENGTH = 200;

// Characters as the server counts them (code points), so an emoji counts once.
export const folderLength = (name) => [...name].length;

export const folderProblem = (input) => {
  const name = input.trim();
  if (!name) return "Type a folder name.";
  const length = folderLength(name);
  if (length > MAX_FOLDER_LENGTH) {
    return `Folder names can be up to ${MAX_FOLDER_LENGTH} characters.`;
  }
  return null;
};

// The existing folder a typed name means, ignoring case and surrounding spaces, so
// "work " lands in "Work" instead of starting a second, almost identical folder.
export const existingFolder = (input, folders) => {
  const wanted = input.trim().toLocaleLowerCase();
  if (!wanted) return null;
  return (
    folders.find((folder) => folder === input.trim()) ??
    folders.find((folder) => folder.toLocaleLowerCase() === wanted) ??
    null
  );
};

export const matchingFolders = (input, folders) => {
  const query = input.trim().toLocaleLowerCase();
  return query ? folders.filter((folder) => folder.toLocaleLowerCase().includes(query)) : folders;
};

export const folderCounts = (entries) => {
  const counts = new Map();
  for (const entry of entries) {
    if (entry.folder) counts.set(entry.folder, (counts.get(entry.folder) ?? 0) + 1);
  }
  return counts;
};

// A folder name short enough for a toast or a sentence.
export const shortFolder = (name, max = 40) => {
  const chars = [...name];
  return chars.length > max
    ? `${chars
        .slice(0, max - 1)
        .join("")
        .trimEnd()}…`
    : name;
};

// The moves that put `entries` back where they were: one per previous folder, so
// Undo can reuse the bulk route. Entries that did not move are left out.
export const undoMoves = (entries, target) => {
  const back = new Map();
  for (const entry of entries) {
    const previous = entry.folder || null;
    if (previous === target) continue;
    if (!back.has(previous)) back.set(previous, []);
    back.get(previous).push(entry.password_name);
  }
  return [...back].map(([folder, names]) => ({ folder, names }));
};

// The rows the move picker offers for `query`: "No folder" while nothing is typed,
// the existing folders that match, then a new folder when the name is new and valid.
export const pickerRows = (query, folders) => {
  const name = query.trim();
  const rows = matchingFolders(query, folders).map((folder) => ({
    key: `folder:${folder}`,
    folder,
  }));
  if (!name) return [{ key: "none", folder: null }, ...rows];
  if (!existingFolder(query, folders) && !folderProblem(query)) {
    rows.push({ key: "new", folder: name, isNew: true });
  }
  return rows;
};

// The row Enter picks among `rows` (the pickable ones) for `query`: the folder typed,
// else the first match (as in a type-ahead), else the new folder. Nothing while the
// query is empty, or when it names a folder that is not pickable (already there).
export const bestRow = (query, folders, rows) => {
  if (!query.trim()) return null;
  const match = existingFolder(query, folders);
  if (match !== null) return rows.find((row) => !row.isNew && row.folder === match) ?? null;
  return rows[0] ?? null;
};
