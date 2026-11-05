// Quick filters of the vault list, React-free so they are testable. Several active
// filters narrow the list together: an entry must match every one of them.

export const hasNotes = (entry) => entry.kind !== "note" && !!entry.description?.trim();
export const attachmentCount = (entry) => entry.attachment_count ?? 0;

export const ENTRY_FILTERS = [
  { key: "favorites", label: "Favorites", test: (entry) => !!entry.favorite },
  { key: "secure-notes", label: "Secure notes", test: (entry) => entry.kind === "note" },
  { key: "notes", label: "Logins with notes", test: hasNotes },
  { key: "attachments", label: "With attachments", test: (entry) => attachmentCount(entry) > 0 },
  { key: "totp", label: "With 2FA", test: (entry) => !!entry.totp_secret },
];

const byKey = new Map(ENTRY_FILTERS.map((filter) => [filter.key, filter]));

export const applyEntryFilters = (entries, active) => {
  const tests = [...active].map((key) => byKey.get(key)?.test).filter(Boolean);
  return tests.length ? entries.filter((entry) => tests.every((test) => test(entry))) : entries;
};

// How many entries each filter would match on its own.
export const entryFilterCounts = (entries) =>
  new Map(
    ENTRY_FILTERS.map((filter) => [
      filter.key,
      entries.filter((entry) => filter.test(entry)).length,
    ])
  );

export const entryFilterLabels = (active) =>
  ENTRY_FILTERS.filter((filter) => active.has(filter.key)).map((filter) => filter.label);
