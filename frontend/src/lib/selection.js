// Row selection for the vault grids, kept outside the DataGrid so it survives page
// changes, searches and folder filters. The grid only ever sees the visible part of
// it; rows hidden by a filter stay selected until the user clears them.

// The ids the grid's model selects among the visible rows. Select-all can arrive as
// an "exclude" model (every row except these), which must never reach rows the
// grid was not showing.
export const selectedAmong = (model, visibleIds) => {
  const ids = model?.ids ?? new Set();
  if (model?.type === "exclude") return visibleIds.filter((id) => !ids.has(id));
  return visibleIds.filter((id) => ids.has(id));
};

// The new selection after the grid reports `model` while showing `visibleIds`:
// visible rows take the grid's answer, hidden rows keep their previous state.
export const mergeSelection = (previous, visibleIds, model) => {
  const visible = new Set(visibleIds);
  const next = new Set([...previous].filter((id) => !visible.has(id)));
  for (const id of selectedAmong(model, visibleIds)) next.add(id);
  return next;
};

// Drops ids that no longer exist (deleted, renamed, restored elsewhere). Returns
// `selected` itself when nothing changed, so a state setter can skip a render.
export const pruneSelection = (selected, existingIds) => {
  const existing = new Set(existingIds);
  const kept = [...selected].filter((id) => existing.has(id));
  return kept.length === selected.size ? selected : new Set(kept);
};

export const gridSelectionModel = (selected, visibleIds) => ({
  type: "include",
  ids: new Set(visibleIds.filter((id) => selected.has(id))),
});

export const entriesWord = (count) => `${count} ${count === 1 ? "entry" : "entries"}`;
