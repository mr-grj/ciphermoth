// Keyboard shortcuts of the vault grids, React-free so the key handling is testable.

export const IS_MAC =
  typeof navigator !== "undefined" &&
  /mac|iphone|ipad/i.test(navigator.userAgentData?.platform ?? navigator.platform ?? "");

// Mac keyboards label Backspace "delete", so both keys trash; with Alt, Ctrl or Shift
// they keep whatever meaning the system gives them.
export const isDeleteKey = (event) =>
  (event.key === "Delete" || event.key === "Backspace") &&
  !event.altKey &&
  !event.ctrlKey &&
  !event.shiftKey;

export const DELETE_KEY_LABEL = IS_MAC ? "⌫" : "Del";

// H opens the focused row's password history; with a modifier it is left alone.
export const isHistoryKey = (event) =>
  (event.key === "h" || event.key === "H") &&
  !event.altKey &&
  !event.ctrlKey &&
  !event.metaKey &&
  !event.shiftKey;

// Keys pressed on a control inside a cell (a copy button, the checkbox, a link)
// belong to that control, not to the row.
export const fromControl = (event) =>
  !!event.target.closest?.(
    "button, a, input, textarea, [role=checkbox], .MuiDataGrid-cellCheckbox"
  );

// "name (copy)", or "name (copy 2)" and so on when that is taken.
export const duplicateName = (name, taken) => {
  const names = new Set(taken);
  let candidate = `${name} (copy)`;
  for (let n = 2; names.has(candidate); n += 1) candidate = `${name} (copy ${n})`;
  return candidate;
};
