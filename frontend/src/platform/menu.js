import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { IS_DESKTOP } from "./index";

// The desktop menu bar sends `menu-action` events naming an action. Components
// register what an action does while they are mounted; the latest one wins.
const handlers = new Map();

// Actions that are safe while a dialog is open. Anything else would replace or
// stack on top of what the user is doing, so it waits until the dialog closes.
const ANYTIME = new Set(["lock", "toggle-theme"]);

const dialogOpen = () => !!document.querySelector(".MuiDialog-root, .MuiPopover-root");

export const dispatchMenuAction = (id) => {
  const handler = handlers.get(id);
  if (!handler) return false;
  if (!ANYTIME.has(id) && dialogOpen()) return false;
  handler();
  return true;
};

export const onMenuAction = (id, handler) => {
  handlers.set(id, handler);
  return () => {
    if (handlers.get(id) === handler) handlers.delete(id);
  };
};

export const listenForMenuActions = () =>
  listen("menu-action", (event) => dispatchMenuAction(event.payload));

// Vault items are enabled only while the vault is unlocked.
export const setMenuUnlocked = (unlocked) =>
  IS_DESKTOP ? invoke("menu_state", { unlocked }).catch(() => {}) : Promise.resolve();
