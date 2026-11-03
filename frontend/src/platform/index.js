import { invoke } from "@tauri-apps/api/core";

// One build-time switch, shared by all platform-dependent functionality.
export const IS_DESKTOP =
  import.meta.env.MODE === "desktop" || import.meta.env.VITE_DESKTOP === "1";
export const copySecret = (value, timeoutMs) => invoke("clipboard_write", { value, timeoutMs });
export const clearClipboard = () =>
  IS_DESKTOP ? invoke("clipboard_clear").catch(() => {}) : Promise.resolve();
export const openExternal = (url) => invoke("open_external", { url });
export const chooseBackup = () => invoke("choose_backup");
export const nativeBackup = (session, password, securityKey) =>
  invoke("backup_export", { session, password, securityKey: securityKey ?? null });
export const nativeRestore = (session, password, ticket, onConflict) =>
  invoke("backup_import", { session, password, ticket, onConflict });
export const saveFile = async (blob, filename) =>
  invoke("save_file", new Uint8Array(await blob.arrayBuffer()), {
    headers: { "x-filename": encodeURIComponent(filename) },
  });

export const enterVault = () => {
  if (!IS_DESKTOP) return window.location.replace("/passwords");
  window.history.replaceState(null, "", "/passwords");
  window.dispatchEvent(new PopStateEvent("popstate"));
};

export const lockNative = () => invoke("vault_lock");
