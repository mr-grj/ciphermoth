import { action, thunk } from "easy-peasy";

import { IS_DESKTOP, nativeBackup, nativeRestore } from "../platform";
import { getSessionToken } from "../utils";
import apiClient from "../api/client";
import { errorDetail, triggerDownload } from "../lib/http";

export const entryPath = (passwordName, suffix = "") => {
  if (passwordName === "." || passwordName === "..") {
    throw new Error(
      `Browsers can't address an entry named "${passwordName}". Edit the entry to rename it, then try again.`
    );
  }
  return `/passwords/${encodeURIComponent(passwordName)}${suffix}`;
};

export const entryHeaders = (passwordName) => ({
  "x-ciphermoth-entry": encodeURIComponent(passwordName),
});

const Passwords = {
  error: null,
  loading: false,
  passwords: [],
  trash: [],
  damaged: { entries: [], attachments: [] },
  damageCheckError: null,

  setError: action((state, error) => {
    state.error = error;
  }),
  setLoading: action((state, loading) => {
    state.loading = loading;
  }),
  setPasswords: action((state, passwords) => {
    state.passwords = passwords;
  }),
  setTrash: action((state, trash) => {
    state.trash = trash;
  }),
  setDamaged: action((state, damaged) => {
    state.damaged = damaged;
  }),
  setDamageCheckError: action((state, error) => {
    state.damageCheckError = error;
  }),

  getDamaged: thunk(async (actions) => {
    try {
      const { data } = await apiClient.get("/vault/damaged");
      actions.setDamaged(data);
      actions.setDamageCheckError(null);
    } catch {
      actions.setDamageCheckError(
        "The vault damage check failed. Some entries or attachments may be missing from this view. Retry the check before relying on this list."
      );
    }
  }),

  removeDamaged: thunk(async (actions, damaged) => {
    try {
      for (const kind of ["entries", "attachments"]) {
        for (const rowId of damaged[kind]) {
          await apiClient.delete(`/vault/damaged/${kind}/${rowId}`);
        }
      }
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to remove the damaged rows."));
    } finally {
      await actions.get();
      await actions.getTrash();
      await actions.getDamaged();
    }
  }),

  get: thunk(async (actions) => {
    actions.setLoading(true);
    actions.setError(null);
    try {
      const { data } = await apiClient.get("/passwords");
      actions.setPasswords(data);
    } catch (err) {
      actions.setError(await errorDetail(err, "Failed to load passwords."));
    } finally {
      actions.setLoading(false);
    }
  }),

  create: thunk(async (actions, payload) => {
    try {
      await apiClient.post("/passwords/create", payload);
      await actions.get();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to create password."));
    }
  }),

  update: thunk(async (actions, payload) => {
    try {
      await apiClient.patch("/passwords/update", payload);
      await actions.get();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to update password."));
    }
  }),

  remove: thunk(async (actions, passwordName) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName);
    try {
      await apiClient.delete(path, { headers });
      await actions.get();
      await actions.getTrash();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to delete password."));
    }
  }),

  // The bulk routes are all-or-nothing: one missing entry or name conflict changes
  // nothing. The lists are reloaded either way, so the view matches the vault.
  trashMany: thunk(async (actions, names) => {
    try {
      const entries = names.map((password_name) => ({ password_name }));
      const { data } = await apiClient.post("/vault/entries/trash", { entries });
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to move the entries to trash."));
    } finally {
      await actions.get();
      await actions.getTrash().catch(() => {});
    }
  }),

  restoreMany: thunk(async (actions, rows) => {
    try {
      const entries = rows.map((row) => ({ password_name: row.password_name, entry_id: row.id }));
      const { data } = await apiClient.post("/vault/trash/restore", { entries });
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to restore the entries."));
    } finally {
      await actions.get();
      await actions.getTrash().catch(() => {});
    }
  }),

  purgeMany: thunk(async (actions, rows) => {
    try {
      const entries = rows.map((row) => ({ password_name: row.password_name, entry_id: row.id }));
      const { data } = await apiClient.post("/vault/trash/purge", { entries });
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to delete the entries."));
    } finally {
      await actions.getTrash().catch(() => {});
    }
  }),

  getTrash: thunk(async (actions) => {
    try {
      const { data } = await apiClient.get("/passwords/trash");
      actions.setTrash(data);
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to load trash."));
    }
  }),

  restore: thunk(async (actions, target) => {
    const { passwordName, entryId } =
      typeof target === "string" ? { passwordName: target } : target;
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, "/restore");
    try {
      await apiClient.post(path, null, { headers, params: { entry_id: entryId } });
      await actions.get();
      await actions.getTrash();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to restore password."));
    }
  }),

  purge: thunk(async (actions, target) => {
    const { passwordName, entryId } =
      typeof target === "string" ? { passwordName: target } : target;
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, "/purge");
    try {
      await apiClient.delete(path, { headers, params: { entry_id: entryId } });
      await actions.getTrash();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to delete password."));
    }
  }),

  toggleFavorite: thunk(async (actions, { passwordName, favorite }) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, "/favorite");
    try {
      await apiClient.patch(path, { favorite }, { headers });
      await actions.get();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to update favorite."));
    }
  }),

  fetchAttachments: thunk(async (actions, passwordName) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, "/attachments");
    try {
      const { data } = await apiClient.get(path, { headers });
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to load attachments."));
    }
  }),

  uploadAttachment: thunk(async (actions, { passwordName, file }) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, "/attachments");
    try {
      const formData = new FormData();
      formData.append("file", file);
      const { data } = await apiClient.post(path, formData, { headers });
      await actions.get();
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to upload attachment."));
    }
  }),

  downloadAttachment: thunk(async (actions, { passwordName, attachmentId, filename }) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, `/attachments/${attachmentId}`);
    try {
      const response = await apiClient.get(path, { responseType: "blob", headers });
      await triggerDownload(response.data, filename || "attachment");
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to download attachment."));
    }
  }),

  deleteAttachment: thunk(async (actions, { passwordName, attachmentId }) => {
    const headers = entryHeaders(passwordName);
    const path = entryPath(passwordName, `/attachments/${attachmentId}`);
    try {
      await apiClient.delete(path, { headers });
      await actions.get();
    } catch (err) {
      throw new Error(await errorDetail(err, "Failed to delete attachment."));
    }
  }),

  importPasswords: thunk(async (actions, { file, masterPassword, onConflict }) => {
    try {
      if (IS_DESKTOP) {
        const data = await nativeRestore(
          getSessionToken(),
          masterPassword,
          file.ticket,
          onConflict
        ).catch((message) => {
          throw new Error(String(message));
        });
        await actions.get();
        await actions.getTrash();
        return data;
      }
      const formData = new FormData();
      formData.append("file", file);
      formData.append("master_password", masterPassword);
      formData.append("on_conflict", onConflict);
      const { data } = await apiClient.post("/passwords/import", formData);
      await actions.get();
      await actions.getTrash();
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, IS_DESKTOP ? err.message : "Import failed."));
    }
  }),

  importCsv: thunk(async (actions, { file, onConflict }) => {
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("on_conflict", onConflict);
      const { data } = await apiClient.post("/passwords/import/csv", formData);
      await actions.get();
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, IS_DESKTOP ? err.message : "Import failed."));
    }
  }),

  backup: thunk(async (_actions, masterPassword) => {
    try {
      if (IS_DESKTOP)
        return await nativeBackup(getSessionToken(), masterPassword).catch((message) => {
          throw new Error(String(message));
        });
      const response = await apiClient.post(
        "/passwords/backup",
        { master_password: masterPassword },
        { responseType: "blob" }
      );
      const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
      triggerDownload(response.data, `ciphermoth_backup_${stamp}.cmbackup`);
    } catch (err) {
      throw new Error(await errorDetail(err, IS_DESKTOP ? err.message : "Backup failed."));
    }
  }),
};

export default Passwords;
