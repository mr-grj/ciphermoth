import { action, thunk } from "easy-peasy";

import { enterVault } from "../platform";
import apiClient from "../api/client";
import { errorDetail } from "../lib/http";
import { SecurityKeyCancelled, securityKeyAnswer } from "../platform/securityKeys";
import { setSessionToken } from "../utils";

const MasterPassword = {
  initialized: null,
  securityKeyRequired: false,
  recoveryAvailable: false,
  error: null,
  loading: false,
  value: "",
  confirm: "",

  setInitialized: action((state, val) => {
    state.initialized = val;
  }),
  setStatus: action((state, status) => {
    state.initialized = status.initialized;
    state.securityKeyRequired = Boolean(status.security_key_required);
    state.recoveryAvailable = Boolean(status.recovery_code);
  }),
  setValue: action((state, value) => {
    state.value = value;
  }),
  setConfirm: action((state, value) => {
    state.confirm = value;
  }),
  setError: action((state, error) => {
    state.error = error;
  }),
  setLoading: action((state, loading) => {
    state.loading = loading;
  }),

  fetchStatus: thunk(async (actions) => {
    try {
      const { data } = await apiClient.get("/master_password/status");
      actions.setStatus(data);
    } catch {
      actions.setInitialized(true);
    }
  }),

  unlock: thunk(async (actions, masterPasswordPayload, { getState }) => {
    actions.setError(null);
    actions.setLoading(true);
    try {
      const body = { ...masterPasswordPayload };
      if (getState().securityKeyRequired) {
        const { data: challenge } = await apiClient.post("/master_password/unlock/challenge");
        body.security_key = await securityKeyAnswer(challenge);
      }
      const { data } = await apiClient.post("/master_password/unlock", body);
      if (data.valid && data.session_token) {
        setSessionToken(data.session_token);
        actions.setValue("");
        actions.setConfirm("");
        enterVault();
      } else {
        actions.setError("Invalid master password.");
      }
    } catch (err) {
      if (err instanceof SecurityKeyCancelled) return;
      const msg =
        err.response?.status === 429
          ? "Too many attempts. Please try again in an hour."
          : err.response
            ? await errorDetail(err, "An error occurred.")
            : err.message || "An error occurred.";
      // The vault may have turned the security key on or off meanwhile.
      if (err.response?.status === 400) await actions.fetchStatus();
      actions.setError(msg);
    } finally {
      actions.setLoading(false);
    }
  }),

  create: thunk(async (actions, masterPasswordPayload) => {
    actions.setError(null);
    actions.setLoading(true);
    try {
      const { data } = await apiClient.post("/master_password/create", masterPasswordPayload);
      if (!data.session_token) {
        actions.setError("The vault was created, but it could not be unlocked. Unlock it now.");
        actions.setInitialized(true);
        return;
      }
      setSessionToken(data.session_token);
      actions.setValue("");
      actions.setConfirm("");
      enterVault();
    } catch (err) {
      actions.setError(await errorDetail(err, "An error occurred."));
    } finally {
      actions.setLoading(false);
    }
  }),

  // Forgot the master password: a new one from the recovery code. Returns the new
  // recovery code and the session, which the caller stores (``openSession``) only
  // once the user has saved the code.
  recover: thunk(async (actions, { code, newPassword, keepSecurityKeys }) => {
    try {
      const { data } = await apiClient.post("/master_password/recover", {
        recovery_code: code,
        new_master_password: newPassword,
        keep_security_keys: keepSecurityKeys,
      });
      actions.setValue("");
      actions.setConfirm("");
      return { recoveryCode: data.recovery_code, sessionToken: data.session_token };
    } catch (err) {
      throw new Error(
        err.response?.status === 429
          ? "Too many attempts. Please try again in an hour."
          : await errorDetail(err, "Could not reset the master password.")
      );
    }
  }),
};

export const openSession = (token) => {
  setSessionToken(token);
  enterVault();
};

export default MasterPassword;
