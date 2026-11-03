import { action, thunk } from "easy-peasy";

import apiClient from "../api/client";
import { endSession } from "../api/session";
import { errorDetail } from "../lib/http";
import {
  SecurityKeyCancelled,
  registerSecurityKey,
  securityKeyAnswer,
  securityKeySupport,
} from "../platform/securityKeys";

// Whether unlocking (and so every sensitive change) needs a security key. Asked
// fresh each time: another device may have just turned it on or off.
export const securityKeyRequired = async () => {
  const { data } = await apiClient.get("/master_password/status");
  return Boolean(data.security_key_required);
};

// What the server asks for before a sensitive change: the master password, and
// an answer from a registered security key when the vault requires one.
export const confirmation = async (masterPassword) => {
  const body = { master_password: masterPassword };
  if (await securityKeyRequired()) {
    const { data } = await apiClient.post("/security/challenge");
    body.security_key = await securityKeyAnswer(data, "Touch your security key to confirm");
  }
  return body;
};

// Errors for the UI: a dismissed key prompt stays a SecurityKeyCancelled, which
// callers ignore; everything else becomes a message.
export const asMessage = async (err, fallback) => {
  if (err instanceof SecurityKeyCancelled) return err;
  if (err.response) return new Error(await errorDetail(err, fallback));
  return new Error(err.message || fallback);
};

const Security = {
  status: null,
  support: null,

  setStatus: action((state, status) => {
    state.status = status;
  }),
  setSupport: action((state, support) => {
    state.support = support;
  }),

  load: thunk(async (actions) => {
    const [support, status] = await Promise.all([
      securityKeySupport(),
      apiClient
        .get("/security")
        .then(({ data }) => data)
        .catch(() => null),
    ]);
    actions.setSupport(support);
    if (status) actions.setStatus(status);
  }),

  // ``swapKeys`` resolves once the user has swapped to the new key; it is called
  // only when an existing key confirmed first.
  addKey: thunk(async (actions, { name, masterPassword, onStep, swapKeys }) => {
    try {
      const confirmed = await confirmation(masterPassword);
      if (confirmed.security_key) await swapKeys();
      const { data: options } = await apiClient.post("/security/keys/options");
      const { registration, assertion } = await registerSecurityKey(options, onStep);
      const { data } = await apiClient.post("/security/keys", {
        name,
        confirmation: confirmed,
        registration,
        assertion,
      });
      actions.setStatus(data);
    } catch (err) {
      throw await asMessage(err, "Could not add the security key.");
    }
  }),

  removeKey: thunk(async (actions, { id, masterPassword }) => {
    try {
      const { data } = await apiClient.post(
        `/security/keys/${encodeURIComponent(id)}/remove`,
        await confirmation(masterPassword)
      );
      actions.setStatus(data);
    } catch (err) {
      throw await asMessage(err, "Could not remove the security key.");
    }
  }),

  createRecoveryCode: thunk(async (actions, masterPassword) => {
    try {
      const { data } = await apiClient.post(
        "/security/recovery-code",
        await confirmation(masterPassword)
      );
      actions.setStatus(data.status);
      return data.recovery_code;
    } catch (err) {
      throw await asMessage(err, "Could not create a recovery code.");
    }
  }),

  removeRecoveryCode: thunk(async (actions, masterPassword) => {
    try {
      const { data } = await apiClient.post(
        "/security/recovery-code/remove",
        await confirmation(masterPassword)
      );
      actions.setStatus(data);
    } catch (err) {
      throw await asMessage(err, "Could not remove the recovery code.");
    }
  }),

  // Every session ends with the change, this one included.
  changeMasterPassword: thunk(async (_actions, { current, next }) => {
    try {
      const body = await confirmation(current);
      await apiClient.patch("/master_password/update", {
        master_password: body.master_password,
        new_master_password: next,
        ...(body.security_key ? { security_key: body.security_key } : {}),
      });
    } catch (err) {
      throw await asMessage(err, "Could not change the master password.");
    }
    await endSession("Master password changed. Unlock with your new one.");
  }),
};

export default Security;
