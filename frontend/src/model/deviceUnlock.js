import { action, thunk } from "easy-peasy";

import apiClient from "../api/client";
import { errorDetail } from "../lib/http";
import { enterVault } from "../platform";
import {
  BiometricCancelled,
  BiometricKeyChanged,
  biometricLabel,
  biometricSecret,
  biometricSupport,
  createBiometricCredential,
  ownEnrollment,
  rememberCredential,
} from "../platform/biometrics";
import { setSessionToken } from "../utils";

const STATUS = "/master_password/device-unlock";

const DeviceUnlock = {
  label: biometricLabel(),
  support: null,
  enrollment: null,
  passwordRequired: false,
  passwordIntervalDays: 14,
  unlocking: false,
  // This page view's enrollment stopped working; the password is the way in.
  keyChanged: false,

  setSupport: action((state, support) => {
    state.support = support;
  }),
  setStatus: action((state, status) => {
    state.enrollment = ownEnrollment(status.enrollments);
    state.passwordRequired = status.password_required;
    state.passwordIntervalDays = status.password_interval_days;
  }),
  setUnlocking: action((state, unlocking) => {
    state.unlocking = unlocking;
  }),
  setKeyChanged: action((state, keyChanged) => {
    state.keyChanged = keyChanged;
  }),

  load: thunk(async (actions) => {
    const [support, status] = await Promise.all([
      biometricSupport(),
      apiClient.get(STATUS).catch(() => null),
    ]);
    actions.setSupport(support);
    if (status) actions.setStatus(status.data);
  }),

  // Returns an error message to show, or null: a dismissed prompt is not an error.
  unlock: thunk(async (actions, _, { getState }) => {
    const { enrollment, label } = getState();
    actions.setUnlocking(true);
    try {
      const secret = await biometricSecret(enrollment);
      const { data } = await apiClient.post(`${STATUS}/unlock`, {
        credential_id: enrollment.credential_id,
        secret,
      });
      if (data.valid && data.session_token) {
        setSessionToken(data.session_token);
        enterVault();
        return null;
      }
      if (data.password_required) {
        await actions.load();
        return null;
      }
      return `${label} could not unlock the vault. Use your master password.`;
    } catch (err) {
      if (err instanceof BiometricCancelled) return null;
      if (err instanceof BiometricKeyChanged) {
        actions.setKeyChanged(true);
        return `Your ${label} fingerprints changed, so this no longer unlocks the vault. Use your master password, then turn ${label} on again in Settings.`;
      }
      return err.response
        ? await errorDetail(err, "An error occurred.")
        : err.message || "An error occurred.";
    } finally {
      actions.setUnlocking(false);
    }
  }),

  // The prompt comes first and the credential survives a mistyped password, so a
  // retry neither asks for the finger again nor leaves an unused passkey behind.
  createCredential: thunk(async () => createBiometricCredential()),

  enroll: thunk(async (actions, { credential, masterPassword }, { getState }) => {
    const previous = getState().enrollment;
    try {
      const { data } = await apiClient.post(`${STATUS}/enroll`, {
        ...credential,
        master_password: masterPassword,
      });
      rememberCredential(credential.credential_id);
      actions.setStatus(data);
      actions.setKeyChanged(false);
    } catch (err) {
      throw new Error(await errorDetail(err, "Could not turn on biometric unlock."));
    }
    if (previous && previous.credential_id !== credential.credential_id) {
      await apiClient.delete(`${STATUS}/${previous.credential_id}`).catch(() => {});
    }
  }),

  disable: thunk(async (actions, _, { getState }) => {
    const { enrollment } = getState();
    try {
      const { data } = await apiClient.delete(`${STATUS}/${enrollment.credential_id}`);
      rememberCredential(null);
      actions.setStatus(data);
    } catch (err) {
      throw new Error(await errorDetail(err, "Could not turn off biometric unlock."));
    }
  }),

  setInterval: thunk(async (actions, days) => {
    try {
      const { data } = await apiClient.patch(STATUS, { password_interval_days: days });
      actions.setStatus(data);
    } catch (err) {
      throw new Error(await errorDetail(err, "Could not save that."));
    }
  }),
};

export default DeviceUnlock;
