import { useEffect, useState } from "react";
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import { useStoreActions } from "easy-peasy";

import PasswordField from "../PasswordField";
import KeyHint from "./KeyHint";
import { getMasterPasswordStrength } from "../../lib/passwordStrength";
import { SecurityKeyCancelled } from "../../platform/securityKeys";

const EMPTY = { current: "", next: "", confirm: "" };

// Change the master password: a full re-key of the vault. Every session ends,
// this one too; security keys and the recovery code keep working.
const ChangeMasterPasswordDialog = ({ open, onClose, securityKeyRequired }) => {
  const changeMasterPassword = useStoreActions(
    (a) => a.ciphermothModels.security.changeMasterPassword
  );
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setForm(EMPTY);
    setError("");
  }, [open]);

  const strength = getMasterPasswordStrength(form.next);
  const field = (key) => ({
    value: form[key],
    onChange: (e) => {
      setForm((prev) => ({ ...prev, [key]: e.target.value }));
      setError("");
    },
  });

  const handleChange = async () => {
    if (!form.current.trim()) return setError("Enter your current master password.");
    if (form.next !== form.confirm) return setError("The new passwords don't match.");
    if (strength.value < 70)
      return setError("The new password is too weak. Use at least 12 characters of mixed types.");
    if (form.next === form.current) return setError("Choose a password you have not used here.");
    setBusy(true);
    try {
      await changeMasterPassword({ current: form.current, next: form.next });
    } catch (err) {
      if (!(err instanceof SecurityKeyCancelled)) setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle>Change master password</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Every entry is encrypted again with a new key. You will be logged out everywhere and
            unlock with the new password. Your security keys and recovery code keep working.
          </Typography>
          <PasswordField
            label="Current master password"
            autoComplete="current-password"
            autoFocus
            {...field("current")}
          />
          <Box>
            <PasswordField
              label="New master password"
              autoComplete="new-password"
              {...field("next")}
            />
            {form.next && (
              <Box sx={{ mt: 1 }}>
                <LinearProgress
                  variant="determinate"
                  value={strength.value}
                  color={strength.color}
                  sx={{ borderRadius: 1, height: 5, bgcolor: "action.hover" }}
                />
                <Typography variant="caption" color={`${strength.color}.main`}>
                  {strength.label}
                </Typography>
              </Box>
            )}
          </Box>
          <PasswordField
            label="Confirm new master password"
            autoComplete="new-password"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleChange();
            }}
            {...field("confirm")}
          />
          <KeyHint required={securityKeyRequired} />
          {error && (
            <Typography variant="body2" color="error" role="alert">
              {error}
            </Typography>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" onClick={handleChange} loading={busy}>
          Change password
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ChangeMasterPasswordDialog;
