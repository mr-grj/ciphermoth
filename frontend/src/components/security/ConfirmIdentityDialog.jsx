import { useEffect, useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from "@mui/material";

import PasswordField from "../PasswordField";
import KeyHint from "./KeyHint";
import { SecurityKeyCancelled } from "../../platform/securityKeys";

// Sensitive changes ask for the master password again (and the security key,
// when the vault requires one), so an unlocked, unattended screen cannot make them.
const ConfirmIdentityDialog = ({
  open,
  title,
  description,
  confirmLabel,
  danger = false,
  securityKeyRequired,
  onConfirm,
  onClose,
}) => {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setPassword("");
    setError("");
  }, [open]);

  const handleConfirm = async () => {
    if (!password.trim()) {
      setError("Enter your master password.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await onConfirm(password);
    } catch (err) {
      if (!(err instanceof SecurityKeyCancelled)) setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {description && (
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              {description}
            </Typography>
          )}
          <PasswordField
            label="Master Password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleConfirm();
            }}
            error={Boolean(error)}
            helperText={error}
            autoComplete="current-password"
            autoFocus
          />
          <KeyHint required={securityKeyRequired} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          color={danger ? "error" : "primary"}
          onClick={handleConfirm}
          loading={busy}
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ConfirmIdentityDialog;
