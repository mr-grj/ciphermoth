import { useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material";

// `details` renders below the message (it may hold block elements, which the
// message paragraph cannot). While an async `onConfirm` runs, both buttons wait.
// `focusConfirm` lets Enter confirm; keep it off for anything that cannot be undone.
const ConfirmDialog = ({
  open,
  title,
  onClose,
  onConfirm,
  confirmText = "Confirm",
  confirmColor = "primary",
  details,
  focusConfirm = false,
  children,
}) => {
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{children}</DialogContentText>
        {details}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          color={confirmColor}
          onClick={confirm}
          loading={busy}
          autoFocus={focusConfirm}
        >
          {confirmText}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ConfirmDialog;
