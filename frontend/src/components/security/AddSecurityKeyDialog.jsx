import { useEffect, useRef, useState } from "react";
import {
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useStoreActions } from "easy-peasy";

import PasswordField from "../PasswordField";
import KeyHint from "./KeyHint";
import { WARN } from "../../lib/brand";
import { SecurityKeyCancelled } from "../../platform/securityKeys";

const AddSecurityKeyDialog = ({ open, onClose, onAdded, status }) => {
  const addKey = useStoreActions((a) => a.ciphermothModels.security.addKey);
  const keys = status?.security_keys ?? [];
  const first = keys.length === 0;
  const unprotected = first && !status?.recovery_code;

  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [againPrompt, setAgainPrompt] = useState(false);
  const [swapping, setSwapping] = useState(false);
  const swapped = useRef(null);

  useEffect(() => {
    setName(first ? "YubiKey" : "Backup key");
    setPassword("");
    setUnderstood(false);
    setError("");
    setAgainPrompt(false);
    setSwapping(false);
  }, [open, first]);

  // After the current key confirmed: a pause to unplug it and insert the new one,
  // so the next touch is not the old key again.
  const swapKeys = () =>
    new Promise((resolve, reject) => {
      swapped.current = { resolve, reject };
      setSwapping(true);
    });

  const finishSwap = (cancelled) => {
    setSwapping(false);
    if (cancelled) swapped.current?.reject(new SecurityKeyCancelled("Cancelled."));
    else swapped.current?.resolve();
    swapped.current = null;
  };

  const handleAdd = async () => {
    if (!name.trim()) return setError("Give the key a name you'll recognise.");
    if (!password.trim()) return setError("Enter your master password.");
    setBusy(true);
    setError("");
    try {
      await addKey({
        name: name.trim(),
        masterPassword: password,
        onStep: () => setAgainPrompt(true),
        swapKeys,
      });
      onAdded(first);
    } catch (err) {
      if (!(err instanceof SecurityKeyCancelled)) setError(err.message);
    } finally {
      setBusy(false);
      setAgainPrompt(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{first ? "Require a security key" : "Add another security key"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {first
              ? "Your vault will be encrypted with your master password and this key together. Unlocking then needs both, on every device, and a stolen copy of the vault is useless without the key."
              : "Any registered key unlocks the vault. Keep a backup key somewhere safe in case you lose your everyday one."}
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {first
              ? "Insert the key, then touch it twice: once to register it and once to show it can protect your vault."
              : "First touch a key you already use, then insert the new one and touch it twice."}
          </Typography>
          <TextField
            label="Key name"
            size="small"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setError("");
            }}
            slotProps={{ htmlInput: { maxLength: 64 } }}
            helperText="Only you see this, and it is stored encrypted."
          />
          <PasswordField
            label="Master Password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (!unprotected || understood)) handleAdd();
            }}
            autoComplete="current-password"
            autoFocus
          />
          {unprotected && (
            <Box
              sx={{
                border: `1px solid ${WARN}`,
                bgcolor: "rgba(224,152,47,0.08)",
                borderRadius: 1.5,
                p: 1.5,
              }}
            >
              <Typography variant="caption" sx={{ color: WARN, display: "block", lineHeight: 1.5 }}>
                You have no recovery code yet. If you lose this key and have no other, the vault
                cannot be opened again. Create a recovery code or add a second key afterwards.
              </Typography>
              <FormControlLabel
                sx={{ ml: 0, mt: 0.5 }}
                control={
                  <Checkbox
                    size="small"
                    checked={understood}
                    onChange={(e) => setUnderstood(e.target.checked)}
                  />
                }
                label={<Typography variant="caption">I understand</Typography>}
              />
            </Box>
          )}
          {swapping ? (
            <Box
              role="status"
              sx={{ borderRadius: 1.5, p: 1.5, bgcolor: "action.hover", textAlign: "center" }}
            >
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                Confirmed. Now remove that key and insert the new one.
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mt: 1.25, justifyContent: "center" }}>
                <Button size="small" onClick={() => finishSwap(true)}>
                  Cancel
                </Button>
                <Button variant="contained" size="small" onClick={() => finishSwap(false)}>
                  The new key is in
                </Button>
              </Stack>
            </Box>
          ) : againPrompt ? (
            <Typography variant="caption" aria-live="polite">
              Registered. Touch the new key once more to finish…
            </Typography>
          ) : (
            <KeyHint />
          )}
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
        <Button
          variant="contained"
          onClick={handleAdd}
          loading={busy}
          disabled={unprotected && !understood}
        >
          {first ? "Add key and turn on" : "Add key"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default AddSecurityKeyDialog;
