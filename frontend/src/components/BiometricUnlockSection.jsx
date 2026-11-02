import { useEffect, useRef, useState } from "react";
import {
  Button,
  Collapse,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import PasswordField from "./PasswordField";
import { BiometricCancelled } from "../platform/biometrics";

const INTERVALS = [7, 14, 30];

const BiometricUnlockSection = ({ open }) => {
  const { enqueueSnackbar } = useSnackbar();
  const { load, createCredential, enroll, disable, setInterval } = useStoreActions(
    (a) => a.ciphermothModels.deviceUnlock
  );
  const { label, support, enrollment, passwordIntervalDays, keyChanged } = useStoreState(
    (s) => s.ciphermothModels.deviceUnlock
  );

  const [enrolling, setEnrolling] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const credential = useRef(null);

  const reset = () => {
    setEnrolling(false);
    setPassword("");
    setError("");
    credential.current = null;
  };

  // Also on close: the password and the pending secret leave memory with the dialog.
  useEffect(() => {
    reset();
    if (open) load();
  }, [open, load]);

  const enabled = Boolean(enrollment) && !keyChanged;
  const available = support?.available === true;

  const handleToggle = async (event) => {
    setError("");
    if (event.target.checked) {
      setEnrolling(true);
      return;
    }
    if (enrolling) {
      reset();
      return;
    }
    setBusy(true);
    try {
      await disable();
      enqueueSnackbar(`${label} turned off. Your master password is the way in.`, {
        variant: "success",
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleEnable = async () => {
    if (!password.trim()) {
      setError("Enter your master password.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      credential.current = credential.current ?? (await createCredential());
      await enroll({ credential: credential.current, masterPassword: password });
      reset();
      enqueueSnackbar(`${label} is on. Your next unlock can be a touch.`, { variant: "success" });
    } catch (err) {
      if (!(err instanceof BiometricCancelled)) setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleInterval = async (event) => {
    try {
      await setInterval(event.target.value);
    } catch (err) {
      setError(err.message);
    }
  };

  const unavailableHint = support && !available && !enabled ? support.reason : "";

  return (
    <Stack spacing={1}>
      <FormControlLabel
        sx={{ ml: 0, justifyContent: "space-between" }}
        labelPlacement="start"
        disabled={!support || (!available && !enabled) || busy}
        control={<Switch checked={enabled || enrolling} onChange={handleToggle} />}
        label={
          <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
            <FingerprintIcon fontSize="small" sx={{ color: "text.secondary" }} />
            <Typography variant="body2">Unlock with {label}</Typography>
          </Stack>
        }
      />
      {unavailableHint && (
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          {unavailableHint}
        </Typography>
      )}
      <Collapse in={enrolling} unmountOnExit>
        <Stack spacing={1.25} sx={{ pt: 0.5 }}>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            Works on this device only. Anyone whose finger or face this device accepts can open the
            vault. Your master password still works and is still the only recovery.
          </Typography>
          <PasswordField
            label="Master Password"
            size="small"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleEnable();
            }}
            autoComplete="current-password"
            autoFocus
          />
          <Button
            variant="outlined"
            size="small"
            startIcon={<FingerprintIcon />}
            loading={busy}
            onClick={handleEnable}
          >
            Turn on {label}
          </Button>
        </Stack>
      </Collapse>
      {enabled && !enrolling && (
        <TextField
          select
          size="small"
          label="Ask for the master password"
          value={passwordIntervalDays}
          onChange={handleInterval}
          helperText="So you don't forget it. There is no other way to recover the vault."
        >
          {INTERVALS.map((days) => (
            <MenuItem key={days} value={days}>
              Every {days} days
            </MenuItem>
          ))}
        </TextField>
      )}
      {error && (
        <Typography variant="body2" color="error">
          {error}
        </Typography>
      )}
    </Stack>
  );
};

export default BiometricUnlockSection;
