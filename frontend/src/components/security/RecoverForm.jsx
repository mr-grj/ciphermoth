import { useState } from "react";
import {
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  LinearProgress,
  Link,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useStoreActions } from "easy-peasy";

import PasswordField from "../PasswordField";
import RecoveryCodeDialog from "./RecoveryCodeDialog";
import { getMasterPasswordStrength } from "../../lib/passwordStrength";
import { groupRecoveryCode, isRecoveryCode } from "../../lib/recoveryCode";
import { openSession } from "../../model/masterPassword";

// "Forgot master password?" on the unlock screen: a new master password from the
// recovery code. The vault opens only once the new recovery code is saved.
const RecoverForm = ({ securityKeyRequired, onBack, buttonSx }) => {
  const recover = useStoreActions((a) => a.ciphermothModels.masterPassword.recover);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [lostKeys, setLostKeys] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const strength = getMasterPasswordStrength(password);

  const handleRecover = async () => {
    if (!isRecoveryCode(code))
      return setError("A recovery code has 32 letters and digits, in groups of four.");
    if (password !== confirm) return setError("The new passwords don't match.");
    if (strength.value < 70)
      return setError("Password is too weak. Use at least 12 characters with mixed types.");
    setBusy(true);
    setError("");
    try {
      setResult(
        await recover({
          code,
          newPassword: password,
          keepSecurityKeys: !lostKeys,
        })
      );
      setCode("");
      setPassword("");
      setConfirm("");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{ textAlign: "left" }}>
      <Typography sx={{ fontSize: 20, fontWeight: 700, textAlign: "center" }}>
        Reset your master password
      </Typography>
      <Typography
        sx={{ mt: 1, mb: 2.5, fontSize: 13, color: "text.secondary", textAlign: "center" }}
      >
        Enter the recovery code you saved. Your entries stay exactly as they are.
      </Typography>
      <Stack spacing={2}>
        <TextField
          label="Recovery code"
          value={code}
          onChange={(e) => {
            setCode(groupRecoveryCode(e.target.value));
            setError("");
          }}
          autoFocus
          fullWidth
          placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
          slotProps={{
            htmlInput: {
              spellCheck: false,
              autoCorrect: "off",
              autoCapitalize: "characters",
              autoComplete: "off",
              style: { fontFamily: "'Space Mono', monospace", letterSpacing: "0.03em" },
            },
          }}
        />
        <Box>
          <PasswordField
            label="New master password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            autoComplete="new-password"
          />
          {password && (
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
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value);
            setError("");
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleRecover();
          }}
          autoComplete="new-password"
        />
        {securityKeyRequired && (
          <FormControlLabel
            sx={{ ml: 0, alignItems: "flex-start" }}
            control={
              <Checkbox
                size="small"
                checked={lostKeys}
                onChange={(e) => setLostKeys(e.target.checked)}
                sx={{ pt: 0.25 }}
              />
            }
            label={
              <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.5 }}>
                I lost my security keys. Remove them, so my new master password alone unlocks the
                vault. (Leave this off and your keys keep working.)
              </Typography>
            }
          />
        )}
        {error && (
          <Typography variant="body2" color="error" role="alert">
            {error}
          </Typography>
        )}
        <Button
          fullWidth
          size="large"
          variant="contained"
          loading={busy}
          onClick={handleRecover}
          sx={buttonSx}
        >
          Reset master password
        </Button>
        <Typography sx={{ fontSize: 12, color: "text.secondary", textAlign: "center" }}>
          Every other session is logged out, and you get a new recovery code.
        </Typography>
        <Link
          component="button"
          type="button"
          underline="hover"
          onClick={onBack}
          sx={{ fontSize: 13, alignSelf: "center" }}
        >
          Back to unlock
        </Link>
      </Stack>
      <RecoveryCodeDialog
        code={result?.recoveryCode}
        doneLabel="Open my vault"
        onDone={() => openSession(result.sessionToken)}
      />
    </Box>
  );
};

export default RecoverForm;
