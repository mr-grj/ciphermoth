import { useEffect, useState } from "react";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import {
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  LinearProgress,
  Link,
  Typography,
} from "@mui/material";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import LoadingScreen from "../components/LoadingScreen";
import MothIcon from "../components/MothIcon";
import PasswordField from "../components/PasswordField";
import KeyHint from "../components/security/KeyHint";
import RecoverForm from "../components/security/RecoverForm";
import ThemeToggle from "../components/ThemeToggle";
import { getMasterPasswordStrength } from "../lib/passwordStrength";
import { GLOW, GLOW_SOFT, INK, WARN } from "../lib/brand";
import { LOGOUT_NOTICE } from "../utils";

const unlockButtonSx = {
  bgcolor: GLOW,
  color: INK,
  fontWeight: 700,
  letterSpacing: "0.06em",
  py: 1.6,
  "&:hover": { bgcolor: GLOW_SOFT },
  "&.Mui-disabled": { bgcolor: "rgba(125,211,192,0.3)", color: "rgba(11,11,12,0.55)" },
};

const LoginPage = () => {
  const { enqueueSnackbar } = useSnackbar();

  const { fetchStatus, unlock, create, setValue, setConfirm, setError } = useStoreActions(
    (a) => a.ciphermothModels.masterPassword
  );
  const { initialized, error, value, confirm, loading, securityKeyRequired, recoveryAvailable } =
    useStoreState((s) => s.ciphermothModels.masterPassword);
  const [recovering, setRecovering] = useState(false);
  const loadDeviceUnlock = useStoreActions((a) => a.ciphermothModels.deviceUnlock.load);
  const unlockWithDevice = useStoreActions((a) => a.ciphermothModels.deviceUnlock.unlock);
  const {
    label: deviceLabel,
    support,
    enrollment,
    passwordRequired,
    unlocking,
    keyChanged,
  } = useStoreState((s) => s.ciphermothModels.deviceUnlock);

  useEffect(() => {
    fetchStatus();
    loadDeviceUnlock();
    const notice = sessionStorage.getItem(LOGOUT_NOTICE);
    if (notice) {
      sessionStorage.removeItem(LOGOUT_NOTICE);
      enqueueSnackbar(notice, { variant: "info" });
    }
  }, [fetchStatus, loadDeviceUnlock, enqueueSnackbar]);

  useEffect(() => {
    if (error) enqueueSnackbar(error, { variant: "error" });
  }, [error, enqueueSnackbar]);

  const [acknowledged, setAcknowledged] = useState(false);

  const strength = initialized === false ? getMasterPasswordStrength(value) : null;
  const deviceEnrolled = Boolean(initialized && enrollment && support?.available && !keyChanged);
  const canUseDevice = deviceEnrolled && !passwordRequired;

  const handleDeviceUnlock = async () => {
    const problem = await unlockWithDevice();
    if (problem) enqueueSnackbar(problem, { variant: "error" });
  };

  const handleLogin = () => {
    if (!value.trim()) {
      enqueueSnackbar("Please enter your master password.", { variant: "error" });
      return;
    }
    unlock({ master_password: value });
  };

  const handleCreate = () => {
    if (!value) {
      setError("Please enter a master password.");
      return;
    }
    if (value !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    if (strength && strength.value < 70) {
      setError("Password is too weak. Use at least 12 characters with mixed types.");
      return;
    }
    if (!acknowledged) {
      setError("Please confirm you understand how recovery works.");
      return;
    }
    create({ master_password: value });
  };

  if (initialized === null) {
    return <LoadingScreen />;
  }

  return (
    <Box
      sx={{
        position: "fixed",
        inset: 0,
        bgcolor: "background.default",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        p: 3,
        overflow: "auto",
        zIndex: (t) => t.zIndex.modal,
      }}
    >
      <Box
        component="form"
        onSubmit={(e) => e.preventDefault()}
        sx={{
          width: "100%",
          maxWidth: initialized ? 400 : 440,
          bgcolor: "background.paper",
          border: "1px solid",
          borderColor: "divider",
          borderRadius: 2,
          px: { xs: 3, sm: 4.25 },
          py: 5,
          textAlign: "center",
        }}
      >
        <Box
          sx={{
            width: 56,
            mx: "auto",
            mb: 2.25,
            color: "text.primary",
            filter: `drop-shadow(0 0 18px color-mix(in srgb, ${GLOW} 50%, transparent))`,
          }}
        >
          <MothIcon width="100%" height="100%" style={{ display: "block", overflow: "visible" }} />
        </Box>

        {recovering ? (
          <RecoverForm
            securityKeyRequired={securityKeyRequired}
            onBack={() => setRecovering(false)}
            buttonSx={unlockButtonSx}
          />
        ) : (
          <>
            {initialized ? (
              <>
                <Typography sx={{ fontSize: 24, fontWeight: 700, color: "text.primary" }}>
                  Cipher
                  <Box component="span" sx={{ color: GLOW }}>
                    Moth
                  </Box>
                </Typography>
                <Typography
                  sx={{
                    mt: 1,
                    mb: 3.25,
                    fontFamily: "'Space Mono', monospace",
                    fontSize: 12,
                    color: "text.secondary",
                  }}
                >
                  Your secrets stay in the dark.
                </Typography>
              </>
            ) : (
              <>
                <Typography sx={{ fontSize: 23, fontWeight: 700, color: "text.primary" }}>
                  Set up your vault
                </Typography>
                <Typography
                  sx={{ mt: 1, mb: 3, fontSize: 13, color: "text.secondary", lineHeight: 1.5 }}
                >
                  One master password protects everything. Choose it well. It is the only key.
                </Typography>
              </>
            )}

            <PasswordField
              label="Master Password"
              required
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && initialized) handleLogin();
              }}
              autoFocus
              autoComplete={initialized ? "current-password" : "new-password"}
            />

            {!initialized && value && strength && (
              <Box sx={{ mt: 2, textAlign: "left" }}>
                <LinearProgress
                  variant="determinate"
                  value={strength.value}
                  color={strength.color}
                  sx={{ borderRadius: 1, height: 6, bgcolor: "action.hover" }}
                />
                <Typography
                  variant="caption"
                  color={`${strength.color}.main`}
                  sx={{ mt: 0.5, display: "block" }}
                >
                  {strength.label}
                </Typography>
              </Box>
            )}

            {!initialized && (
              <Box sx={{ mt: 2 }}>
                <PasswordField
                  label="Confirm Master Password"
                  required
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleCreate();
                  }}
                  autoComplete="new-password"
                />
                <Box
                  sx={{
                    mt: 2,
                    display: "flex",
                    gap: 1.25,
                    textAlign: "left",
                    border: `1px solid ${WARN}`,
                    bgcolor: "rgba(224,152,47,0.08)",
                    borderRadius: 1.5,
                    p: 1.6,
                  }}
                >
                  <Box component="span" sx={{ color: WARN, lineHeight: 1.4 }}>
                    ⚠
                  </Box>
                  <Typography variant="caption" sx={{ color: WARN, lineHeight: 1.5 }}>
                    Nobody can reset your master password for you. Once you are in, create a
                    recovery code in Settings &rarr; Security; without one, a lost master password
                    means the vault is gone, permanently. That is the trade for nobody-but-you
                    holding the key.
                  </Typography>
                </Box>
                <FormControlLabel
                  sx={{ mt: 1, ml: 0, alignItems: "center" }}
                  control={
                    <Checkbox
                      size="small"
                      checked={acknowledged}
                      onChange={(e) => {
                        setAcknowledged(e.target.checked);
                        setError(null);
                      }}
                      sx={{ color: GLOW, "&.Mui-checked": { color: GLOW }, py: 0.25 }}
                    />
                  }
                  label={
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                      I understand only a recovery code can reset my master password.
                    </Typography>
                  }
                />
              </Box>
            )}

            {initialized && securityKeyRequired && (
              <Box sx={{ mt: 2, display: "flex", justifyContent: "center" }}>
                <KeyHint required />
              </Box>
            )}

            <Button
              fullWidth
              size="large"
              variant="contained"
              loading={loading}
              disabled={!initialized && !acknowledged}
              onClick={initialized ? handleLogin : handleCreate}
              sx={{ mt: 3, ...unlockButtonSx }}
            >
              {initialized ? "Unlock Vault" : "Create Vault"}
            </Button>

            {canUseDevice && (
              <Button
                fullWidth
                size="large"
                variant="outlined"
                startIcon={<FingerprintIcon />}
                loading={unlocking}
                disabled={loading}
                onClick={handleDeviceUnlock}
                sx={{ mt: 1.5, py: 1.4, color: "text.primary", borderColor: "divider" }}
              >
                Unlock with {deviceLabel}
              </Button>
            )}

            {deviceEnrolled && passwordRequired && (
              <Typography sx={{ mt: 2, fontSize: 12, color: "text.secondary", lineHeight: 1.5 }}>
                A little practice: enter your master password so you never forget it. {deviceLabel}{" "}
                works again right after.
              </Typography>
            )}

            {initialized && recoveryAvailable && (
              <Link
                component="button"
                type="button"
                underline="hover"
                onClick={() => setRecovering(true)}
                sx={{ mt: 2.25, fontSize: 13, display: "block", mx: "auto" }}
              >
                Forgot master password?
              </Link>
            )}

            <Typography sx={{ mt: 2.75, fontSize: 11, color: "text.disabled" }}>
              Closing this tab locks your vault. That is by design.
            </Typography>
          </>
        )}
      </Box>
      <ThemeToggle zIndex={1301} />
    </Box>
  );
};

export default LoginPage;
