import { useEffect, useState } from "react";
import { Box, Button, Modal, Stack, TextField, Typography } from "@mui/material";
import UsbIcon from "@mui/icons-material/Usb";

import useSecurityKeyPrompt from "../../hooks/useSecurityKeyPrompt";
import { GLOW, PAPER_DARK, TEXT_ON_DARK, TEXT_ON_DARK_MUTED } from "../../lib/brand";
import { IS_DESKTOP } from "../../platform";
import { cancelSecurityKey } from "../../platform/securityKeys";

const fieldSx = {
  "& .MuiInputBase-root": { color: TEXT_ON_DARK },
  "& .MuiInputLabel-root": { color: TEXT_ON_DARK_MUTED },
  "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" },
};

const PinForm = ({ pin }) => {
  const [value, setValue] = useState("");
  useEffect(() => setValue(""), [pin]);
  const submit = (event) => {
    event.preventDefault();
    pin.submit(value);
  };
  return (
    <Box component="form" onSubmit={submit} sx={{ mt: 2 }}>
      <TextField
        type="password"
        label="PIN"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        error={Boolean(pin.error)}
        helperText={pin.error || "The PIN of the key itself, not your master password."}
        autoFocus
        fullWidth
        size="small"
        autoComplete="off"
        slotProps={{
          htmlInput: { maxLength: 63, "aria-label": "Security key PIN" },
          formHelperText: { sx: { color: pin.error ? undefined : TEXT_ON_DARK_MUTED } },
        }}
        sx={fieldSx}
      />
      <Stack direction="row" spacing={1} sx={{ mt: 2, justifyContent: "center" }}>
        <Button onClick={pin.cancel} sx={{ color: TEXT_ON_DARK }}>
          Cancel
        </Button>
        <Button type="submit" variant="contained" color="secondary">
          Continue
        </Button>
      </Stack>
    </Box>
  );
};

// The desktop app's security key prompt: the key's PIN, then "touch your key".
// Browsers show their own. A Modal, not a bare Backdrop: an open dialog (adding a
// key in Settings) keeps focus inside itself unless the prompt is a modal above
// it, and the PIN field took no typing.
const SecurityKeyPrompt = () => {
  const state = useSecurityKeyPrompt();
  if (!IS_DESKTOP) return null;
  const close = (_event, reason) => {
    if (reason !== "escapeKeyDown") return;
    if (state?.pin) state.pin.cancel();
    else cancelSecurityKey();
  };
  return (
    <Modal
      open={Boolean(state)}
      onClose={close}
      sx={{
        zIndex: (t) => t.zIndex.modal + 10,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Box
        tabIndex={-1}
        role="alertdialog"
        aria-live="assertive"
        aria-label={state?.message}
        sx={{
          bgcolor: PAPER_DARK,
          color: TEXT_ON_DARK,
          borderRadius: 2,
          px: 4,
          py: 3.5,
          width: 340,
          textAlign: "center",
          boxShadow: 12,
          outline: "none",
        }}
      >
        <Box
          sx={{
            width: 56,
            height: 56,
            mx: "auto",
            mb: 2,
            borderRadius: "50%",
            display: "grid",
            placeItems: "center",
            color: GLOW,
            border: `2px solid ${GLOW}`,
            animation: state?.pin ? "none" : "cmKeyPulse 1.6s ease-in-out infinite",
            "@keyframes cmKeyPulse": {
              "0%, 100%": { boxShadow: `0 0 0 0 color-mix(in srgb, ${GLOW} 45%, transparent)` },
              "50%": { boxShadow: `0 0 0 12px color-mix(in srgb, ${GLOW} 0%, transparent)` },
            },
          }}
        >
          <UsbIcon />
        </Box>
        <Typography sx={{ fontWeight: 700 }}>{state?.message}</Typography>
        {state?.pin ? (
          <PinForm pin={state.pin} />
        ) : (
          <>
            <Typography variant="body2" sx={{ mt: 1, color: TEXT_ON_DARK_MUTED }}>
              Its light blinks while it waits for your finger.
            </Typography>
            <Button onClick={cancelSecurityKey} sx={{ mt: 2.5, color: TEXT_ON_DARK }}>
              Cancel
            </Button>
          </>
        )}
      </Box>
    </Modal>
  );
};

export default SecurityKeyPrompt;
