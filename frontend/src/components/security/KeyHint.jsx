import { Stack, Typography } from "@mui/material";
import UsbIcon from "@mui/icons-material/Usb";

import useSecurityKeyPrompt from "../../hooks/useSecurityKeyPrompt";

// An inline line under a form: what the security key is waiting for, or (with
// ``required``) that one will be asked for.
const KeyHint = ({ required }) => {
  const message = useSecurityKeyPrompt()?.message;
  if (!message && !required) return null;
  return (
    <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} aria-live="polite">
      <UsbIcon fontSize="small" sx={{ color: message ? "secondary.main" : "text.disabled" }} />
      <Typography variant="caption" sx={{ color: message ? "text.primary" : "text.secondary" }}>
        {message ? `${message}…` : "You'll be asked to touch your security key."}
      </Typography>
    </Stack>
  );
};

export default KeyHint;
