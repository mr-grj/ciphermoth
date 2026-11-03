import { useEffect, useState } from "react";
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
  Typography,
} from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import DownloadIcon from "@mui/icons-material/Download";
import { useSnackbar } from "notistack";

import useClipboard from "../../hooks/useClipboard";
import { triggerDownload } from "../../lib/http";
import { WARN } from "../../lib/brand";

const fileText = (code) =>
  [
    "CipherMoth recovery code",
    "",
    `    ${code}`,
    "",
    "Use it to set a new master password if you forget yours (Forgot master",
    "password? on the unlock screen, or 'ciphermoth recover'). It also gets you in",
    "without your security key. It works once; you then get a new one.",
    "",
    "Anyone holding this code can open your vault. Keep it offline: printed, in a",
    "safe place. Delete this file once it is stored.",
    "",
  ].join("\n");

// Shown once, right after a recovery code is made. It cannot be shown again.
const RecoveryCodeDialog = ({ code, onDone, doneLabel = "Done" }) => {
  const copy = useClipboard();
  const { enqueueSnackbar } = useSnackbar();
  const [saved, setSaved] = useState(false);

  useEffect(() => setSaved(false), [code]);

  const download = async () => {
    try {
      await triggerDownload(
        new Blob([fileText(code)], { type: "text/plain" }),
        "ciphermoth-recovery-code.txt"
      );
    } catch {
      enqueueSnackbar("Could not save the file. Copy the code or write it down.", {
        variant: "error",
      });
    }
  };

  return (
    <Dialog open={Boolean(code)} maxWidth="xs" fullWidth>
      <DialogTitle>Your recovery code</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            If you forget your master password or lose your security key, this code gets you back
            in. This is the only time it is shown.
          </Typography>
          <Box
            data-testid="recovery-code"
            sx={{
              fontFamily: "'Space Mono', monospace",
              fontSize: 17,
              letterSpacing: "0.04em",
              lineHeight: 1.9,
              textAlign: "center",
              py: 2,
              px: 1.5,
              borderRadius: 1.5,
              border: "1px dashed",
              borderColor: "divider",
              bgcolor: "action.hover",
              userSelect: "all",
              wordSpacing: "0.4em",
            }}
          >
            {code?.split("-").slice(0, 4).join("-")}
            <br />
            {code?.split("-").slice(4).join("-")}
          </Box>
          <Stack direction="row" spacing={1}>
            <Button
              fullWidth
              variant="outlined"
              size="small"
              startIcon={<ContentCopyIcon />}
              onClick={() => copy(code, "Recovery code")}
            >
              Copy
            </Button>
            <Button
              fullWidth
              variant="outlined"
              size="small"
              startIcon={<DownloadIcon />}
              onClick={download}
            >
              Save as file
            </Button>
          </Stack>
          <Typography variant="caption" sx={{ color: WARN, lineHeight: 1.5 }}>
            Anyone holding this code can open your vault. Write it down or print it and keep it
            somewhere safe, away from this computer.
          </Typography>
          <FormControlLabel
            sx={{ ml: 0 }}
            control={
              <Checkbox size="small" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            }
            label={
              <Typography variant="body2">I&rsquo;ve stored my recovery code safely</Typography>
            }
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button variant="contained" disabled={!saved} onClick={onDone}>
          {doneLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default RecoveryCodeDialog;
