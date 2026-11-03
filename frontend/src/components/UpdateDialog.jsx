import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Link,
  Stack,
  Typography,
} from "@mui/material";
import { useStoreState } from "easy-peasy";

import { GLOW } from "../lib/brand";
import { MANUAL_UPDATE_COMMAND } from "../lib/updateCommands";
import { IS_DESKTOP } from "../platform";
import DesktopUpdateDialog from "./DesktopUpdateDialog";

const stripV = (v) => String(v ?? "").replace(/^v/, "");

const Command = ({ children }) => (
  <Box
    component="pre"
    sx={{
      m: 0,
      p: 1.5,
      borderRadius: 1,
      border: "1px solid",
      borderColor: "divider",
      bgcolor: (t) => (t.palette.mode === "dark" ? "rgba(255,255,255,0.06)" : "#141416"),
      color: (t) => (t.palette.mode === "dark" ? t.palette.text.primary : "#f4f4f2"),
      fontSize: 12,
      overflowX: "auto",
      whiteSpace: "pre-wrap",
    }}
  >
    {children}
  </Box>
);

const UpdateDialog = ({ open, onClose }) => {
  const { current, latest, releaseUrl } = useStoreState((s) => s.ciphermothModels.updates);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>A new moult is ready</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <Chip label={current ? `v${stripV(current)}` : "-"} size="small" />
            <Typography sx={{ color: "text.disabled" }}>→</Typography>
            <Chip
              label={latest ?? "-"}
              size="small"
              sx={{ bgcolor: GLOW, color: "#0b0b0c", fontWeight: 700 }}
            />
          </Stack>

          {releaseUrl && (
            <Link href={releaseUrl} target="_blank" rel="noopener noreferrer" variant="body2">
              Read the release notes on GitHub
            </Link>
          )}

          <Box>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
              Update from a terminal in your CipherMoth folder. The first command keeps a raw
              snapshot of the encrypted vault file, so you can always go back. It opens only with
              the master password you have today; for a portable copy, use Backup.
            </Typography>
            <Command>{MANUAL_UPDATE_COMMAND}</Command>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default IS_DESKTOP ? DesktopUpdateDialog : UpdateDialog;
