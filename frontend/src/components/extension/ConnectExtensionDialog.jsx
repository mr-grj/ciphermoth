import { useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from "@mui/material";
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined";
import { useStoreActions } from "easy-peasy";

import { clearHandoff, deliverToken, pendingHandoff } from "../../lib/extensionHandoff";
import { GLOW } from "../../lib/brand";

// Shown once the vault is unlocked in a tab the browser extension opened for
// its handoff. Nothing is sent to the extension until the user says so.
const ConnectExtensionDialog = () => {
  const [handoff, setHandoff] = useState(() => pendingHandoff());
  const [phase, setPhase] = useState("ask");
  const [error, setError] = useState("");
  const { connect, disconnect } = useStoreActions((a) => a.ciphermothModels.extension);

  if (!handoff) return null;

  const close = () => {
    clearHandoff();
    setHandoff(null);
  };

  const handleConnect = async () => {
    setPhase("connecting");
    setError("");
    try {
      const session = await connect({ browser: handoff.browser, client: handoff.client });
      const delivered = await deliverToken({
        request: handoff.request,
        token: session.session_token,
      });
      clearHandoff();
      if (delivered) {
        setPhase("connected");
        return;
      }
      await disconnect(session.id).catch(() => {});
      setPhase("ask");
      setError(
        "The extension did not answer. Open CipherMoth from its toolbar button and choose “Unlock in CipherMoth” again."
      );
    } catch (err) {
      setPhase("ask");
      setError(err.message);
    }
  };

  const browser = handoff.browser === "Browser" ? "this browser" : handoff.browser;

  return (
    <Dialog
      open
      onClose={phase === "connecting" ? undefined : close}
      maxWidth="xs"
      fullWidth
      aria-labelledby="connect-extension-title"
    >
      <DialogTitle id="connect-extension-title">
        {phase === "connected" ? "Connected" : `Connect ${browser} to this vault?`}
      </DialogTitle>
      <DialogContent>
        {phase === "connected" ? (
          <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
            <CheckCircleOutlinedIcon sx={{ color: GLOW }} />
            <Typography variant="body2">
              The extension is unlocked. You can close this tab.
            </Typography>
          </Stack>
        ) : (
          <Stack spacing={1.5}>
            <Typography variant="body2">
              The CipherMoth extension in {browser} asked to unlock. It can fill logins on the sites
              you choose, only when you ask.
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              It cannot see your vault list, notes or attachments, export or change anything. It
              locks with your inactivity timeout, and you can disconnect it in Settings → Browser
              extension.
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              Didn’t ask for this? Choose Cancel.
            </Typography>
            {error && (
              <Typography variant="body2" color="error" role="alert">
                {error}
              </Typography>
            )}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        {phase === "connected" ? (
          <Button variant="contained" onClick={close}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={close} disabled={phase === "connecting"}>
              Cancel
            </Button>
            <Button variant="contained" onClick={handleConnect} loading={phase === "connecting"}>
              Connect
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default ConnectExtensionDialog;
