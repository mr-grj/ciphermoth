import { useEffect, useState } from "react";
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Typography,
} from "@mui/material";

import { GLOW } from "../../lib/brand";
import { answerPairing, formatPairingCode, onPairingRequest } from "../../platform/extension";

// Desktop only: a browser's CipherMoth extension asks to pair. The app shows
// the code it computed; the extension's popup shows its own. They match only
// if nothing sits between the two, so the user compares before allowing.
const PairingDialog = () => {
  const [request, setRequest] = useState(null);

  useEffect(() => {
    let stop = null;
    let cancelled = false;
    onPairingRequest(
      (next) => setRequest(next),
      (id) => setRequest((current) => (current?.id === id ? null : current))
    ).then((unlisten) => {
      if (cancelled) unlisten();
      else stop = unlisten;
    });
    return () => {
      cancelled = true;
      stop?.();
    };
  }, []);

  const code = formatPairingCode(request?.code);
  const answer = (allow) => {
    if (request) answerPairing(request.id, allow);
    setRequest(null);
  };

  return (
    <Dialog open={Boolean(request && code)} onClose={() => answer(false)} maxWidth="xs" fullWidth>
      <DialogTitle>Allow {request?.browser ?? "this browser"} to fill logins?</DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
          Check that the CipherMoth extension in {request?.browser ?? "your browser"} shows this
          code. If it shows another code, or you did not ask, choose Don&apos;t allow.
        </Typography>
        <Box
          aria-label={`Pairing code ${code}`}
          sx={{
            fontFamily: "'Space Mono', monospace",
            fontSize: 34,
            letterSpacing: 4,
            textAlign: "center",
            py: 1.5,
            borderRadius: 2,
            bgcolor: "rgba(125, 211, 192, 0.12)",
            border: `1px solid ${GLOW}`,
          }}
        >
          {code}
        </Box>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={() => answer(false)}>Don&apos;t allow</Button>
        <Button variant="contained" onClick={() => answer(true)}>
          Allow
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PairingDialog;
