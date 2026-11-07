import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  FormControlLabel,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Stack,
  Switch,
  Tooltip,
  Typography,
} from "@mui/material";
import ExtensionOutlinedIcon from "@mui/icons-material/ExtensionOutlined";
import LinkOffIcon from "@mui/icons-material/LinkOff";
import WebOutlinedIcon from "@mui/icons-material/WebOutlined";
import { useSnackbar } from "notistack";

import { formatAgo } from "../../lib/dates";
import { EXTENSION_DOCS_URL } from "../../lib/extensionHandoff";
import { allowExtensions, extensionStatus, unpairBrowser } from "../../platform/extension";

const Hint = ({ children }) => (
  <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.5 }}>
    {children}
  </Typography>
);

const list = (names) =>
  names.length <= 1 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

// Settings → Browser extension in the desktop app: the switch that lets the
// extension reach this app (off until the user turns it on), and the browsers
// paired with it.
const DesktopExtensionSettings = ({ open }) => {
  const { enqueueSnackbar } = useSnackbar();
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(
    () =>
      extensionStatus()
        .then(setStatus)
        .catch(() => setStatus(null)),
    []
  );

  useEffect(() => {
    if (!open) return undefined;
    refresh();
    // A browser may pair while this tab is open.
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [open, refresh]);

  const toggle = async (event) => {
    const enabled = event.target.checked;
    setBusy(true);
    try {
      const next = await allowExtensions(enabled);
      setStatus(next);
      if (next.error) enqueueSnackbar(next.error, { variant: "error" });
      else if (!enabled) enqueueSnackbar("Browser extensions can't reach CipherMoth now.");
    } catch (err) {
      enqueueSnackbar(String(err?.message ?? err), { variant: "error" });
    } finally {
      setBusy(false);
    }
  };

  const unpair = async (pairing) => {
    setBusy(true);
    try {
      setStatus(await unpairBrowser(pairing.id));
      enqueueSnackbar(`${pairing.browser} removed.`, { variant: "success" });
    } catch (err) {
      enqueueSnackbar(String(err?.message ?? err), { variant: "error" });
    } finally {
      setBusy(false);
    }
  };

  if (!status) {
    return (
      <Box sx={{ mt: 1 }}>
        <Hint>Browser extensions are not available in this copy of CipherMoth.</Hint>
      </Box>
    );
  }

  return (
    <Stack spacing={3} sx={{ mt: 1 }}>
      <Stack spacing={1}>
        <FormControlLabel
          control={<Switch checked={status.enabled} onChange={toggle} disabled={busy} />}
          label="Allow browser extensions"
        />
        <Hint>
          The CipherMoth extension in Chrome, Brave or Firefox fills logins from this app, only when
          you ask and only while CipherMoth is unlocked. Each browser asks once, with a code you
          confirm here. Turning this off disconnects every browser.
        </Hint>
        {status.enabled && status.browsers.length > 0 && (
          <Hint>Set up for {list(status.browsers)}.</Hint>
        )}
        {status.enabled && status.browsers.length === 0 && !status.error && (
          <Hint>
            No supported browser found. Install Chrome, Brave or Firefox, then restart CipherMoth.
          </Hint>
        )}
        {status.error && <Alert severity="warning">{status.error}</Alert>}
        <Hint>
          <Link href={EXTENSION_DOCS_URL} target="_blank" rel="noopener noreferrer">
            Get the extension
          </Link>
          , then choose “CipherMoth app on this computer” in its settings.
        </Hint>
      </Stack>

      <Box component="section" aria-label="Paired browsers">
        <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 0.75 }}>
          <Box sx={{ color: "text.secondary", display: "flex" }}>
            <WebOutlinedIcon fontSize="small" />
          </Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            Paired browsers
          </Typography>
        </Stack>
        {status.pairings.length === 0 ? (
          <Hint>No browser is paired yet.</Hint>
        ) : (
          <List dense disablePadding aria-label="Paired browsers">
            {status.pairings.map((pairing) => (
              <ListItem
                key={pairing.id}
                disableGutters
                secondaryAction={
                  <Tooltip title="Remove" arrow>
                    <span>
                      <IconButton
                        edge="end"
                        aria-label={`Remove ${pairing.browser}`}
                        onClick={() => unpair(pairing)}
                        disabled={busy}
                      >
                        <LinkOffIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                }
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <ExtensionOutlinedIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={pairing.browser}
                  secondary={`Paired ${formatAgo(pairing.created)}${
                    pairing.lastUsed ? ` · last used ${formatAgo(pairing.lastUsed)}` : ""
                  }`}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Box>
    </Stack>
  );
};

export default DesktopExtensionSettings;
