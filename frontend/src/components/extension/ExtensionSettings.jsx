import { useEffect, useState } from "react";
import {
  Box,
  Button,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined";
import ExtensionOutlinedIcon from "@mui/icons-material/ExtensionOutlined";
import LinkOffIcon from "@mui/icons-material/LinkOff";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import WebOutlinedIcon from "@mui/icons-material/WebOutlined";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import { formatAgo } from "../../lib/dates";
import {
  EXTENSION_DOCS_URL,
  RELEASES_URL,
  detectBrowser,
  installTarget,
  isConnectedIn,
} from "../../lib/extensionHandoff";

const Section = ({ icon, title, children }) => (
  <Box component="section" aria-label={title}>
    <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 0.75 }}>
      <Box sx={{ color: "text.secondary", display: "flex" }}>{icon}</Box>
      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
        {title}
      </Typography>
    </Stack>
    <Stack spacing={1.25} sx={{ pl: 3.75 }}>
      {children}
    </Stack>
  </Box>
);

const Hint = ({ children }) => (
  <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.5 }}>
    {children}
  </Typography>
);

const ExtensionSettings = ({ open }) => {
  const { enqueueSnackbar } = useSnackbar();
  const sessions = useStoreState((s) => s.ciphermothModels.extension.sessions);
  const loaded = useStoreState((s) => s.ciphermothModels.extension.loaded);
  const { loadSessions, disconnect } = useStoreActions((a) => a.ciphermothModels.extension);
  const [busy, setBusy] = useState(null);
  const browser = detectBrowser();
  const install = installTarget(browser);
  const connected = isConnectedIn(sessions, browser);

  useEffect(() => {
    if (open) loadSessions().catch((err) => enqueueSnackbar(err.message, { variant: "error" }));
  }, [open, loadSessions, enqueueSnackbar]);

  const handleDisconnect = async (session) => {
    setBusy(session.id);
    try {
      await disconnect(session.id);
      enqueueSnackbar(`${session.browser} disconnected.`, { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Stack spacing={3} sx={{ mt: 1 }}>
      <Section icon={<ExtensionOutlinedIcon fontSize="small" />} title="Install">
        <Hint>
          Fill logins on the sites you visit, only when you ask. Nothing shows up on pages by
          itself, and the extension talks only to this vault.
        </Hint>
        {connected ? (
          // Pages cannot see extensions (on purpose), so this comes from the
          // vault's list of connected browsers, not from this browser.
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <CheckCircleOutlinedIcon fontSize="small" color="secondary" />
            <Typography variant="body2">CipherMoth is connected in {browser}.</Typography>
          </Stack>
        ) : (
          <Box>
            <Button
              variant="contained"
              size="small"
              href={install.url}
              target="_blank"
              rel="noopener noreferrer"
              endIcon={<OpenInNewIcon fontSize="small" />}
            >
              {install.label}
            </Button>
          </Box>
        )}
        <Hint>
          <Link href={EXTENSION_DOCS_URL} target="_blank" rel="noopener noreferrer">
            {connected ? "Install in another browser" : "Other browsers"}
          </Link>
          {" · "}
          <Link href={RELEASES_URL} target="_blank" rel="noopener noreferrer">
            Install without a store
          </Link>{" "}
          (no automatic security updates; check the checksums first).
        </Hint>
      </Section>

      <Section icon={<WebOutlinedIcon fontSize="small" />} title="Connected browsers">
        {loaded && sessions.length === 0 && (
          <Hint>No browser is connected right now. Unlock the extension to connect one.</Hint>
        )}
        {sessions.length > 0 && (
          <List dense disablePadding aria-label="Connected browsers">
            {sessions.map((session) => (
              <ListItem
                key={session.id}
                disableGutters
                secondaryAction={
                  <Tooltip title="Disconnect" arrow>
                    <span>
                      <IconButton
                        edge="end"
                        aria-label={`Disconnect ${session.browser}`}
                        onClick={() => handleDisconnect(session)}
                        disabled={busy === session.id}
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
                  primary={session.browser}
                  secondary={`Connected ${formatAgo(session.created)} · last used ${formatAgo(
                    session.last_used
                  )}`}
                />
              </ListItem>
            ))}
          </List>
        )}
        <Hint>
          A connected browser stays unlocked until your inactivity timeout, at most 12 hours, or
          until you disconnect it here. Changing the master password disconnects every browser.
        </Hint>
      </Section>
    </Stack>
  );
};

export default ExtensionSettings;
