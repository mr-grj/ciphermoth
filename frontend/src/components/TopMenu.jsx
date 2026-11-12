import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  AppBar,
  Box,
  Button,
  Chip,
  Container,
  IconButton,
  Toolbar,
  Tooltip,
  Typography,
  useMediaQuery,
} from "@mui/material";
import LogoutIcon from "@mui/icons-material/Logout";
import SettingsIcon from "@mui/icons-material/Settings";
import UpgradeIcon from "@mui/icons-material/Upgrade";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import { endSession } from "../api/session";
import { isAuth } from "../utils";
import useMenuAction from "../hooks/useMenuAction";
import { DEV_ACCENT, IS_DEV } from "../lib/appEnv";
import { GLOW } from "../lib/brand";
import EnvBadge from "./EnvBadge";
import MothIcon from "./MothIcon";
import SettingsModal from "./SettingsModal";
import UpdateDialog from "./UpdateDialog";

const TopMenu = () => {
  const userIsAuth = isAuth();
  const { pathname } = useLocation();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [updateOpen, setUpdateOpen] = useState(false);
  const narrow = useMediaQuery((theme) => theme.breakpoints.down("sm"));

  const updateCheckEnabled = useStoreState(
    (s) => s.ciphermothModels.settings.settings.update_check_enabled
  );
  const settingsLoaded = useStoreState((s) => s.ciphermothModels.settings.loaded);
  const updateAvailable = useStoreState((s) => s.ciphermothModels.updates.updateAvailable);
  const version = useStoreState((s) => s.ciphermothModels.updates.current);
  const checkForUpdates = useStoreActions((a) => a.ciphermothModels.updates.checkForUpdates);
  const fetchVersion = useStoreActions((a) => a.ciphermothModels.updates.fetchVersion);

  useEffect(() => {
    if (userIsAuth) fetchVersion();
  }, [userIsAuth, fetchVersion]);

  useEffect(() => {
    if (userIsAuth && settingsLoaded && updateCheckEnabled) checkForUpdates();
  }, [userIsAuth, settingsLoaded, updateCheckEnabled, checkForUpdates]);

  const handleLogout = () => endSession();

  const { enqueueSnackbar, closeSnackbar } = useSnackbar();
  useMenuAction("settings", () => setSettingsOpen(true));
  useMenuAction("lock", handleLogout);
  // Asked for from the menu, the check runs even with automatic checks off, and
  // always answers.
  useMenuAction("check-updates", async () => {
    const checking = enqueueSnackbar("Checking for updates…", {
      variant: "info",
      persist: true,
    });
    const status = await checkForUpdates();
    closeSnackbar(checking);
    if (!status) {
      enqueueSnackbar("Could not check for updates. Check your connection and try again.", {
        variant: "warning",
      });
    } else if (status.updateAvailable) {
      setUpdateOpen(true);
    } else {
      const running = String(status.current ?? version ?? "").replace(/^v/, "");
      enqueueSnackbar(`You're up to date${running ? ` (v${running})` : ""}.`, {
        variant: "success",
      });
    }
  });

  return (
    <AppBar
      position="absolute"
      sx={IS_DEV ? { borderBottom: `3px solid ${DEV_ACCENT}` } : undefined}
    >
      <Container maxWidth="lg">
        <Toolbar disableGutters>
          <Box sx={{ flexGrow: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <Box sx={{ width: 24, height: 24, display: "flex", color: "inherit" }}>
              <MothIcon
                width="100%"
                height="100%"
                style={{ display: "block", overflow: "visible" }}
              />
            </Box>
            <Typography
              component="h1"
              variant="h6"
              noWrap
              sx={{ color: "inherit", fontWeight: 600 }}
            >
              Cipher
              <Box component="span" sx={{ color: GLOW }}>
                Moth
              </Box>
            </Typography>
            <EnvBadge />
            {version && (
              <Tooltip arrow title="Running version">
                <Typography
                  component="span"
                  sx={{
                    fontFamily: "'Space Mono', monospace",
                    fontSize: 10,
                    letterSpacing: "0.08em",
                    color: "rgba(255,255,255,0.5)",
                    cursor: "default",
                    display: { xs: "none", sm: "inline" },
                  }}
                >
                  v{String(version).replace(/^v/, "")}
                </Typography>
              </Tooltip>
            )}
          </Box>

          {userIsAuth ? (
            <>
              {updateAvailable && (
                <Tooltip title="A new CipherMoth release is available" describeChild>
                  <Chip
                    icon={<UpgradeIcon sx={{ fontSize: 18 }} />}
                    label="Update"
                    size="small"
                    onClick={() => setUpdateOpen(true)}
                    sx={{
                      mr: 1,
                      bgcolor: GLOW,
                      color: "#0b0b0c",
                      fontWeight: 700,
                      cursor: "pointer",
                      "& .MuiChip-icon": { color: "#0b0b0c" },
                      "&:hover": { bgcolor: GLOW, filter: "brightness(0.92)" },
                    }}
                  />
                </Tooltip>
              )}
              <Tooltip title="Settings">
                <IconButton color="inherit" onClick={() => setSettingsOpen(true)} sx={{ mr: 0.5 }}>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
              {narrow ? (
                <Tooltip title="Log out">
                  <IconButton color="inherit" aria-label="Log out" onClick={handleLogout}>
                    <LogoutIcon />
                  </IconButton>
                </Tooltip>
              ) : (
                <Button color="inherit" onClick={handleLogout} sx={{ whiteSpace: "nowrap" }}>
                  Log out
                </Button>
              )}
              <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
              <UpdateDialog open={updateOpen} onClose={() => setUpdateOpen(false)} />
            </>
          ) : (
            pathname !== "/login" && (
              <Button href="/login" color="inherit">
                Log in
              </Button>
            )
          )}
        </Toolbar>
      </Container>
    </AppBar>
  );
};

export default TopMenu;
