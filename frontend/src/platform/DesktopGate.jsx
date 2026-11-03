import { useEffect, useState } from "react";
import { Box, Button, Typography } from "@mui/material";
import { listen } from "@tauri-apps/api/event";
import { IS_DESKTOP, openExternal, clearClipboard } from "./index";
import { coreStatus, coreRestart, onCoreStatus } from "./core";
import { listenForMenuActions } from "./menu";
import { clearSession, isAuth } from "../utils";
import LoadingScreen from "../components/LoadingScreen";

export default function DesktopGate({ children }) {
  const [status, setStatus] = useState(null);
  useEffect(() => {
    if (!IS_DESKTOP) return;
    let disposed = false;
    let generation;
    const unlisten = [];
    const locked = () => {
      clearClipboard();
      clearSession();
      window.location.replace("/login");
    };
    const update = (next) => {
      if (disposed) return;
      if (
        isAuth() &&
        (next.state !== "ready" || (generation !== undefined && next.generation !== generation))
      )
        locked();
      generation = next.generation;
      setStatus(next);
    };
    Promise.all([
      onCoreStatus(update),
      listen("vault-locked", locked),
      listenForMenuActions(),
    ]).then((stops) => {
      if (disposed) stops.forEach((stop) => stop());
      else unlisten.push(...stops);
    });
    coreStatus().then(update);
    const click = (event) => {
      const link = event.target.closest?.("a[href]");
      if (link && /^https?:|^mailto:/i.test(link.href)) {
        event.preventDefault();
        openExternal(link.href).catch(() => {});
      }
    };
    const keydown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === "l") {
        event.preventDefault();
        import("../api/session").then(({ endSession }) => endSession());
      }
    };
    document.addEventListener("click", click, true);
    document.addEventListener("keydown", keydown);
    return () => {
      disposed = true;
      unlisten.forEach((stop) => stop());
      document.removeEventListener("click", click, true);
      document.removeEventListener("keydown", keydown);
    };
  }, []);
  if (!IS_DESKTOP || status?.state === "ready") return children;
  if (status?.state === "failed")
    return (
      <Box sx={{ minHeight: "100vh", display: "grid", placeContent: "center", gap: 2, p: 4 }}>
        <Typography variant="h5">Your vault could not be opened</Typography>
        <Typography>
          Close other CipherMoth windows and check that this application is complete. Your vault has
          not been replaced.
        </Typography>
        <Button onClick={() => coreRestart()}>Try again</Button>
      </Box>
    );
  return <LoadingScreen label="OPENING CIPHERMOTH" />;
}
