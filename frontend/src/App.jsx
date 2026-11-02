import { useEffect } from "react";
import { BrowserRouter as Router, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Box, Container, CssBaseline, GlobalStyles, Toolbar } from "@mui/material";
import { useStoreActions } from "easy-peasy";

import DesktopGate from "./platform/DesktopGate";
import ThemeToggle from "./components/ThemeToggle";
import TopMenu from "./components/TopMenu";
import { ColorModeProvider } from "./hooks/useColorMode";
import useAutoLogout from "./hooks/useAutoLogout";
import routes from "./routes";
import { isAuth } from "./utils";
import { GLOW, INFO, PAPER_DARK, TEXT_ON_DARK, WARN, WEAK } from "./lib/brand";

const SANS = "'Space Grotesk Variable', system-ui, sans-serif";

const AppContent = () => {
  useLocation();
  useAutoLogout();

  const authed = isAuth();
  const getSettings = useStoreActions((a) => a.ciphermothModels.settings.get);
  useEffect(() => {
    if (authed) getSettings();
  }, [authed, getSettings]);

  const appRoutes = (
    <Routes>
      {routes.map((route) => (
        <Route key={route.path} path={route.path} element={route.element} />
      ))}
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );

  if (!authed) {
    return (
      <>
        <CssBaseline />
        {appRoutes}
      </>
    );
  }

  return (
    <Box sx={{ display: "flex" }}>
      <CssBaseline />
      <TopMenu />
      <Box
        component="main"
        sx={{
          bgcolor: "background.default",
          flexGrow: 1,
          minWidth: 0,
          // The vault grid scrolls inside this height. The page itself only scrolls
          // when the window is too short to fit the grid's minimum height.
          height: "100dvh",
          overflow: "auto",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <Toolbar sx={{ flexShrink: 0 }} />
        <Container
          maxWidth="lg"
          sx={{
            flex: "1 0 auto",
            display: "flex",
            flexDirection: "column",
            pt: { xs: 2, sm: 3 },
            pb: { xs: 2, sm: 3 },
          }}
        >
          {appRoutes}
        </Container>
      </Box>
      <ThemeToggle />
    </Box>
  );
};

const snackbarStyles = (
  <GlobalStyles
    styles={{
      // Toasts share a single dark surface with a coloured accent stripe so the
      // outcome reads at a glance without breaking the black-and-glow palette.
      ".notistack-MuiContent": {
        backgroundColor: `${PAPER_DARK} !important`,
        color: `${TEXT_ON_DARK} !important`,
        fontFamily: `${SANS} !important`,
        borderRadius: "10px !important",
        border: "1px solid rgba(255,255,255,0.12)",
      },
      ".notistack-MuiContent-success": { borderLeft: `3px solid ${GLOW} !important` },
      ".notistack-MuiContent-error": { borderLeft: `3px solid ${WEAK} !important` },
      ".notistack-MuiContent-warning": { borderLeft: `3px solid ${WARN} !important` },
      ".notistack-MuiContent-info": { borderLeft: `3px solid ${INFO} !important` },
    }}
  />
);

const themeTransitionStyles = (
  <GlobalStyles
    styles={{
      "html.cm-theming, html.cm-theming *, html.cm-theming *::before, html.cm-theming *::after": {
        transition:
          "background-color 420ms ease, border-color 420ms ease, color 300ms ease, fill 300ms ease !important",
      },
    }}
  />
);

const App = () => (
  <Router>
    <ColorModeProvider>
      {snackbarStyles}
      {themeTransitionStyles}
      <DesktopGate>
        <AppContent />
      </DesktopGate>
    </ColorModeProvider>
  </Router>
);

export default App;
