import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import "@fontsource-variable/space-grotesk";
import "@fontsource/space-mono/400.css";
import { GLOW, INK } from "../../../../frontend/src/lib/brand.js";
import App from "./App.jsx";

const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: INK },
    secondary: { main: GLOW },
    background: { default: INK },
  },
  typography: { fontFamily: "'Space Grotesk Variable', 'Space Grotesk', system-ui, sans-serif" },
  components: { MuiButtonBase: { defaultProps: { disableRipple: true } } },
});

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <App />
    </ThemeProvider>
  </StrictMode>
);
