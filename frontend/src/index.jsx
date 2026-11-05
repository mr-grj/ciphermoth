import ReactDOM from "react-dom/client";
import { StoreProvider } from "easy-peasy";
import { SnackbarProvider } from "notistack";
import "@fontsource-variable/space-grotesk";
import "@fontsource/space-mono/400.css";
import "@fontsource/space-mono/700.css";

import App from "./App";
import { store } from "./store";
import { forgetLegacyKey } from "./utils";
import { captureHandoff } from "./lib/extensionHandoff";
import { IS_DESKTOP } from "./platform";

forgetLegacyKey();
if (!IS_DESKTOP) captureHandoff();

const root = ReactDOM.createRoot(document.getElementById("root"));

root.render(
  <StoreProvider store={store}>
    <SnackbarProvider
      preventDuplicate
      maxSnack={3}
      anchorOrigin={{
        vertical: "bottom",
        horizontal: "right",
      }}
    >
      <App />
    </SnackbarProvider>
  </StoreProvider>
);

if (import.meta.env.VITE_DESKTOP_QA === "1") {
  if (import.meta.env.VITE_UPDATE_QA === "1") import("./platform/qaUpdates");
  else import("./platform/qa");
}
