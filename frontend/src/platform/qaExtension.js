// Imported only by the dedicated native QA build. Browser extensions in
// desktop mode: the harness (desktop/harness/extension.py) plays the browser
// through the app's real native host while this side drives the switch and
// answers the pairing dialog the way a user would, after the harness confirmed
// both sides show the same code.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import api from "../api/client";

const ensure = (condition, message) => {
  if (!condition) throw new Error(message);
};

export const EXTENSION_LOGIN = {
  password_name: "Extension QA login",
  password_value: "Extension-QA-canary-2026!",
  username: "qa@example.test",
  url: "https://login.example.test",
};

export async function extensionWorkflow(checks) {
  await api.post("/passwords/create", EXTENSION_LOGIN);
  let status = await invoke("extension_status");
  ensure(!status.enabled && !status.listening, "browser extensions are on by default");
  status = await invoke("extension_set_enabled", { enabled: true });
  ensure(status.enabled && status.listening && !status.error, "the switch did not turn on");

  const stop = await listen("extension-pairing", async (event) => {
    // The host compares this code with the one it computed, then acknowledges.
    await invoke("qa_report", {
      result: {
        stage: "extension_pairing",
        code: event.payload.code,
        browser: event.payload.browser,
      },
    });
    await invoke("extension_pairing_answer", { id: event.payload.id, allow: true });
  });
  try {
    await invoke("qa_report", { result: { stage: "extension", browsers: status.browsers } });
  } finally {
    stop();
  }
  status = await invoke("extension_status");
  ensure(status.pairings.length === 1 && status.pairings[0].browser === "Chrome", "no pairing");
  const sessions = (await api.get("/extension/sessions")).data;
  ensure(sessions.length === 1, "the paired browser has no extension session");

  status = await invoke("extension_set_enabled", { enabled: false });
  ensure(!status.enabled && !status.listening, "the switch did not turn off");
  ensure(status.browsers.length === 0, "manifests left behind");
  ensure((await api.get("/extension/sessions")).data.length === 0, "extension session survived");
  ensure(status.pairings.length === 1, "turning off forgot the pairing");
  await invoke("qa_report", { result: { stage: "extension_off" } });
  await invoke("extension_unpair", { id: status.pairings[0].id });
  checks.push(
    "browser extension: switch, manifests, pairing with matching codes, fill over the channel, off ends sessions"
  );
}
