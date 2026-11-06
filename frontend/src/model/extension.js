import { action, thunk } from "easy-peasy";

import apiClient from "../api/client";
import { errorDetail } from "../lib/http";

// Browser extensions connected to this vault (docs/EXTENSION.md). The list
// shows browser names and times only; the server never returns their tokens.
const Extension = {
  sessions: [],
  loaded: false,

  setSessions: action((state, sessions) => {
    state.sessions = sessions;
    state.loaded = true;
  }),

  loadSessions: thunk(async (actions) => {
    try {
      const { data } = await apiClient.get("/extension/sessions");
      actions.setSessions(Array.isArray(data) ? data : []);
    } catch (err) {
      throw new Error(await errorDetail(err, "Could not load connected browsers."));
    }
  }),

  disconnect: thunk(async (actions, id) => {
    try {
      await apiClient.delete(`/extension/sessions/${encodeURIComponent(id)}`);
    } catch (err) {
      if (err.response?.status !== 404) {
        throw new Error(await errorDetail(err, "Could not disconnect the browser."));
      }
    }
    await actions.loadSessions();
  }),

  // Opens an extension session for the handoff: { session_token, id }.
  connect: thunk(async (actions, { browser, client = null }) => {
    try {
      const { data } = await apiClient.post("/extension/sessions", {
        browser,
        ...(client ? { client } : {}),
      });
      return data;
    } catch (err) {
      throw new Error(await errorDetail(err, "Could not connect the extension."));
    }
  }),
};

export default Extension;
