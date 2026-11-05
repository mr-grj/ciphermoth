// A second extension that tries to message CipherMoth, connect to it and read
// its storage. Every attempt must fail.
self.attack = async (id) => {
  const results = {};
  for (const message of [
    { type: "status" },
    { type: "credential", id: 1, origin: "https://github.test", confirmed: true },
    { type: "handoff-token", request: "A".repeat(43), token: "B".repeat(43) },
  ]) {
    try {
      results[message.type] = { reply: await chrome.runtime.sendMessage(id, message) };
    } catch (error) {
      results[message.type] = { error: String(error) };
    }
  }
  try {
    const port = chrome.runtime.connect(id);
    results.connect = await new Promise((resolve) => {
      port.onDisconnect.addListener(() =>
        resolve({ disconnected: String(chrome.runtime.lastError?.message) })
      );
      port.postMessage({ type: "status" });
      setTimeout(() => resolve({ open: true }), 1000);
    });
  } catch (error) {
    results.connect = { error: String(error) };
  }
  // It has no access to another extension's storage at all; its own is empty.
  results.storage = chrome.storage ? await chrome.storage.session.get(null) : "no storage API";
  return results;
};
