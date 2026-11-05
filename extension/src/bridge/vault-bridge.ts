// Runs only on the vault's own origin, only while a handoff the user started
// is pending (registered and unregistered by the background). It passes one
// message from the CipherMoth web app to the background and answers the web
// app once the background accepted it. It reads nothing else from the page.
//
// Accepted only from this window itself (not a frame, not another window), on
// this origin, with the exact message shape. The background then checks the
// tab, the frame, the origin and the single-use request nonce.

const SESSION_MESSAGE = "ciphermoth:extension-session";
const CONNECTED_MESSAGE = "ciphermoth:extension-connected";
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

(() => {
  if (window.top !== window) return;
  const runtime =
    (globalThis as unknown as { browser?: typeof chrome }).browser?.runtime ?? chrome.runtime;
  // A wrong message must not stop the right one (the background ignores a
  // wrong nonce without consuming the request), but the bridge forwards only a
  // few and goes quiet once a token was accepted.
  let attempts = 0;
  let done = false;

  const onMessage = (event: MessageEvent) => {
    if (done || event.source !== window || event.origin !== location.origin) return;
    const data = event.data as Record<string, unknown> | null;
    if (
      typeof data !== "object" ||
      data === null ||
      Object.keys(data).length !== 3 ||
      data.type !== SESSION_MESSAGE ||
      typeof data.request !== "string" ||
      typeof data.token !== "string" ||
      !TOKEN.test(data.request) ||
      !TOKEN.test(data.token)
    )
      return;
    attempts += 1;
    if (attempts > 5) {
      done = true;
      window.removeEventListener("message", onMessage);
      return;
    }
    const request = data.request;
    runtime
      .sendMessage({ type: "handoff-token", request, token: data.token })
      .then((reply: { ok?: boolean; value?: boolean } | undefined) => {
        if (reply?.ok && reply.value === true) {
          done = true;
          window.removeEventListener("message", onMessage);
          window.postMessage({ type: CONNECTED_MESSAGE, request }, location.origin);
        }
      })
      .catch(() => {});
  };

  window.addEventListener("message", onMessage);
})();
