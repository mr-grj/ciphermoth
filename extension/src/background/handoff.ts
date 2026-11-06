// "Unlock in CipherMoth": the web app unlocks (master password, security key,
// passkey) and hands this extension a session token.
//
// 1. A random 256-bit request nonce is made here and never sent to a server
//    (it travels in the URL fragment).
// 2. The bridge content script is registered for the vault's origin only, for
//    as long as the request is pending, and a tab opens
//    <vault>/#/connect-extension?request=<nonce>&browser=<name>.
// 3. After the user confirms in the web app, it posts the token to its own
//    window; the bridge forwards it here.
// 4. The token is accepted once, only from the top frame of that tab, on that
//    origin, with that nonce, within five minutes, and only after the server
//    confirms it is a live extension session.

import { adoptToken, browserName } from "./session";
import { getConfig, getHandoff, installId, setHandoff } from "./storage";
import { ext, randomToken, sameSecret } from "../shared/browser";
import { BRIDGE_SCRIPT_ID, HANDOFF_TTL_MS } from "../shared/constants";
import type { MessageOf } from "../shared/messages";

export const HANDOFF_ALARM = "ciphermoth-handoff-expired";
const CLOSE_DELAY_MS = 1500;

const unregisterBridge = async (): Promise<void> => {
  await ext.scripting.unregisterContentScripts({ ids: [BRIDGE_SCRIPT_ID] }).catch(() => {});
};

export const cancelHandoff = async (): Promise<void> => {
  await setHandoff(null);
  await unregisterBridge();
  await ext.alarms.clear(HANDOFF_ALARM);
};

export const startHandoff = async (): Promise<void> => {
  const config = await getConfig();
  if (!config) throw new Error("Connect to your CipherMoth first.");
  await cancelHandoff();
  const request = randomToken(32);
  await ext.scripting.registerContentScripts([
    {
      id: BRIDGE_SCRIPT_ID,
      matches: [`${config.vault}/*`],
      js: ["bridge.js"],
      runAt: "document_start",
      allFrames: false,
      persistAcrossSessions: false,
    },
  ]);
  const client = await installId();
  const url = `${config.vault}/#/connect-extension?request=${request}&browser=${browserName()}&client=${client}`;
  const tab = await ext.tabs.create({ url, active: true });
  if (tab.id === undefined) {
    await unregisterBridge();
    throw new Error("Could not open CipherMoth.");
  }
  const expires = Date.now() + HANDOFF_TTL_MS;
  await setHandoff({ request, tabId: tab.id, vault: config.vault, expires });
  await ext.alarms.create(HANDOFF_ALARM, { when: expires });
};

const senderOrigin = (sender: chrome.runtime.MessageSender): string | null => {
  const raw = (sender as { origin?: string }).origin ?? sender.url;
  if (!raw) return null;
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
};

export const receiveToken = async (
  message: MessageOf<"handoff-token">,
  sender: chrome.runtime.MessageSender
): Promise<boolean> => {
  const pending = await getHandoff();
  if (
    !pending ||
    Date.now() >= pending.expires ||
    sender.id !== ext.runtime.id ||
    sender.tab?.id !== pending.tabId ||
    sender.frameId !== 0 ||
    senderOrigin(sender) !== pending.vault ||
    !sameSecret(message.request, pending.request)
  )
    return false;
  // Single use: consumed before anything else happens, success or not.
  await cancelHandoff();
  const config = await getConfig();
  if (!config || config.vault !== pending.vault) return false;
  const adopted = await adoptToken(message.token);
  if (adopted) {
    setTimeout(() => {
      ext.tabs.remove(pending.tabId).catch(() => {});
    }, CLOSE_DELAY_MS);
  }
  return adopted;
};
