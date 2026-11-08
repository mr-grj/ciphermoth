// Desktop mode: the CipherMoth app on this computer, reached through its
// native-messaging host (docs/EXTENSION.md, design 4.3). No network: the
// browser starts the host, which relays to the running app over a same-user
// local socket or pipe.
//
// Everything after the handshake is end-to-end encrypted between this
// background and the app (shared/channel.ts); the host only relays. There is
// no session token on this side at all: the app opens the extension session
// for the pairing and keeps its token (design decision 40). What this side
// holds is the pairing key (non-extractable, IndexedDB) and, while a port is
// open, that connection's key (non-extractable, memory).

import { ApiError } from "./api";
import { type Pairing, deletePairing, loadPairing, savePairing } from "./pairing-store";
import { reportUnexpected } from "./report";
import { nativeMessagingReady, restart } from "./restart";
import { ext } from "../shared/browser";
import {
  Channel,
  bytes,
  commit,
  connectionKey,
  finish,
  fromBase64Url,
  newExchange,
  supportsX25519,
  toBase64Url,
  transcript,
} from "../shared/channel";
import { NATIVE_HOST } from "../shared/constants";

// The test build talks to the QA app's host and a --desktop-dev build to the
// development app's; a real build only ever to the real app's.
export const HOST = NATIVE_HOST;

const STEP_MS = 10_000;
const REQUEST_MS = 20_000;
// The user compares codes and answers in the app (which waits 120 s).
const APPROVAL_MS = 150_000;
// A port keeps the background alive; close it when nothing happens.
const IDLE_MS = 30_000;

export const NO_HOST = "no_host";
export const APP_NOT_RUNNING = "app_not_running";
export const UNPAIRED = "unpaired";
const APP_CLOSED = "app_closed";
const PROTOCOL = "protocol";
const NO_PERMISSION = "no_permission";
const RESTARTING = "restarting";

export const MESSAGES: Record<string, string> = {
  [NO_HOST]:
    "CipherMoth can't be reached from this browser. In the CipherMoth app, turn on Settings → Browser extension → Allow browser extensions.",
  [APP_NOT_RUNNING]: "The CipherMoth app isn't running.",
  [APP_CLOSED]: "The CipherMoth app closed the connection.",
  [UNPAIRED]: "This browser isn't paired with the CipherMoth app.",
  [PROTOCOL]: "The CipherMoth app and this extension don't understand each other. Update both.",
  [NO_PERMISSION]:
    "CipherMoth needs your permission to talk to the app. Allow it in the extension's settings.",
  [RESTARTING]: "CipherMoth is finishing its setup. Open it again in a moment.",
  locked: "CipherMoth is locked. Unlock it first.",
  denied: "Pairing wasn't allowed in CipherMoth.",
  busy: "CipherMoth is pairing another browser. Try again in a moment.",
  disabled: "Browser extensions are turned off in the CipherMoth app.",
  caller: "CipherMoth doesn't trust this copy of the extension.",
  // Every code the app or the host can send needs an entry: failure() turns
  // unknown codes into "protocol".
  unknown_pairing: "This browser isn't paired with the CipherMoth app any more.",
  launch_failed: "CipherMoth could not be started. Open it yourself.",
  timeout: "CipherMoth didn't answer in time.",
};

const failure = (code: string, status = 0): ApiError =>
  new ApiError(MESSAGES[code] ?? MESSAGES[PROTOCOL]!, status, code in MESSAGES ? code : PROTOCOL);

type Envelope = Record<string, unknown>;

const isEnvelope = (value: unknown): value is Envelope =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  typeof (value as Envelope).t === "string";

// One native-messaging port, read as a queue of messages.
class Port {
  private readonly port: chrome.runtime.Port;
  private readonly inbox: Envelope[] = [];
  private waiting: { resolve: (m: Envelope) => void; reject: (e: ApiError) => void } | null = null;
  private heard = false;
  closed: ApiError | null = null;

  constructor() {
    this.port = ext.runtime.connectNative(HOST);
    this.port.onMessage.addListener((message: unknown) => {
      this.heard = true;
      if (!isEnvelope(message)) return this.fail(failure(PROTOCOL));
      if (this.waiting) {
        const { resolve } = this.waiting;
        this.waiting = null;
        resolve(message);
      } else if (this.inbox.length < 8) {
        this.inbox.push(message);
      } else {
        this.fail(failure(PROTOCOL));
      }
    });
    this.port.onDisconnect.addListener((port) => {
      // Chromium: runtime.lastError; Firefox: port.error. A host that never
      // answered was not found or not allowed: the switch in the app is off.
      const reason =
        ext.runtime.lastError?.message ?? (port as { error?: { message?: string } }).error?.message;
      this.fail(failure(this.heard || !reason ? APP_CLOSED : NO_HOST));
    });
  }

  private fail(error: ApiError): void {
    if (this.closed) return;
    this.closed = error;
    try {
      this.port.disconnect();
    } catch {
      // already gone
    }
    this.waiting?.reject(error);
    this.waiting = null;
  }

  send(message: Envelope): void {
    if (this.closed) throw this.closed;
    try {
      this.port.postMessage(message);
    } catch {
      // Disconnected before the event arrived.
      this.fail(failure(this.heard ? APP_CLOSED : NO_HOST));
      throw this.closed;
    }
  }

  next(timeoutMs: number): Promise<Envelope> {
    const queued = this.inbox.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting = null;
        this.fail(failure("timeout"));
        reject(failure("timeout"));
      }, timeoutMs);
      this.waiting = {
        resolve: (m) => {
          clearTimeout(timer);
          resolve(m);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
    });
  }

  close(): void {
    this.fail(failure(APP_CLOSED));
  }
}

// A port to the host, once the browser lets this worker open one (see restart.ts).
const openPort = async (): Promise<Port> => {
  if (nativeMessagingReady()) return new Port();
  if (!(await hasNativePermission())) throw failure(NO_PERMISSION);
  await restart({ reopenOptions: false });
  throw failure(RESTARTING);
};

// An answer that is not part of the protocol: the host's own errors and the
// app's refusals become errors with their code.
const answerOf = (message: Envelope, type: string): Envelope => {
  if (message.t === type) return message;
  if (message.t === "error" || message.t === "refused") {
    throw failure(typeof message.code === "string" ? message.code : PROTOCOL);
  }
  throw failure(PROTOCOL);
};

interface Live {
  port: Port;
  channel: Channel;
  nextId: number;
}

let live: Live | null = null;
let idleTimer: ReturnType<typeof setTimeout> | null = null;
let queue: Promise<unknown> = Promise.resolve();

const drop = (): void => {
  live?.port.close();
  live = null;
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
};

const hello = async (port: Port, pairing: Pairing): Promise<Channel> => {
  const id = fromBase64Url(pairing.id, 16);
  if (!id) throw failure(UNPAIRED);
  const nonce = bytes(16);
  port.send({ t: "hello", id: pairing.id, nonce: toBase64Url(nonce) });
  let answer: Envelope;
  try {
    answer = answerOf(await port.next(STEP_MS), "hello_ok");
  } catch (error) {
    // The app no longer knows this pairing (removed in its Settings).
    if (error instanceof ApiError && error.code === "unknown_pairing") {
      await deletePairing();
      throw failure(UNPAIRED);
    }
    throw error;
  }
  const appNonce = fromBase64Url(answer.nonce, 16);
  if (!appNonce) throw failure(PROTOCOL);
  return new Channel(await connectionKey(pairing.key, id, nonce, appNonce));
};

const connect = async (): Promise<Live> => {
  if (live && !live.port.closed) return live;
  const pairing = await loadPairing();
  if (!pairing) throw failure(UNPAIRED);
  const port = await openPort();
  try {
    live = { port, channel: await hello(port, pairing), nextId: 1 };
    return live;
  } catch (error) {
    port.close();
    throw error;
  }
};

const decoder = new TextDecoder("utf-8", { fatal: true });

const request = async (link: Live, op: string, extra: Record<string, unknown>) => {
  const id = link.nextId++;
  const plain = new TextEncoder().encode(JSON.stringify({ id, op, ...extra }));
  link.port.send({ t: "msg", ...(await link.channel.seal(plain)) });
  const answer = answerOf(await link.port.next(REQUEST_MS), "msg");
  let reply: Record<string, unknown>;
  try {
    reply = JSON.parse(decoder.decode(await link.channel.open(answer.c, answer.d)));
  } catch {
    throw failure(PROTOCOL);
  }
  if (reply.id !== id || typeof reply.ok !== "boolean") throw failure(PROTOCOL);
  if (reply.ok) return reply.value;
  const code = typeof reply.code === "string" ? reply.code : "error";
  const status = typeof reply.status === "number" ? reply.status : code === "locked" ? 401 : 0;
  const detail = typeof reply.detail === "string" ? reply.detail.slice(0, 300) : null;
  throw new ApiError(detail ?? MESSAGES[code] ?? "CipherMoth refused the request.", status, code);
};

// One request to the app, in order. A connection the app closed in the
// meantime (idle, restart, lock) is replaced once.
export const call = (op: string, extra: Record<string, unknown> = {}): Promise<unknown> => {
  const run = async () => {
    for (let attempt = 0; ; attempt++) {
      const reused = Boolean(live && !live.port.closed);
      const link = await connect();
      try {
        const value = await request(link, op, extra);
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(drop, IDLE_MS);
        return value;
      } catch (error) {
        const closed = error instanceof ApiError && error.code === APP_CLOSED;
        const transport =
          !(error instanceof ApiError) || closed || link.port.closed || error.code === PROTOCOL;
        if (transport) drop();
        // The app ended a connection we had kept open: try once on a new one.
        if (closed && reused && attempt === 0) continue;
        throw error;
      }
    }
  };
  const next = queue.then(run, run);
  queue = next.catch(() => undefined);
  return next;
};

export const api = (route: "matches" | "search" | "credential" | "totp", body: unknown) =>
  call("api", { route, body });

// --- pairing ---------------------------------------------------------------------

interface PairingState {
  code: string | null;
  error: string | null;
  port: Port | null;
}

let pairing: PairingState | null = null;

export const pairingState = (): { code: string | null; error: string | null } | null =>
  pairing && { code: pairing.code, error: pairing.error };

export const cancelPairing = (): void => {
  pairing?.port?.close();
  pairing = null;
};

const pairingFailed = (state: PairingState, error: unknown): void => {
  state.port?.close();
  state.port = null;
  state.code = null;
  if (!(error instanceof ApiError)) reportUnexpected(error);
  state.error = error instanceof ApiError ? error.message : MESSAGES[PROTOCOL]!;
};

// Wait for the user's answer in the app, then prove the new key works before
// keeping it.
const awaitApproval = async (state: PairingState, port: Port, pairingKey: CryptoKey) => {
  try {
    const answer = answerOf(await port.next(APPROVAL_MS), "paired");
    if (typeof answer.id !== "string" || !fromBase64Url(answer.id, 16)) throw failure(PROTOCOL);
    const record = { id: answer.id, key: pairingKey };
    const link: Live = { port, channel: await hello(port, record), nextId: 1 };
    await request(link, "status", {});
    await savePairing(record);
    drop();
    live = link;
    idleTimer = setTimeout(drop, IDLE_MS);
    if (pairing === state) pairing = null;
  } catch (error) {
    if (pairing === state) pairingFailed(state, error);
  }
};

// Start pairing: returns once the code is known (the popup shows it while the
// user compares it with the app's dialog); approval is awaited in the background.
export const startPairing = async (browser: string): Promise<void> => {
  cancelPairing();
  drop();
  const port = await openPort();
  const state: PairingState = { code: null, error: null, port };
  pairing = state;
  try {
    const exchange = await newExchange();
    const nonce = bytes(16);
    port.send({
      t: "pair_commit",
      browser,
      commit: toBase64Url(await commit(exchange.publicKey, nonce)),
    });
    const offer = answerOf(await port.next(STEP_MS), "pair_key");
    const appPublic = fromBase64Url(offer.pub, 32);
    const appNonce = fromBase64Url(offer.nonce, 16);
    if (!appPublic || !appNonce) throw failure(PROTOCOL);
    port.send({
      t: "pair_reveal",
      pub: toBase64Url(exchange.publicKey),
      nonce: toBase64Url(nonce),
    });
    const salt = await transcript(browser, exchange.publicKey, nonce, appPublic, appNonce);
    const paired = await finish(exchange.privateKey, appPublic, salt);
    state.code = paired.sas;
    void awaitApproval(state, port, paired.pairingKey);
  } catch (error) {
    // The caller reports it; keeping it for the next status too showed it
    // twice in the settings, and again after the app was unlocked.
    state.port?.close();
    if (pairing === state) pairing = null;
    throw error;
  }
};

// Unpair on both sides: the app forgets this browser (and ends its session)
// when it can be reached; this side forgets the pairing either way.
export const unpair = async (): Promise<void> => {
  cancelPairing();
  if (await loadPairing()) await call("unpair").catch(() => undefined);
  drop();
  await deletePairing();
};

// --- the app --------------------------------------------------------------------

export const hasNativePermission = (): Promise<boolean> =>
  ext.permissions.contains({ permissions: ["nativeMessaging"] }).catch(() => false);

export type DesktopPhase =
  | "setup"
  | "unsupported"
  | "pairing"
  | "unpaired"
  | "no-host"
  | "no-app"
  | "locked"
  | "unlocked"
  | "offline";

export const desktopPhase = async (): Promise<{
  phase: DesktopPhase;
  code: string | null;
  error: string | null;
}> => {
  const none = { code: null, error: null };
  if (!(await hasNativePermission())) return { phase: "setup", ...none };
  if (!(await supportsX25519())) return { phase: "unsupported", ...none };
  if (pairing?.error) {
    // A failed pairing is reported once; the next look starts fresh (the app
    // may be unlocked by then).
    const error = pairing.error;
    pairing = null;
    return { phase: "unpaired", code: null, error };
  }
  if (pairing) return { phase: "pairing", code: pairing.code, error: null };
  if (!(await loadPairing())) return { phase: "unpaired", ...none };
  try {
    const value = (await call("status")) as { state?: unknown } | null;
    return { phase: value?.state === "unlocked" ? "unlocked" : "locked", ...none };
  } catch (error) {
    const code = error instanceof ApiError ? error.code : null;
    if (code === NO_HOST) return { phase: "no-host", ...none };
    if (code === APP_NOT_RUNNING || code === APP_CLOSED) return { phase: "no-app", ...none };
    if (code === UNPAIRED) return { phase: "unpaired", ...none };
    if (!(error instanceof ApiError)) reportUnexpected(error);
    return {
      phase: "offline",
      code: null,
      error: error instanceof ApiError ? error.message : "Something went wrong.",
    };
  }
};

// "Open CipherMoth": the host starts the app.
export const launchApp = async (): Promise<void> => {
  drop();
  const port = await openPort();
  try {
    port.send({ t: "launch" });
    answerOf(await port.next(STEP_MS), "launched");
  } finally {
    port.close();
  }
};

// "Unlock CipherMoth": bring the app's window forward.
export const showApp = async (): Promise<void> => {
  await call("show");
};

// Locking in desktop mode locks the app (which ends every extension session).
export const lockApp = async (): Promise<void> => {
  await call("lock").catch(() => undefined);
  drop();
};

export const forgetDesktop = drop;
