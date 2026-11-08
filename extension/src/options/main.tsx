import { render } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";

import { ext } from "../shared/browser";
import { TARGET, VERSION } from "../shared/constants";
import type { Status } from "../shared/messages";
import { serverOrigin } from "../shared/url";
import { MothIcon, send } from "../ui/shared";
import { notNeededBy, permissionOrigins, targetFor } from "../shared/target";

const formatTimeout = (ms: number | null): string => {
  if (!ms) return "your vault's inactivity timeout";
  if (ms < 60_000 || ms % 60_000 !== 0) return `${Math.round(ms / 1000)} s of inactivity`;
  return `${ms / 60_000} min of inactivity`;
};

const Connection = ({ status, reload }: { status: Status; reload: () => void }) => {
  const [vault, setVault] = useState(status.vault ?? "");
  const [api, setApi] = useState(
    status.api && status.vault && status.api !== `${status.vault}/api` ? status.api : ""
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; bad: boolean } | null>(null);

  const connect = async (event: Event) => {
    event.preventDefault();
    setMessage(null);
    const target = targetFor(vault, api || null);
    if (typeof target === "string") {
      setMessage({ text: target, bad: true });
      return;
    }
    // Ask for exactly the vault's origin (and the API's, if separate), right
    // here in the click: the browser shows the user which site it is.
    const origins = permissionOrigins(target);
    // Access the stored connection uses stays, whatever happens to this attempt.
    const held =
      status.vault && status.api ? permissionOrigins({ vault: status.vault, api: status.api }) : [];
    const drop = async (patterns: string[]) => {
      if (patterns.length) await ext.permissions.remove({ origins: patterns }).catch(() => false);
    };
    const granted = await ext.permissions.request({ origins }).catch(() => false);
    if (!granted) {
      setMessage({
        text: "CipherMoth needs access to your vault's address to talk to it.",
        bad: true,
      });
      return;
    }
    setBusy(true);
    try {
      const next = await send<Status>({
        type: "configure",
        vault: target.vault,
        api: target.api,
      });
      if (next.phase === "too-old") {
        await drop(notNeededBy(origins, held));
        setMessage({ text: next.error ?? "Update CipherMoth first.", bad: true });
        return;
      }
      // A new address: the old one's access is no longer needed.
      await drop(notNeededBy(held, origins));
      setMessage({
        text: "Connected. Open CipherMoth from the toolbar to unlock.",
        bad: false,
      });
      reload();
    } catch (err) {
      await drop(notNeededBy(origins, held));
      setMessage({
        text: err instanceof Error ? err.message : "Could not connect.",
        bad: true,
      });
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    await send({ type: "forget" }).catch(() => {});
    setVault("");
    setApi("");
    setMessage({
      text: "Disconnected. Nothing of your vault is left in this browser.",
      bad: false,
    });
    reload();
  };

  const connected = status.mode === "server" && status.phase !== "setup";
  return (
    <section aria-labelledby="connection">
      <h2 id="connection">Connection</h2>
      {connected ? (
        <div class="row">
          <span class={`status ${status.phase === "unlocked" ? "on" : ""}`}>
            {status.phase === "unlocked"
              ? "Unlocked"
              : status.phase === "locked"
                ? "Locked"
                : "Not reachable"}
          </span>
          <code>{status.vault}</code>
        </div>
      ) : (
        <p>
          Connect to your own CipherMoth server. The extension asks your browser for access to that
          one address only.
        </p>
      )}
      <form onSubmit={connect}>
        <label for="vault">Vault address</label>
        <input
          id="vault"
          class="field mono"
          placeholder="https://vault.example.com"
          value={vault}
          autoFocus={!connected}
          spellcheck={false}
          onInput={(e) => setVault((e.target as HTMLInputElement).value)}
        />
        <details open={Boolean(api)}>
          <summary>API on another address?</summary>
          <label for="api">API address</label>
          <input
            id="api"
            class="field mono"
            placeholder={
              serverOrigin(vault)
                ? `${vault.replace(/\/+$/, "")}/api`
                : "https://vault.example.com:8000/api"
            }
            value={api}
            spellcheck={false}
            onInput={(e) => setApi((e.target as HTMLInputElement).value)}
          />
          <p style={{ marginTop: "6px", fontSize: "12px" }}>
            Leave empty when the API is at <code>/api</code> on the vault address (the usual reverse
            proxy setup). The Docker defaults are UI on port 3000 and API on port 8000.
          </p>
        </details>
        <div class="buttons">
          <button class="button primary" type="submit" disabled={busy || !vault.trim()}>
            {busy ? "Connecting…" : connected ? "Save" : "Connect"}
          </button>
          {connected && (
            <button class="button danger" type="button" onClick={disconnect}>
              Disconnect
            </button>
          )}
        </div>
      </form>
      {message && (
        <p
          class={message.bad ? "error" : ""}
          role={message.bad ? "alert" : "status"}
          style={{ marginTop: "12px" }}
        >
          {message.text}
        </p>
      )}
    </section>
  );
};

const NEEDS_NATIVE_PERMISSION =
  "CipherMoth needs your permission to talk to the app on this computer.";

const DESKTOP_STATES: Partial<Record<Status["phase"], string>> = {
  unlocked: "Paired · CipherMoth is unlocked",
  locked: "Paired · CipherMoth is locked",
  "no-app": "Paired · the CipherMoth app isn't running",
  "no-host": "Browser extensions are turned off in the CipherMoth app",
  offline: "Can't reach the CipherMoth app",
};

// "482913" -> "482 913", as the app's dialog shows it.
const spacedCode = (code: string | null): string =>
  code && /^\d{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : "";

const DesktopConnection = ({ status, reload }: { status: Status; reload: () => void }) => {
  const [message, setMessage] = useState<{ text: string; bad: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const pairing = status.phase === "pairing";

  // The pairing is answered in the app; follow it here.
  useEffect(() => {
    if (!pairing) return;
    const timer = setInterval(reload, 1000);
    return () => clearInterval(timer);
  }, [pairing, reload]);

  const pair = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await send<Status>({ type: "pair" });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Could not pair.", bad: true });
    } finally {
      setBusy(false);
      reload();
    }
  };

  const disconnect = async () => {
    await send({ type: "unpair" }).catch(() => {});
    setMessage({
      text: "Unpaired in this browser and in the app. Nothing of your vault is left in this browser.",
      bad: false,
    });
    reload();
  };

  // The permission was removed (in the browser's extension settings): ask again.
  const allow = async () => {
    setMessage(null);
    const granted = await ext.permissions
      .request({ permissions: ["nativeMessaging"] })
      .catch(() => false);
    if (!granted) {
      setMessage({ text: NEEDS_NATIVE_PERMISSION, bad: true });
      return;
    }
    await send<Status>({ type: "use-desktop" }).catch(() => undefined);
    reload();
  };

  const state = DESKTOP_STATES[status.phase];
  return (
    <section aria-labelledby="desktop">
      <h2 id="desktop">CipherMoth app</h2>
      {status.phase === "setup" && (
        <>
          <p>{NEEDS_NATIVE_PERMISSION}</p>
          <div class="buttons">
            <button class="button primary" onClick={() => void allow()}>
              Allow
            </button>
          </div>
        </>
      )}
      {status.phase === "unsupported" && (
        <p class="error" role="alert">
          This browser can't pair with the CipherMoth app. Update to Chrome 133, Firefox 130 or
          newer.
        </p>
      )}
      {state && (
        <div class="row">
          <span class={`status ${status.phase === "unlocked" ? "on" : ""}`}>{state}</span>
        </div>
      )}
      {status.phase === "unpaired" && (
        <>
          <p>
            Pair this browser with CipherMoth on this computer. The app shows a code; check that it
            is the one shown here, then allow it. CipherMoth must be unlocked.
          </p>
          {status.error && (
            <p class="error" role="alert">
              {status.error}
            </p>
          )}
          <div class="buttons">
            <button class="button primary" onClick={pair} disabled={busy}>
              {busy ? "Pairing…" : "Pair"}
            </button>
          </div>
        </>
      )}
      {pairing && (
        <>
          <p>Check that CipherMoth shows this code, then choose Allow there:</p>
          <p class="pairing-code" aria-label={`Pairing code ${spacedCode(status.pairingCode)}`}>
            {spacedCode(status.pairingCode)}
          </p>
          <div class="buttons">
            <button
              class="button"
              onClick={() => {
                void send({ type: "cancel-pair" }).finally(reload);
              }}
            >
              Cancel
            </button>
          </div>
        </>
      )}
      {status.phase !== "unpaired" &&
        !pairing &&
        status.phase !== "unsupported" &&
        status.phase !== "setup" && (
          <div class="buttons">
            <button class="button danger" type="button" onClick={disconnect}>
              Unpair
            </button>
          </div>
        )}
      {message && (
        <p
          class={message.bad ? "error" : ""}
          role={message.bad ? "alert" : "status"}
          style={{ marginTop: "12px" }}
        >
          {message.text}
        </p>
      )}
      <p style={{ marginTop: "12px", fontSize: "12px" }}>
        The extension talks to the app through your browser's native messaging, never over the
        network. In the app, turn on Settings → Browser extension → Allow browser extensions.
      </p>
    </section>
  );
};

// Where this browser fills from (design decision 39): one at a time.
const Mode = ({ status, reload }: { status: Status; reload: () => void }) => {
  const [chosen, setChosen] = useState<"server" | "desktop">(status.mode ?? "server");
  const [error, setError] = useState("");

  const choose = async (mode: "server" | "desktop") => {
    setError("");
    setChosen(mode);
    if (mode !== "desktop" || status.mode === "desktop") return;
    // Asked here, in the click, so the browser can show its prompt.
    const granted = await ext.permissions
      .request({ permissions: ["nativeMessaging"] })
      .catch(() => false);
    if (!granted) {
      setChosen(status.mode ?? "server");
      setError(NEEDS_NATIVE_PERMISSION);
      return;
    }
    try {
      await send<Status>({ type: "use-desktop" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not switch.");
    }
    reload();
  };

  return (
    <section aria-labelledby="mode">
      <h2 id="mode">Fill from</h2>
      <div class="choices" role="radiogroup" aria-labelledby="mode">
        <label class="choice">
          <input
            type="radio"
            name="mode"
            checked={chosen === "desktop"}
            onChange={() => void choose("desktop")}
          />
          <span>
            CipherMoth app on this computer
            <small>Unlock with the app (master password, security key or Touch ID).</small>
          </span>
        </label>
        <label class="choice">
          <input
            type="radio"
            name="mode"
            checked={chosen === "server"}
            onChange={() => void choose("server")}
          />
          <span>
            Your CipherMoth server
            <small>A vault you host, over HTTPS.</small>
          </span>
        </label>
      </div>
      {error && (
        <p class="error" role="alert">
          {error}
        </p>
      )}
      {chosen === "desktop" && status.mode === "desktop" && (
        <DesktopConnection status={status} reload={reload} />
      )}
      {chosen === "desktop" && status.mode !== "desktop" && (
        <div class="buttons">
          <button class="button primary" onClick={() => void choose("desktop")}>
            Use the CipherMoth app
          </button>
        </div>
      )}
      {chosen === "server" && <Connection status={status} reload={reload} />}
    </section>
  );
};

const Preferences = ({ status, reload }: { status: Status; reload: () => void }) => {
  const save = async (patch: Partial<Pick<Status, "subdomains" | "strictClipboard">>) => {
    await send({
      type: "settings",
      subdomains: patch.subdomains ?? status.subdomains,
      strictClipboard: patch.strictClipboard ?? status.strictClipboard,
    });
    reload();
  };

  const toggleStrict = async (on: boolean) => {
    if (on) {
      const granted = await ext.permissions
        .request({ permissions: ["clipboardRead"] })
        .catch(() => false);
      if (!granted) return;
    } else {
      await ext.permissions.remove({ permissions: ["clipboardRead"] }).catch(() => false);
    }
    await save({ strictClipboard: on });
  };

  const shortcuts = () => {
    if (TARGET === "chromium") void ext.tabs.create({ url: "chrome://extensions/shortcuts" });
  };

  return (
    <section aria-labelledby="filling">
      <h2 id="filling">Filling</h2>
      <div class="toggle">
        <label for="subdomains" style={{ margin: 0 }}>
          <span>Match subdomains</span>
          <small>
            Offer a login saved for example.com on login.example.com too. Never across public
            suffixes such as co.uk or github.io.
          </small>
        </label>
        <input
          id="subdomains"
          type="checkbox"
          checked={status.subdomains}
          disabled={status.phase === "setup"}
          onChange={(e) => void save({ subdomains: (e.target as HTMLInputElement).checked })}
        />
      </div>
      <div class="toggle">
        <label for="strict" style={{ margin: 0 }}>
          <span>Only clear what CipherMoth copied</span>
          <small>
            Copied passwords are cleared after 30 seconds. With this on, CipherMoth first checks the
            clipboard still holds its copy, so it never wipes something you copied since. Your
            browser will ask to let it read the clipboard.
          </small>
        </label>
        <input
          id="strict"
          type="checkbox"
          checked={status.strictClipboard}
          disabled={status.phase === "setup"}
          onChange={(e) => void toggleStrict((e.target as HTMLInputElement).checked)}
        />
      </div>
      {status.mode === "desktop" ? (
        <p>Fills only while the CipherMoth app is unlocked. Locking the app locks this too.</p>
      ) : (
        <p>
          Locks after {formatTimeout(status.idleTimeoutMs)}, the same as your vault (change it in
          CipherMoth's Settings), and when the browser closes.
        </p>
      )}
      <h2 style={{ marginTop: "18px" }}>Keyboard shortcuts</h2>
      <p>
        Open CipherMoth: <code>Alt+Shift+M</code>. Fill this page:{" "}
        <code>{/Mac/.test(navigator.platform) ? "⌘+Shift+L" : "Ctrl+Shift+L"}</code>.
      </p>
      {TARGET === "chromium" ? (
        <button class="button" onClick={shortcuts}>
          Change shortcuts
        </button>
      ) : (
        <p>
          To change them, open <code>about:addons</code>, click the gear icon and choose “Manage
          Extension Shortcuts”.
        </p>
      )}
    </section>
  );
};

const About = () => (
  <section aria-labelledby="about">
    <h2 id="about">About</h2>
    <p>
      CipherMoth extension <code>{VERSION}</code>. No CipherMoth account, ever. The extension comes
      from your browser's store, which sees the install like any extension. It only ever talks to
      your own CipherMoth, and only when you ask it to fill. Only the page's origin is sent to find
      matches, never its path or contents. No favicons, no analytics, no remote configuration.
    </p>
    <p>
      Installed from a file? Check it against <code>SHA256SUMS</code> from the GitHub release:{" "}
      <code>shasum -a 256 -c SHA256SUMS</code>. The build is reproducible; see{" "}
      <code>docs/EXTENSION.md</code>.
    </p>
  </section>
);

const App = () => {
  const [status, setStatus] = useState<Status | null>(null);
  const reload = useCallback(() => {
    send<Status>({ type: "status" }).then(setStatus, () => setStatus(null));
  }, []);
  useEffect(reload, [reload]);

  return (
    <main>
      <h1>
        <span class="moth">
          <MothIcon size={28} />
        </span>
        <span class="wordmark">
          Cipher<span>Moth</span>
        </span>
      </h1>
      <p class="tagline">Your secrets stay in the dark.</p>
      {status ? (
        <>
          <Mode status={status} reload={reload} />
          <Preferences status={status} reload={reload} />
        </>
      ) : (
        <p class="muted">Loading…</p>
      )}
      <About />
    </main>
  );
};

const root = document.getElementById("app");
if (root) render(<App />, root);
