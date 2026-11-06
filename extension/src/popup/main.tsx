import { render } from "preact";
import { useCallback, useEffect, useMemo, useRef, useState } from "preact/hooks";

import { ext, sha256Hex } from "../shared/browser";
import { CLIPBOARD_CLEAR_MS, E2E } from "../shared/constants";
import type { FillOutcome, Login, PageInfo, Status } from "../shared/messages";
import { unicodeHost } from "../shared/url";
import { BackgroundError, Icon, MothIcon, send } from "../ui/shared";

interface Listing {
  page: PageInfo;
  logins: Login[];
  truncated: boolean;
}

type Toast = { text: string; tone: "ok" | "bad" | "warn" } | null;

type Prompt =
  | { kind: "mismatch"; login: Login }
  | { kind: "insecure"; login: Login; canFill: boolean }
  | { kind: "no-fields"; login: Login; text: string }
  | null;

const AVATAR_COLORS = ["#7dd3c0", "#a8e6d8", "#e0982f", "#8b9dc9", "#d9a3c7", "#9fd18b"];

const avatarColor = (name: string): string => {
  let hash = 0;
  for (const char of name) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  return AVATAR_COLORS[hash % AVATAR_COLORS.length] ?? "#7dd3c0";
};

const initial = (name: string): string => (Array.from(name.trim())[0] ?? "?").toUpperCase();

const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl+";

const targetTab = async (): Promise<number | null> => {
  // Test build only: Playwright cannot click the toolbar button.
  const forced = E2E ? new URLSearchParams(location.hash.slice(1)).get("tab") : null;
  if (forced) return Number(forced);
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
};

// Preact sets the autofocus attribute, which browsers honour only for the first
// element of a page; views that appear later focus themselves.
const focusOnMount = (element: HTMLElement | null): void => element?.focus();

const close = () => {
  if (!E2E) window.close();
};

const FILL_MESSAGES: Record<string, string> = {
  "username-only": "Username filled. Fill again on the next step.",
  "password-only": "Password filled.",
  "no-fields": "No login fields found on this page.",
  hidden: "The login fields on this page are hidden or covered, so nothing was filled.",
  "new-password": "This looks like a sign-up or password change form, so nothing was filled.",
  origin: "The page changed before the fill, so nothing was filled. Try again.",
  frame:
    "No login fields on this page itself. If the form is inside a frame, CipherMoth does not fill it: copy instead.",
  blocked: "This page can't be filled. Copy the password instead.",
};

// --- small pieces -------------------------------------------------------------

const Header = ({ onLock }: { onLock?: () => void }) => (
  <header class="top">
    <span class="moth">
      <MothIcon />
    </span>
    <span class="wordmark">
      Cipher<span>Moth</span>
    </span>
    {onLock && (
      <button class="icon-button" title="Lock" aria-label="Lock" onClick={onLock}>
        <Icon name="lock" />
      </button>
    )}
    <button
      class="icon-button"
      title="Settings"
      aria-label="Settings"
      onClick={() => {
        void ext.runtime.openOptionsPage();
        close();
      }}
    >
      <Icon name="gear" />
    </button>
  </header>
);

const Ring = ({ seconds }: { seconds: number }) => {
  const radius = 6;
  const length = 2 * Math.PI * radius;
  return (
    <svg class="ring" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
      <circle
        cx="8"
        cy="8"
        r={radius}
        fill="none"
        stroke="currentColor"
        opacity="0.25"
        stroke-width="2"
      />
      <circle
        cx="8"
        cy="8"
        r={radius}
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-dasharray={`${(length * seconds) / 30} ${length}`}
      />
    </svg>
  );
};

// --- states ------------------------------------------------------------------

const Setup = () => (
  <main class="centered">
    <div class="hero">
      <MothIcon size={44} />
    </div>
    <h1>Fill logins from your CipherMoth</h1>
    <p>Connect this browser to your own CipherMoth server. No account, nothing in between.</p>
    <button
      class="button primary"
      ref={focusOnMount}
      onClick={() => {
        void ext.runtime.openOptionsPage();
        close();
      }}
    >
      Set up CipherMoth
    </button>
  </main>
);

const Problem = ({ status, onRetry }: { status: Status; onRetry: () => void }) => (
  <main class="centered" role="alert">
    <h1>{status.phase === "too-old" ? "CipherMoth needs an update" : "Can't reach CipherMoth"}</h1>
    <p>{status.error}</p>
    <div class="stack">
      {status.phase === "offline" && (
        <button class="button primary" ref={focusOnMount} onClick={onRetry}>
          Try again
        </button>
      )}
      <button
        class="button"
        onClick={() => {
          void ext.runtime.openOptionsPage();
          close();
        }}
      >
        Open settings
      </button>
    </div>
  </main>
);

const Locked = ({ status, onUnlocked }: { status: Status; onUnlocked: (s: Status) => void }) => {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [needsHandoff, setNeedsHandoff] = useState(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError("");
    try {
      const next = await send<Status>({ type: "unlock", password });
      setPassword("");
      onUnlocked(next);
    } catch (err) {
      if (err instanceof BackgroundError && err.code === "use_handoff") setNeedsHandoff(true);
      setError(err instanceof Error ? err.message : "Could not unlock.");
    } finally {
      setBusy(false);
    }
  };

  const handoff = async () => {
    setError("");
    try {
      await send({ type: "handoff" });
      close();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open CipherMoth.");
    }
  };

  return (
    <main class="centered">
      <h1>Unlock</h1>
      <p class="mono" style={{ fontSize: "12px" }}>
        {status.vault}
      </p>
      {status.handoffPending && (
        <p class="warn">Finish unlocking in the CipherMoth tab, then open this again.</p>
      )}
      {!needsHandoff && (
        <form class="stack" onSubmit={submit}>
          <label class="sr-only" for="master">
            Master password
          </label>
          <input
            id="master"
            class="field"
            type="password"
            autoComplete="off"
            placeholder="Master password"
            ref={focusOnMount}
            value={password}
            onInput={(e) => setPassword((e.target as HTMLInputElement).value)}
          />
          <button class="button primary" type="submit" disabled={busy || !password}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        </form>
      )}
      {error && (
        <p class="error" role="alert">
          {error}
        </p>
      )}
      <button class="button" onClick={handoff} ref={needsHandoff ? focusOnMount : null}>
        <Icon name="shield" size={16} /> Unlock in CipherMoth
      </button>
      {!needsHandoff && (
        <p style={{ fontSize: "12px" }}>Use this for a security key, passkey or Touch ID.</p>
      )}
    </main>
  );
};

// --- the list ------------------------------------------------------------------

const Unlocked = ({ vault, onLocked }: { vault: string | null; onLocked: () => void }) => {
  const [listing, setListing] = useState<Listing | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Login[] | null>(null);
  const [selected, setSelected] = useState(0);
  const [toast, setToast] = useState<Toast>(null);
  const [prompt, setPrompt] = useState<Prompt>(null);
  const [codes, setCodes] = useState<Record<number, { code: string; until: number }>>({});
  const [now, setNow] = useState(Date.now());
  const searchRef = useRef<HTMLInputElement>(null);
  const loaded = Boolean(listing);
  useEffect(() => {
    if (loaded) searchRef.current?.focus();
  }, [loaded]);

  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof BackgroundError && err.code === "invalid_session") return onLocked();
      setToast({
        text: err instanceof Error ? err.message : "Something went wrong.",
        tone: "bad",
      });
    },
    [onLocked]
  );

  useEffect(() => {
    (async () => {
      const tabId = await targetTab();
      if (tabId === null) {
        setListing({
          page: { tabId: -1, origin: null, host: null, insecure: false },
          logins: [],
          truncated: false,
        });
        return;
      }
      setListing(await send<Listing>({ type: "matches", tabId }));
    })().catch(fail);
  }, [fail]);

  useEffect(() => {
    if (!query.trim()) {
      setResults(null);
      return;
    }
    // An answer for a query the user has since changed or cleared is dropped,
    // so a slow or out-of-order reply never shows (or fills from) old results.
    let live = true;
    const timer = setTimeout(() => {
      send<{ logins: Login[] }>({ type: "search", query })
        .then((found) => {
          if (!live) return;
          setResults(found.logins);
          setSelected(0);
        })
        .catch((error) => {
          if (live) fail(error);
        });
    }, 120);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [query, fail]);

  useEffect(() => {
    if (!Object.keys(codes).length) return;
    const timer = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(timer);
  }, [codes]);

  const page = listing?.page ?? null;
  const matchIds = useMemo(() => new Set(listing?.logins.map((l) => l.id)), [listing]);
  const rows = results ?? listing?.logins ?? [];
  const current = rows[Math.min(selected, rows.length - 1)];

  const copy = async (login: Login, what: "password" | "username" | "totp") => {
    const origin = page?.origin ?? "https://invalid.invalid";
    const confirmed = !matchIds.has(login.id);
    try {
      let value: string;
      let label: string;
      if (what === "totp") {
        const totp = await send<{ code: string; expiresIn: number }>({
          type: "totp",
          id: login.id,
          origin,
          confirmed,
        });
        value = totp.code;
        label = "2FA code";
        setCodes((all) => ({
          ...all,
          [login.id]: { code: totp.code, until: Date.now() + totp.expiresIn * 1000 },
        }));
      } else {
        const credential = await send<{ username: string | null; password: string }>({
          type: "credential",
          id: login.id,
          origin,
          confirmed,
        });
        value = (what === "password" ? credential.password : credential.username) ?? "";
        label = what === "password" ? "Password" : "Username";
      }
      await navigator.clipboard.writeText(value);
      await send({ type: "copied", digest: await sha256Hex(value) });
      setToast({
        text: `${label} copied. Clears in ${Math.round(CLIPBOARD_CLEAR_MS / 1000)} s.`,
        tone: "ok",
      });
    } catch (err) {
      fail(err);
    }
  };

  const doFill = async (login: Login, confirmed: boolean) => {
    if (!page?.origin) return;
    setPrompt(null);
    try {
      const outcome = await send<FillOutcome>({
        type: "fill",
        tabId: page.tabId,
        id: login.id,
        origin: page.origin,
        confirmed,
      });
      if (outcome.reason === "filled" || outcome.reason === "password-only") {
        setToast({ text: FILL_MESSAGES[outcome.reason] ?? "Filled.", tone: "ok" });
        if (outcome.reason === "filled") close();
        return;
      }
      if (outcome.reason === "username-only") {
        setToast({ text: FILL_MESSAGES["username-only"] ?? "", tone: "ok" });
        return;
      }
      setPrompt({ kind: "no-fields", login, text: FILL_MESSAGES[outcome.reason] ?? "" });
    } catch (err) {
      fail(err);
    }
  };

  const fill = (login: Login) => {
    setToast(null);
    if (!page?.origin) {
      setToast({
        text: "This tab has no web page CipherMoth can fill. Copy instead.",
        tone: "warn",
      });
      return;
    }
    const matched = matchIds.has(login.id);
    if (page.insecure) {
      setPrompt({ kind: "insecure", login, canFill: matched });
      return;
    }
    if (!matched) {
      setPrompt({ kind: "mismatch", login });
      return;
    }
    void doFill(login, false);
  };

  const lockNow = async () => {
    await send({ type: "lock" }).catch(() => {});
    onLocked();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    const mod = isMac ? event.metaKey : event.ctrlKey;
    if (event.key === "Escape") {
      event.preventDefault();
      if (prompt) setPrompt(null);
      else close();
      return;
    }
    if (prompt) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelected((s) => Math.min(s + 1, Math.max(rows.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelected((s) => Math.max(s - 1, 0));
    } else if (event.key === "Enter" && current) {
      const target = event.target as HTMLElement;
      if (target.tagName === "BUTTON") return;
      event.preventDefault();
      fill(current);
    } else if (mod && event.key.toLowerCase() === "c" && current) {
      const input = searchRef.current;
      const selecting =
        input && document.activeElement === input && input.selectionStart !== input.selectionEnd;
      if (selecting) return;
      event.preventDefault();
      void copy(current, event.shiftKey ? "username" : "password");
    }
  };

  // Keys work wherever focus is in the popup (also before the search box has it).
  const keyHandler = useRef(onKeyDown);
  keyHandler.current = onKeyDown;
  useEffect(() => {
    const listener = (event: KeyboardEvent) => keyHandler.current(event);
    document.addEventListener("keydown", listener);
    return () => document.removeEventListener("keydown", listener);
  }, []);

  if (!listing) {
    return (
      <>
        <Header onLock={lockNow} />
        <div class="loading" aria-label="Loading">
          <MothIcon size={32} />
        </div>
      </>
    );
  }

  const unicode = page?.host ? unicodeHost(page.host.replace(/^http:\/\//, "")) : null;
  const listLabel = results ? "Search results" : "Logins for this site";

  return (
    <div>
      <Header onLock={lockNow} />
      <div class="page mono" title={unicode ? `${page?.host} (${unicode})` : (page?.host ?? "")}>
        {page?.host ? (
          page.insecure ? (
            <span class="insecure">⚠ {page.host} · not secure</span>
          ) : (
            page.host
          )
        ) : (
          "No web page in this tab"
        )}
      </div>
      <div class="search">
        <span class="glass">
          <Icon name="search" size={16} />
        </span>
        <label class="sr-only" for="search">
          Search logins
        </label>
        <input
          id="search"
          ref={searchRef}
          class="field"
          type="search"
          placeholder="Search logins"
          autoComplete="off"
          spellcheck={false}

          role="combobox"
          aria-controls="logins"
          aria-expanded="true"
          aria-activedescendant={current ? `login-${current.id}` : undefined}
          value={query}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
        />
      </div>

      {prompt && (
        <div class="panel" role="alertdialog" aria-live="assertive">
          {prompt.kind === "mismatch" && (
            <>
              <p>
                This login is saved for <strong>{prompt.login.host ?? "no website"}</strong>. Fill
                it on <strong>{page?.host}</strong>?
              </p>
              <div class="buttons">
                <button class="button" onClick={() => setPrompt(null)}>
                  Cancel
                </button>
                <button
                  class="button primary"
                  ref={focusOnMount}
                  onClick={() => void doFill(prompt.login, true)}
                >
                  Fill anyway
                </button>
              </div>
            </>
          )}
          {prompt.kind === "insecure" && (
            <>
              <p>This page isn't secure (HTTP). Copy instead?</p>
              <div class="buttons">
                {prompt.canFill && (
                  <button class="button" onClick={() => void doFill(prompt.login, false)}>
                    Fill anyway
                  </button>
                )}
                <button
                  class="button primary"
                  ref={focusOnMount}
                  onClick={() => {
                    setPrompt(null);
                    void copy(prompt.login, "password");
                  }}
                >
                  Copy password
                </button>
              </div>
            </>
          )}
          {prompt.kind === "no-fields" && (
            <>
              <p>{prompt.text}</p>
              <div class="buttons">
                <button class="button" onClick={() => setPrompt(null)}>
                  Close
                </button>
                <button
                  class="button primary"
                  ref={focusOnMount}
                  onClick={() => {
                    setPrompt(null);
                    void copy(prompt.login, "password");
                  }}
                >
                  Copy password
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {toast && (
        <div class={`toast ${toast.tone === "ok" ? "" : toast.tone}`} role="status">
          {toast.text}
        </div>
      )}

      {rows.length === 0 ? (
        <div class="empty">
          {results
            ? "No logins match your search."
            : page?.origin
              ? "No logins saved for this site. Search all your logins above."
              : "Search your logins to copy one."}
          {vault && (
            <div>
              <button
                class="button"
                onClick={() => {
                  void ext.tabs.create({ url: vault });
                  close();
                }}
              >
                Open CipherMoth
              </button>
            </div>
          )}
        </div>
      ) : (
        <>
          <div class="section-label" id="logins-label">
            {listLabel}
          </div>
          <ul class="list" id="logins" role="listbox" aria-labelledby="logins-label">
            {rows.map((login, index) => {
              const code = codes[login.id];
              const left = code ? Math.max(0, Math.ceil((code.until - now) / 1000)) : 0;
              const sub =
                results || !matchIds.has(login.id)
                  ? [login.username, login.host].filter(Boolean).join(" · ")
                  : (login.username ?? "");
              return (
                <li
                  key={login.id}
                  id={`login-${login.id}`}
                  class="row"
                  role="option"
                  aria-selected={index === selected}
                  title={`${login.name}${sub ? ` — ${sub}` : ""}`}
                  onMouseEnter={() => setSelected(index)}
                  onClick={() => fill(login)}
                >
                  <span
                    class="avatar"
                    style={{ background: avatarColor(login.name) }}
                    aria-hidden="true"
                  >
                    {initial(login.name)}
                  </span>
                  <span class="who">
                    <span class="name">
                      {login.name}
                      {login.favorite && (
                        <span class="star" aria-label="Favorite">
                          <Icon name="star" size={13} />
                        </span>
                      )}
                    </span>
                    {sub && <span class="sub">{sub}</span>}
                  </span>
                  <span class="actions" onClick={(e) => e.stopPropagation()}>
                    {code && left > 0 && (
                      <span class="code" aria-label={`2FA code ${code.code}, ${left} seconds left`}>
                        {code.code}
                        <Ring seconds={left} />
                      </span>
                    )}
                    {login.username && (
                      <button
                        class="icon-button"
                        title="Copy username"
                        aria-label={`Copy username for ${login.name}`}
                        onClick={() => void copy(login, "username")}
                      >
                        <Icon name="user" size={17} />
                      </button>
                    )}
                    <button
                      class="icon-button"
                      title="Copy password"
                      aria-label={`Copy password for ${login.name}`}
                      onClick={() => void copy(login, "password")}
                    >
                      <Icon name="key" size={17} />
                    </button>
                    {login.has_totp && (
                      <button
                        class="icon-button"
                        title="Copy 2FA code"
                        aria-label={`Copy 2FA code for ${login.name}`}
                        onClick={() => void copy(login, "totp")}
                      >
                        <Icon name="timer" size={17} />
                      </button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
      <footer class="hint">
        Fill: <kbd>Enter</kbd> · Copy password: <kbd>{MOD}C</kbd> · Username: <kbd>{MOD}⇧C</kbd>
      </footer>
    </div>
  );
};

// --- root ------------------------------------------------------------------------

const App = () => {
  const [status, setStatus] = useState<Status | null>(null);

  const load = useCallback(() => {
    setStatus(null);
    send<Status>({ type: "status" })
      .then(setStatus)
      .catch((err: unknown) =>
        setStatus({
          phase: "offline",
          vault: null,
          api: null,
          serverVersion: null,
          idleTimeoutMs: null,
          subdomains: false,
          strictClipboard: false,
          handoffPending: false,
          error: err instanceof Error ? err.message : "Something went wrong.",
        })
      );
  }, []);

  useEffect(load, [load]);

  if (!status) {
    return (
      <div class="loading" aria-label="Loading">
        <MothIcon size={32} />
      </div>
    );
  }
  switch (status.phase) {
    case "setup":
      return <Setup />;
    case "too-old":
    case "offline":
      return (
        <>
          <Header />
          <Problem status={status} onRetry={load} />
        </>
      );
    case "locked":
      return (
        <>
          <Header />
          <Locked status={status} onUnlocked={setStatus} />
        </>
      );
    case "unlocked":
      return (
        <Unlocked vault={status.vault} onLocked={() => setStatus({ ...status, phase: "locked" })} />
      );
  }
};

const root = document.getElementById("app");
if (root) render(<App />, root);
