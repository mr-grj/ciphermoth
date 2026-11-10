// The e2e stack: a live CipherMoth backend (uvicorn, throwaway data folder),
// an HTTPS fixture server for test sites and the attack lab, and Playwright's
// Chromium with the extension's test build. Every host name resolves to the
// fixture server (--host-resolver-rules), whose self-signed certificate is
// trusted by its key (--ignore-certificate-errors-spki-list); one port speaks
// TLS and plain HTTP so http:// pages work too.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { extname, join, normalize, sep } from "node:path";
import tls from "node:tls";

import { type BrowserContext, type Page, type Worker, chromium } from "@playwright/test";

import {
  BACKEND_DIR,
  E2E_DIR,
  FRONTEND_DIST,
  LAB_DIR,
  OTHER_EXTENSION,
  SITES_DIR,
  TEST_BUILD,
} from "./paths";

export const MASTER_PASSWORD = "Moth-Test-Vault-2026!";
export const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
export const GITHUB_PASSWORD = "gh-canary-Secret-7Q";
export const WORK_PASSWORD = "gh-work-canary-2R";
export const INTRANET_PASSWORD = "intranet-canary-5T";
export const NOTE_BODY = "note-canary-safe-behind-the-moth-painting";

export interface RecordedRequest {
  host: string;
  method: string;
  path: string;
  query: string;
  headers: http.IncomingHttpHeaders;
}

export interface Stack {
  port: number;
  backend: string;
  spki: string;
  requests: RecordedRequest[];
  // Hold the next request to an API path (e.g. "/api/extension/search") this
  // many milliseconds before passing it on. Used once, then forgotten.
  delays: Map<string, number>;
  stop: () => Promise<void>;
}

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });

interface Certificate {
  key: Buffer;
  cert: Buffer;
  spki: string;
}

const makeCertificate = (name: string): Certificate => {
  const dir = join(E2E_DIR, "certs");
  mkdirSync(dir, { recursive: true });
  const key = join(dir, `${name}.key`);
  const cert = join(dir, `${name}.crt`);
  if (!existsSync(cert)) {
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      "30",
      "-subj",
      `/CN=ciphermoth-e2e-${name}`,
      "-addext",
      "subjectAltName=DNS:*.test,DNS:*.github.io,DNS:localhost",
    ]);
  }
  const certPem = readFileSync(cert);
  const der = createPublicKey({ key: certPem, format: "pem" }).export({
    type: "spki",
    format: "der",
  });
  return {
    key: readFileSync(key),
    cert: certPem,
    spki: createHash("sha256").update(der).digest("base64"),
  };
};

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

const serveFile = (res: http.ServerResponse, root: string, path: string, fallback?: string) => {
  const target = normalize(join(root, decodeURIComponent(path)));
  let file = target.startsWith(root + sep) && existsSync(target) ? target : null;
  if (file && statSync(file).isDirectory())
    file = existsSync(join(file, "index.html")) ? join(file, "index.html") : null;
  if (!file && fallback) file = join(root, fallback);
  if (!file) {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }
  res
    .writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "cache-control": "no-store",
    })
    .end(readFileSync(file));
};

const proxy = (req: http.IncomingMessage, res: http.ServerResponse, backendPort: number) => {
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port: backendPort,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, host: `127.0.0.1:${backendPort}` },
    },
    (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers);
      answer.pipe(res);
    }
  );
  upstream.on("error", () => res.writeHead(502).end());
  req.pipe(upstream);
};

const route = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  backendPort: number,
  requests: RecordedRequest[],
  delays: Map<string, number>
) => {
  const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
  const url = new URL(req.url ?? "/", "http://x");
  requests.push({
    host,
    method: req.method ?? "GET",
    path: url.pathname,
    query: url.search,
    headers: req.headers,
  });
  const json = (status: number, body: string) =>
    res
      .writeHead(status, { "content-type": "application/json", "cache-control": "no-store" })
      .end(body);

  if (host === "vault.test") {
    if (url.pathname.startsWith("/api/")) {
      const delay = delays.get(url.pathname);
      if (delay === undefined) return proxy(req, res, backendPort);
      delays.delete(url.pathname);
      setTimeout(() => proxy(req, res, backendPort), delay);
      return;
    }
    return serveFile(res, FRONTEND_DIST, url.pathname, "index.html");
  }
  if (host === "redirect.test") {
    return res.writeHead(302, { location: "https://evil.test/stolen" }).end();
  }
  if (host === "huge.test")
    return json(200, `{"version":"9","features":["${"x".repeat(5 << 20)}"]}`);
  if (host === "badjson.test") return json(200, "{not json");
  if (host === "notcm.test") {
    return res
      .writeHead(200, { "content-type": "text/html" })
      .end("<!doctype html><title>x</title>");
  }
  if (host === "old.test") {
    if (url.pathname !== "/api/meta") return json(404, '{"detail":"Not Found"}');
    return json(200, '{"version":"3.4.0","features":["vault-sessions"]}');
  }
  if (url.pathname.startsWith("/lab/")) return serveFile(res, LAB_DIR, url.pathname.slice(5));
  return serveFile(
    res,
    SITES_DIR,
    url.pathname === "/" ? "login.html" : url.pathname.slice(1),
    "login.html"
  );
};

const waitFor = async (check: () => Promise<boolean>, what: string, ms = 60_000) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await check().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`timed out waiting for ${what}`);
};

export const startStack = async (): Promise<Stack> => {
  const dataDir = mkdtempSync(join(tmpdir(), "cm-ext-e2e-"));
  const backendPort = await freePort();
  const backend: ChildProcess = spawn(
    "uv",
    [
      "run",
      "--frozen",
      "uvicorn",
      "main:app",
      "--host",
      "127.0.0.1",
      "--port",
      String(backendPort),
    ],
    {
      cwd: BACKEND_DIR,
      env: {
        ...process.env,
        CIPHERMOTH_DATA_DIR: dataDir,
        CIPHERMOTH_RATE_LIMIT: "100000/hour",
      },
      stdio: ["ignore", "ignore", "pipe"],
    }
  );
  let backendLog = "";
  backend.stderr?.on("data", (chunk) => (backendLog += chunk));
  const backendUrl = `http://127.0.0.1:${backendPort}/api`;
  await waitFor(
    async () => (await fetch(`${backendUrl}/meta`)).ok,
    `the backend to start:\n${backendLog}`
  );

  const main = makeCertificate("main");
  const other = makeCertificate("untrusted");
  const requests: RecordedRequest[] = [];
  const delays = new Map<string, number>();
  const handler = (req: http.IncomingMessage, res: http.ServerResponse) =>
    route(req, res, backendPort, requests, delays);
  const secure = https.createServer(
    {
      key: main.key,
      cert: main.cert,
      SNICallback: (servername, done) =>
        done(
          null,
          tls.createSecureContext(
            servername === "badtls.test"
              ? { key: other.key, cert: other.cert }
              : { key: main.key, cert: main.cert }
          )
        ),
    },
    handler
  );
  const plain = http.createServer(handler);
  const listen = (server: net.Server) =>
    new Promise<number>((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port))
    );
  const securePort = await listen(secure);
  const plainPort = await listen(plain);
  // One public port for both: a TLS ClientHello starts with 0x16.
  const sockets = new Set<net.Socket>();
  const front = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.once("data", (first) => {
      const upstream = net.connect(first[0] === 0x16 ? securePort : plainPort, "127.0.0.1");
      sockets.add(upstream);
      upstream.on("close", () => sockets.delete(upstream));
      upstream.on("error", () => socket.destroy());
      upstream.write(first);
      socket.pipe(upstream).pipe(socket);
    });
  });
  const port = await listen(front);

  return {
    port,
    backend: backendUrl,
    spki: main.spki,
    requests,
    delays,
    stop: async () => {
      for (const socket of sockets) socket.destroy();
      secure.closeAllConnections();
      plain.closeAllConnections();
      await Promise.all(
        [front, secure, plain].map((s) => new Promise<void>((resolve) => s.close(() => resolve())))
      );
      backend.kill("SIGTERM");
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
};

// --- the vault ------------------------------------------------------------------

export const api = async (
  stack: Stack,
  path: string,
  { method = "POST", body, token }: { method?: string; body?: unknown; token?: string } = {}
) => {
  const response = await fetch(`${stack.backend}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { "x-ciphermoth-session": token } : {}),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
};

export const seedVault = async (stack: Stack): Promise<string> => {
  const created = await api(stack, "/master_password/create", {
    body: { master_password: MASTER_PASSWORD },
  });
  const token = created.body.session_token as string;
  const entries = [
    {
      password_name: "GitHub",
      password_value: GITHUB_PASSWORD,
      username: "moth@example.com",
      url: "https://github.test/login",
      totp_secret: TOTP_SECRET,
      favorite: true,
    },
    {
      password_name: "GitHub (work)",
      password_value: WORK_PASSWORD,
      username: "work@example.com",
      url: "github.test",
    },
    {
      password_name: "Intranet",
      password_value: INTRANET_PASSWORD,
      username: "moth",
      url: "http://intranet.test",
    },
    {
      password_name: "Multi",
      password_value: "multi-canary-9",
      username: "moth",
      url: "multi.test",
    },
    { password_name: "Docs", password_value: "docs-canary-3", url: "moth.github.io" },
    {
      password_name: "Notes for GitHub",
      password_value: NOTE_BODY,
      kind: "note",
      url: "https://github.test",
    },
  ];
  for (const entry of entries) {
    const response = await api(stack, "/passwords/create", { body: entry, token });
    if (response.status !== 200) throw new Error(JSON.stringify(response.body));
  }
  return token;
};

// --- the browser ------------------------------------------------------------------

export interface Browser {
  context: BrowserContext;
  extensionId: string;
  worker: Worker;
  profile: string;
  close: () => Promise<void>;
}

export const launch = async (
  stack: Stack,
  {
    profile,
    otherExtension = false,
    env,
    before,
    scale,
  }: {
    profile?: string;
    otherExtension?: boolean;
    // Desktop mode: the browser passes its environment to the native host.
    env?: Record<string, string>;
    // Runs with the profile folder before the browser starts.
    before?: (profile: string) => void;
    // Device pixels per CSS pixel (screenshots for the store).
    scale?: number;
  } = {}
): Promise<Browser> => {
  const dir = profile ?? mkdtempSync(join(tmpdir(), "cm-ext-profile-"));
  before?.(dir);
  const extensions = otherExtension ? `${TEST_BUILD},${OTHER_EXTENSION}` : TEST_BUILD;
  const context = await chromium.launchPersistentContext(dir, {
    channel: "chromium",
    ...(env ? { env: { ...process.env, ...env } as Record<string, string> } : {}),
    headless: !process.env.HEADED,
    viewport: { width: 1100, height: 760 },
    ...(scale ? { deviceScaleFactor: scale } : {}),
    args: [
      `--disable-extensions-except=${extensions}`,
      `--load-extension=${extensions}`,
      `--host-resolver-rules=MAP * 127.0.0.1:${stack.port}, EXCLUDE localhost, EXCLUDE 127.0.0.1`,
      `--ignore-certificate-errors-spki-list=${stack.spki}`,
    ],
  });
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const workers = async () =>
    context.serviceWorkers().filter((w) => w.url().endsWith("/background.js"));
  let [worker] = await workers();
  if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = new URL(worker.url()).host;
  return {
    context,
    extensionId,
    worker,
    profile: dir,
    close: async () => context.close(),
  };
};

export const configure = async (browser: Browser, vault = "https://vault.test") => {
  await browser.worker.evaluate(
    async ({ vault }) => {
      await chrome.storage.local.set({
        config: { vault, api: `${vault}/api`, subdomains: false, strictClipboard: false },
      });
    },
    { vault }
  );
};

export const tabIdOf = async (browser: Browser, page: Page): Promise<number> => {
  await page.bringToFront();
  const url = page.url();
  const id = await browser.worker.evaluate(async (url) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((tab) => tab.url === url)?.id ?? null;
  }, url);
  if (id === null) throw new Error(`no tab for ${url}`);
  return id;
};

// The popup, pointed at a tab (test build only: Playwright cannot click the
// toolbar button). It opens in its own window so the page keeps its tab.
export const openPopup = async (browser: Browser, target: Page | number | null): Promise<Page> => {
  const tabId =
    target === null || typeof target === "number" ? target : await tabIdOf(browser, target);
  const url = `chrome-extension://${browser.extensionId}/popup.html${
    tabId === null ? "" : `#tab=${tabId}`
  }`;
  const next = browser.context.waitForEvent("page");
  await browser.worker.evaluate(async (url) => {
    await chrome.windows.create({ url, type: "popup", width: 380, height: 620 });
  }, url);
  const popup = await next;
  await popup.waitForLoadState("domcontentloaded");
  return popup;
};

export const unlockInPopup = async (popup: Page, password = MASTER_PASSWORD) => {
  await popup.getByPlaceholder("Master password").fill(password);
  await popup.getByRole("button", { name: "Unlock", exact: true }).click();
};

// Connected to the test vault and unlocked, whatever the state before.
export const unlocked = async (browser: Browser, stack: Stack) => {
  await configure(browser);
  const popup = await openPopup(browser, null);
  const search = popup.getByPlaceholder("Search logins");
  const password = popup.getByPlaceholder("Master password");
  await search.or(password).first().waitFor();
  if (await password.isVisible()) {
    await unlockInPopup(popup);
    await search.waitFor();
  }
  await popup.close();
  void stack;
};

export const sessionToken = (browser: Browser): Promise<string | null> =>
  browser.worker.evaluate(async () => {
    const { session } = (await chrome.storage.session.get("session")) as {
      session?: { token: string };
    };
    return session?.token ?? null;
  });

export const fillCommand = (browser: Browser, page: Page) =>
  tabIdOf(browser, page).then((tabId) =>
    browser.worker.evaluate(
      async (tabId) =>
        (
          globalThis as unknown as {
            __ciphermothE2E: { fillCommand: (id: number) => Promise<string> };
          }
        ).__ciphermothE2E.fillCommand(tabId),
      tabId
    )
  );

// What the page received: every lab and site page keeps a spy of its fields.
export const fieldValues = (page: Page) =>
  page.evaluate(() =>
    Array.from(document.querySelectorAll("input")).map((input) => ({
      id: input.id,
      value: input.value,
    }))
  );

export const allFrameValues = async (page: Page) => {
  const values: { frame: string; id: string; value: string }[] = [];
  for (const frame of page.frames()) {
    const fields = await frame
      .evaluate(() =>
        Array.from(document.querySelectorAll("input")).map((i) => ({ id: i.id, value: i.value }))
      )
      .catch(() => []);
    for (const field of fields) values.push({ frame: frame.url(), ...field });
  }
  return values;
};
