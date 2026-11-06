# The CipherMoth browser extension

Fill a saved login into the page you are on, **only when you ask**: click the toolbar
button (or press **Ctrl+Shift+L**, **⌘+Shift+L** on a Mac) and pick the login. Nothing
shows up inside web pages by itself, nothing is filled when a page loads, and the
extension never asks to save logins.

> **No CipherMoth account, ever.** The extension comes from your browser's store, which
> sees the install like any extension. It only ever talks to your own CipherMoth server,
> and only when you ask it to fill. Only the page's origin (scheme, host, port) is sent
> to find matches, never its path, title or contents. No favicons, no analytics, no
> remote configuration.

Works with Chrome, Brave, Edge, Opera and Vivaldi (Chromium 120 or newer) and Firefox 128
or newer, against a CipherMoth server (Docker edition) that lists the `browser-extension`
feature (3.6.0 and later). Connecting it to the desktop app is planned (phase 2).

## Install

| Browser | Recommended | Without a store |
|---|---|---|
| Chrome, Brave, Vivaldi | Chrome Web Store (listing pending) | Load unpacked from `ciphermoth-extension-chromium-X.Y.Z.zip` |
| Edge | Chrome Web Store, or Edge Add-ons later | Load unpacked |
| Opera | Chrome Web Store through Opera's "Install Chrome Extensions" | Load unpacked |
| Firefox | addons.mozilla.org (listing pending) | The signed `ciphermoth-extension-firefox-X.Y.Z.xpi` from the GitHub release |

Until the store listings exist, use the files attached to each
[GitHub release](https://github.com/mr-grj/ciphermoth/releases/latest). Settings →
**Browser extension** in CipherMoth links here.

### Load unpacked (Chromium browsers)

1. Download `ciphermoth-extension-chromium-X.Y.Z.zip` and `SHA256SUMS` from the release
   and check the file first (below).
2. Unzip it into a folder you keep (the browser loads it from there every start).
3. Open `chrome://extensions` (Edge: `edge://extensions`, Opera: `opera://extensions`),
   turn on **Developer mode**, click **Load unpacked** and choose the folder.

Things to know about this path:

- **No automatic updates.** Security fixes reach you only when you download the next
  release and load it again. The store version updates itself.
- Chrome warns about developer-mode extensions at every start on Windows and macOS.
- Turning developer mode off disables the extension (Chrome 133 and later).
- Loading unknown unpacked extensions is a habit worth not forming. Do it only for files
  you checked against `SHA256SUMS`.

### Signed XPI (Firefox)

Download `ciphermoth-extension-firefox-X.Y.Z.xpi` from the release and open it in
Firefox (drag it onto a window, or `about:addons` → gear → **Install Add-on From
File**). It is signed by Mozilla as an unlisted add-on, so release Firefox installs it.
The unsigned `ciphermoth-extension-firefox-X.Y.Z.zip` (the package sent to Mozilla) only
loads as a temporary add-on (`about:debugging`) or in Developer Edition, Nightly and ESR
with signing turned off.

## Connect and unlock

1. On first install the extension opens its settings. Enter the address you open
   CipherMoth at, for example `https://vault.example.com`, and click **Connect**. The
   browser asks to let the extension access **that one address** (and the API's, if it
   runs elsewhere). Plain `http://` is accepted only for `localhost`, `127.0.0.1` and
   `[::1]`.
   - When the API is not at `/api` on the same address (the Docker defaults put the UI on
     port 3000 and the API on 8000), open **API on another address?** and enter it, for
     example `http://localhost:8000`.
2. Click the toolbar button and unlock:
   - **Master password** in the popup (it is browser UI, never part of a page), or
   - **Unlock in CipherMoth**: a tab with your vault opens; unlock there as usual
     (security key, passkey, Touch ID) and confirm **Connect <browser> to this vault?**.
     Vaults that require a security key always use this way, because a security key
     cannot answer for your vault from inside an extension.

The extension stays unlocked until your vault's **inactivity timeout** (Settings →
General), at most 12 hours, until you lock it (🔒 in the popup), until you disconnect it
(CipherMoth Settings → **Browser extension** → Disconnect), until the master password
changes, or until the browser or the server restarts.

## Fill, copy and 2FA

- The popup lists the logins saved for the page first (favorites first), then lets you
  search all your logins (name, username, site).
- **Enter** or a click fills the selected login. Arrows move. **Ctrl/⌘+C** copies the
  password, **Ctrl/⌘+Shift+C** the username, **Esc** closes. The timer button copies the
  current 2FA code (the secret never leaves your server).
- **Ctrl+Shift+L** (⌘+Shift+L) fills directly when exactly one login matches a secure
  page, and opens the list otherwise. Change shortcuts at `chrome://extensions/shortcuts`
  (Firefox: `about:addons` → gear → Manage Extension Shortcuts).
- **Multi-step logins** (username first, password on the next page): fill on each step.
- Copied values are cleared after 30 seconds. With **Only clear what CipherMoth copied**
  (extension settings) it first checks the clipboard still holds its copy; the browser
  asks to let it read the clipboard for that.
- **Match subdomains** (off by default) also offers a login saved for `example.com` on
  `login.example.com`, never across public suffixes such as `co.uk` or `github.io`.

### When it asks first

- **A login saved for another site** (picked from search): "This login is saved for
  github.com. Fill it on gitlab.com?"
- **A plain HTTP page**: "This page isn't secure (HTTP). Copy instead?" Filling is offered
  only for a login saved for that same `http://` address.
- **No usable login fields**: it says so and offers to copy the password.

## What the extension can and cannot do

**The session.** Unlocking gives the extension an *extension session*: a random token
the server maps to your vault key, like a web session, but limited by the server to five
routes: list the logins saved for a site, search logins, read one login's username and
password at the moment of a fill or copy, compute a 2FA code, and keep the session alive.
Every other route refuses it (`403 extension_scope`), so it cannot list the vault, read
notes, history, custom fields or attachments, export, back up, change settings or delete
anything. Each browser profile has one extension session: unlocking again (also after a
browser restart, which drops the old token) replaces it, using a random installation id the
extension keeps; it is not a secret and opens nothing. At most 8 extension sessions exist at
a time, separate from web sessions. The
token lives in the browser's memory-only session storage, readable only by the
extension's own pages.

**What it guarantees** (and the test suite checks, including an attack lab of hostile
pages, see "Testing" below):

- Nothing is filled unless you clicked or pressed the shortcut. Page scripts cannot press
  browser shortcuts or open the popup.
- Only the top frame of the page is filled, and only when its origin still equals the
  origin the popup matched (checked again inside the page, so a navigation in between
  fills nothing). Frames, including same-origin and sandboxed ones, are never filled.
- Exact origin matching by default: `github.com.evil.example`, `evil.example/github.com`,
  `github.com@evil.example`, punycode lookalikes, other ports and `http://` versions of an
  `https://` login do not match. International names are compared in punycode, which the
  popup shows (the Unicode form is in the tooltip).
- Only fields a person can see and use are filled: not hidden, transparent, masked,
  clipped, zero-sized, off-screen, covered by another element, read-only, disabled, in
  `aria-hidden` content or in a `<template>`. Sign-up and password-change forms
  (`autocomplete="new-password"`) are refused.
- The extension adds nothing to web pages (no icons, no frames, no web-accessible
  resources), so pages cannot detect it, frame it or click-jack it. Other extensions and
  web pages cannot message it.
- It talks only to the address you configured, follows no redirects with the token,
  sends no cookies, and fails closed on TLS errors and on answers that are not
  CipherMoth's.
- Nothing secret is written to disk: the browser profile is scanned for the master
  password, passwords, the 2FA secret, entry names and tokens after a full session in the
  tests.

**The limits.**

- **Guarantees are per origin.** Once a visible field on the right origin is filled,
  that site owns its page: its scripts can read the value, copy it into another field or
  send it anywhere. That is true of every password manager and of typing it yourself.
  A site with a cross-site scripting bug is compromised for you either way.
- An element drawn over a field with `pointer-events: none` is not detected; the field
  is still the site's own field on the right origin.
- Software running as your user on your computer can read browser memory and is outside
  what the extension (or the vault) protects against.
- A stolen extension token is still limited to the five routes above, the inactivity
  timeout and 12 hours, and can be disconnected in Settings; but within those it can read
  login passwords one by one (rate-limited to 300 per hour).

## Check a download

Every release attaches `SHA256SUMS`. In the folder with the downloads:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing     # macOS
sha256sum -c SHA256SUMS --ignore-missing         # Linux
```

Each package also has a GitHub build provenance attestation:
`gh attestation verify ciphermoth-extension-chromium-X.Y.Z.zip --repo mr-grj/ciphermoth`.

### Rebuild it yourself (reproducible build)

The build is reproducible: the toolchain is pinned in `extension/package-lock.json`, the
output has no minified names, no source maps, no timestamps or paths, and the zip entries
are sorted with a fixed date (`SOURCE_DATE_EPOCH`, 2026-01-01 by default). Building the
same tag gives byte-identical packages:

```sh
git clone https://github.com/mr-grj/ciphermoth && cd ciphermoth
git checkout vX.Y.Z && cd extension
npm ci                                   # Node 22
node scripts/verify.mjs ~/Downloads/SHA256SUMS
```

`verify.mjs` rebuilds both packages and prints `OK` or `MISMATCH` for each. The signed
XPI differs from the zip only by Mozilla's `META-INF/` signature files: unzip both and
compare the rest. To check a store install, compare the extension's folder in your
browser profile with `extension/dist/chromium` after the build.

## Troubleshooting

- **"Can't reach your CipherMoth"**: the server is down, the address is wrong, or this
  browser does not trust the server's certificate. A self-signed certificate must be
  trusted by your operating system (open the vault in a tab first: if the browser warns
  there, the extension cannot connect either). The extension never accepts an untrusted
  certificate.
- **"No CipherMoth API at …"**: the API is not at `/api` on that address. Enter the API's
  address under **API on another address?**.
- **"CipherMoth needs an update"**: the server is older than the extension's routes
  (before 3.6.0). Update it (docs/UPDATING.md).
- **"This vault needs a security key"**: use **Unlock in CipherMoth**.
- **The handoff tab says the extension did not answer**: open the popup and choose
  **Unlock in CipherMoth** again; a request expires after 5 minutes and works once.
- **Nothing was filled**: the popup says why (no fields, hidden fields, a frame, a
  sign-up form). Copy the password instead.
- **Desktop app**: not supported yet; it has no network listener for the extension to
  reach. Desktop mode (native messaging) is planned.

## Development

```sh
cd extension && npm ci
npm run build            # dist/chromium, dist/firefox
npm run package          # + dist/packages/*.zip and SHA256SUMS
npm test                 # Vitest: URL vectors, message schemas, manifests, clipboard, zips
npm run typecheck && npm run lint && npm run format:check
npm run lint:firefox     # web-ext lint on dist/firefox
npm run test:e2e         # Playwright Chromium: flows + attack lab (needs uv for the backend)
SCREENSHOTS=1 npx playwright test screenshots   # every popup state, light and dark
```

Layout: `src/background` (the only network and injection code), `src/popup`,
`src/options` (Preact), `src/fill/fill-script.ts` (the one function ever injected into a
page), `src/bridge` (handoff content script, registered only while a handoff is pending,
only on the vault's origin), `src/shared` (message schemas, URL display logic). The
server side is `backend/api/endpoints/extension.py`, `backend/crud/extension.py` and
`backend/url_match.py`; URL matching is pinned by `testdata/vectors/url-matching.json`,
which both sides test.

The e2e tests (`extension/tests/e2e`) start a real backend on a throwaway vault and an
HTTPS fixture server that answers for every host name (`--host-resolver-rules`) with a
certificate trusted by its key. They run against the **test build**
(`node scripts/build.mjs --test`, `dist-test/`), which differs from the real one only in
ways the tests need and the unit tests prove absent from the real build: host permissions
for every site (Playwright cannot click the toolbar button that grants `activeTab`), the
clipboard read permission, a 3-second clipboard timer, a popup that can be pointed at a
tab and a hook to run the fill command. The attack lab (`extension/tests/attack-lab`)
covers DOM-based extension clickjacking, hidden-field harvesting, frames, origin tricks,
form tricks, messaging, synthetic input, extension page access, hostile networks and the
clipboard. The manual checklist for each release is `extension/VALIDATION.md`.
