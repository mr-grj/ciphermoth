# addons.mozilla.org (AMO) listing

What we enter on addons.mozilla.org for CipherMoth (add-on id
`ciphermoth@mr-grj.github.io`, pinned in `extension/manifest/firefox.json` and trusted by
the desktop app's native host). Listed on AMO: Mozilla checks and signs every version,
and Firefox installs and updates it from the listing.

History (decision 64): the 3.9.0 Release workflow created the add-on in the **unlisted**
channel (AMO id 3124124) while `AMO_JWT_*` were set. AMO never accepts a version number
twice, in either channel, so 3.9.0 stays unlisted (its signed `.xpi` is on the GitHub
release). 3.9.1 was then uploaded by hand, but the distribution screen was left on "On your
own" (AMO preselects the channel of the previous version), so it became unlisted as well.
3.9.2 is the first listed version, uploaded into the same add-on.
Never delete or disable the add-on: its id could never be used again. Keep `AMO_JWT_*`
unset in the `extension-release` environment.

## Developer Hub links

- Add-on dashboard: https://addons.mozilla.org/en-US/developers/addon/ciphermoth/edit
  (before the URL is changed: `.../addon/db1ccfe2b8784bb09e15/edit`)
- Versions: https://addons.mozilla.org/en-US/developers/addon/ciphermoth/versions
- Public page (after the first listed version is approved):
  https://addons.mozilla.org/firefox/addon/ciphermoth/

## Listing texts

**Name:** CipherMoth

**Add-on URL:** `ciphermoth`

**Summary** (max 250 characters; from the manifest):
Fill logins from your self-hosted CipherMoth vault, only when you ask. No account, no tracking.

**Description:**

```text
CipherMoth fills a saved login into the page you are on, only when you ask. It works with your own CipherMoth: your self-hosted CipherMoth server, or the CipherMoth desktop app on this computer. No CipherMoth account, no tracking, no analytics.

HOW IT WORKS
• Click the CipherMoth button in the toolbar (pin it from the Extensions menu, the puzzle icon) or press Ctrl+Shift+L (⌘+Shift+L on a Mac), then pick a login.
• Nothing shows up inside web pages, nothing is filled when a page loads, and the extension never asks to save logins.
• Copy a username, password or live 2FA code with one click. Copied values are cleared from the clipboard after 30 seconds.

HARD TO TRICK
• Exact-origin matching: lookalike domains, other ports and http:// copies of an https:// site never match. Subdomain matching is off unless you turn it on.
• Only the top frame is filled, and only fields a person can see and use. Hidden, transparent, covered or off-screen fields are skipped; sign-up and password-change forms are refused.
• A login saved for another site asks before it fills.
• The extension adds nothing to web pages, so pages cannot detect it, frame it or click-jack it. Other extensions and websites cannot message it.

YOUR VAULT STAYS YOURS
• Server mode: the extension talks only to the CipherMoth server address you enter, over HTTPS, and sends only the page's origin (scheme, host and port) to find matches, never the path, title or page contents. Unlock with your master password, or in the CipherMoth web app with a security key, passkey or Touch ID.
• Desktop mode: the extension talks to the CipherMoth desktop app through Firefox's native messaging, with no network at all. Pair once by comparing a six-digit code; every message between the extension and the app is end-to-end encrypted.
• The extension writes no passwords or vault contents to disk.

REQUIREMENTS
• Firefox 128 or newer.
• Server mode: a CipherMoth server, version 3.6.0 or newer.
• Desktop mode: the CipherMoth desktop app, version 3.9.0 or newer, and Firefox 130 or newer.

CipherMoth is free and open source (MIT).
Source code and releases: https://github.com/mr-grj/ciphermoth
Guide: https://github.com/mr-grj/ciphermoth/blob/master/docs/EXTENSION.md
```

**Checkboxes:** "This add-on is experimental": off. "This add-on requires payment, non-free
services or software, or additional hardware": off (the server and the desktop app it
works with are free, open-source software).

**Firefox categories** (up to 2): Privacy & Security only.
**Firefox for Android categories:** none (not compatible with Android).

**Support email:** empty (it is shown publicly). **Support website:**
`https://github.com/mr-grj/ciphermoth/issues`

**License:** MIT License.

**Homepage:** `https://github.com/mr-grj/ciphermoth`

**Privacy policy** (tick "This add-on has a privacy policy"; plain text, the content of
`docs/PRIVACY.md`):

```text
CipherMoth (the server, the desktop app, the command-line client and the browser extension) is self-hosted, open-source software. The developer runs no service for it and receives no data from it. There is no CipherMoth account, no telemetry, no analytics and no remote configuration.

THE BROWSER EXTENSION
• What it handles: when you click its toolbar button or press its shortcut, it reads the current tab's origin (scheme, host and port) to find logins saved for that site, and fills or copies the login you pick. It reads the page's input fields only to place that login.
• Where data goes: only to the CipherMoth you configured: your own CipherMoth server at the address you entered, or the CipherMoth desktop app on the same computer (through Firefox's native messaging, no network). It sends the page's origin to find matches, never its path, query, title or contents. Nothing is sent to the developer or to any third party.
• What it stores: its settings (the server address or the choice of the desktop app, your matching options and a random installation id) in the browser's extension storage. In server mode, the session token is kept only in memory-only session storage; in desktop mode, a pairing key that cannot be read back is kept in the extension's own storage. No passwords or vault contents are written to disk.
• The clipboard: values you copy are cleared from the clipboard after 30 seconds. The optional "only clear what CipherMoth copied" setting reads the clipboard only to compare it with a hash of what CipherMoth copied; it is never stored or sent.
• addons.mozilla.org sees installs and update checks, like for any add-on; that is covered by Mozilla's own privacy policy.

THE SERVER AND THE DESKTOP APP
Your vault lives on hardware you control, encrypted with a key derived from your master password. The web app checks for new releases by asking GitHub's public API from your browser (Settings, Check for updates, which you can turn off); the desktop app checks GitHub Releases for signed updates. No vault data is part of either request.

Details: https://github.com/mr-grj/ciphermoth/blob/master/SECURITY.md and https://github.com/mr-grj/ciphermoth/blob/master/docs/EXTENSION.md
Questions: open an issue at https://github.com/mr-grj/ciphermoth/issues
```

**Icon:** the add-on's own icon (from the manifest, 32 and 64 px). Do not upload another.

**Screenshots** (1280×800, from `extension/.e2e/store/`, made by
`SCREENSHOTS=1 npx playwright test screenshots`), in this order, with these captions:

| File | Caption |
|---|---|
| `screenshot-1-matches.png` | Fills only when you ask: click the toolbar button or press Ctrl+Shift+L. |
| `screenshot-2-confirm-other-site.png` | Exact-origin matching: a login saved for another site asks first. |
| `screenshot-3-copied-2fa.png` | Copy a password or a live 2FA code; the clipboard clears itself. |
| `screenshot-4-locked.png` | Unlock with your master password, or in CipherMoth with a security key. |
| `screenshot-5-search.png` | Works with your own server or the CipherMoth desktop app. |

No promo tile or marquee: AMO has no such fields.

## Uploading a version

1. Download the release's Firefox zip and check it:

   ```sh
   mkdir -p ~/cm-amo && cd ~/cm-amo
   gh release download vX.Y.Z -R mr-grj/ciphermoth -p 'ciphermoth-extension-firefox-X.Y.Z.zip' -p SHA256SUMS
   grep 'ciphermoth-extension-firefox-X.Y.Z.zip' SHA256SUMS | shasum -a 256 -c
   ```

2. Make the source package from the tag (enough to rebuild every package byte for byte):

   ```sh
   git -C ~/Projects/ciphermoth fetch --tags
   git -C ~/Projects/ciphermoth archive --format=zip -o ~/cm-amo/ciphermoth-extension-source-X.Y.Z.zip \
     vX.Y.Z extension frontend/src/lib/brand.js LICENSE
   ```

3. Versions page -> **Upload a New Version**. The first screen asks how to distribute:
   select **On this site** yourself (AMO preselects the previous version's channel, which
   was unlisted for 3.9.0 and 3.9.1; "On your own" signs an unlisted version whose number
   can never be listed). Then select `ciphermoth-extension-firefox-X.Y.Z.zip` (never the
   `.xpi`, never a local build). Validation must show 0 errors; the known warnings are
   listed in the reviewer notes.
4. Compatible platforms: **Firefox** only (untick Firefox for Android).
5. Source code: **Yes**, upload `ciphermoth-extension-source-X.Y.Z.zip`.
6. If the Describe page appears (the first listed version), fill it from the texts above.
7. **Release notes** ("Version notes"): `What's new: https://github.com/mr-grj/ciphermoth/releases/tag/vX.Y.Z`
   plus one or two sentences from the CHANGELOG section.
8. **Notes for Reviewers:** below, with X.Y.Z replaced. Submit Version.
9. Check that it went to the listed channel: the version's page (Versions -> **Version
   X.Y.Z**) shows the license and the release notes you entered, and once it is approved
   https://addons.mozilla.org/firefox/addon/ciphermoth/ shows version X.Y.Z. The Edit
   Product Page shows **Add-on Media** (screenshots) only after the first listed version.
10. Afterwards: `rm -rf ~/cm-amo`.

## Notes for reviewers

```text
CipherMoth is a self-hosted, open-source password manager (MIT, https://github.com/mr-grj/ciphermoth). This extension fills a login from the user's own CipherMoth into the current page, only when the user clicks the toolbar button or presses the shortcut. There is no hosted service: the extension talks only to the CipherMoth server address the user enters (an optional host permission requested for that one host) or, in desktop mode, to the CipherMoth desktop app through native messaging (optional nativeMessaging permission). data_collection_permissions is "none": nothing is sent to the developer.

SOURCE AND BUILD
The source zip is `git archive` of tag vX.Y.Z (https://github.com/mr-grj/ciphermoth/tree/vX.Y.Z), paths extension/, frontend/src/lib/brand.js (the build checks the brand colours against it) and LICENSE. extension/README.md has the same instructions. With Node 22 and npm 10 on macOS or Linux:
  cd extension
  npm ci
  node scripts/build.mjs --package
This writes dist/firefox/ and dist/packages/ciphermoth-extension-firefox-X.Y.Z.zip, byte-identical to the uploaded package (dist/packages/SHA256SUMS). esbuild bundles the TypeScript and Preact sources into plain IIFE files: no minification, no source maps, no remote code. scripts/verify.mjs rebuilds and compares the checksums.

LINT WARNINGS
- UNSAFE_VAR_ASSIGNMENT (popup.js, options.js): inside Preact's DOM renderer (its dangerouslySetInnerHTML support). Our code never uses it; ESLint forbids innerHTML and dangerouslySetInnerHTML in the sources.
- data_collection_permissions below the minimum version: strict_min_version is 128 (ESR); older versions ignore the key.

HOW TO TEST
1. Run a CipherMoth server locally (Docker):
     curl -fsSL https://raw.githubusercontent.com/mr-grj/ciphermoth/vX.Y.Z/docker-compose.prod.yml -o docker-compose.yml
     CIPHERMOTH_VERSION=X.Y.Z docker compose up -d
   Open http://localhost:3000, create a vault (any master password of 12+ characters with two character classes) and add a login whose website is a page with a login form.
2. In the extension's settings choose "Your CipherMoth server", enter http://localhost:3000, open "API on another address?" and enter http://localhost:8000, click Connect and allow the host permission.
3. Open the login page, click the toolbar button, unlock with the master password and pick the login: the username and password are filled. Copy buttons copy the password or the 2FA code; the clipboard is cleared after 30 seconds.
Desktop mode needs the CipherMoth desktop app from the GitHub release; the same flows work after pairing (a six-digit code shown on both sides).
```
