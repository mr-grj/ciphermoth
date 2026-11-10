# Chrome Web Store listing

What we enter in the Chrome Web Store developer dashboard for the CipherMoth item
(`gjdobbdnepjkgfpcmhjdagkcjholjkkd`, design decision 62). Keep it in step with the
manifest and docs/EXTENSION.md: a new permission needs a justification here before the
upload. Images: `SCREENSHOTS=1 npx playwright test screenshots` writes them to
`extension/.e2e/store/`.

## Store listing tab

**Title** (from the manifest): CipherMoth

**Summary** (from the manifest `description`, max 132 characters):
Fill logins from your self-hosted CipherMoth vault, only when you ask. No account, no tracking.

**Description:**

```text
CipherMoth fills a saved login into the page you are on, only when you ask. It works with your own CipherMoth: your self-hosted CipherMoth server, or the CipherMoth desktop app on this computer. No CipherMoth account, no tracking, no analytics.

HOW IT WORKS
• Click the toolbar button or press Ctrl+Shift+L (⌘+Shift+L on a Mac), then pick a login.
• Nothing shows up inside web pages, nothing is filled when a page loads, and the extension never asks to save logins.
• Copy a username, password or live 2FA code with one click. Copied values are cleared from the clipboard after 30 seconds.

HARD TO TRICK
• Exact-origin matching: lookalike domains, other ports and http:// copies of an https:// site never match. Subdomain matching is off unless you turn it on.
• Only the top frame is filled, and only fields a person can see and use. Hidden, transparent, covered or off-screen fields are skipped; sign-up and password-change forms are refused.
• A login saved for another site asks before it fills.
• The extension adds nothing to web pages, so pages cannot detect it, frame it or click-jack it. Other extensions and websites cannot message it.

YOUR VAULT STAYS YOURS
• Server mode: the extension talks only to the CipherMoth server address you enter, over HTTPS, and sends only the page's origin (scheme, host and port) to find matches, never the path, title or page contents. Unlock with your master password, or in the CipherMoth web app with a security key, passkey or Touch ID.
• Desktop mode: the extension talks to the CipherMoth desktop app through your browser's native messaging, with no network at all. Pair each browser once by comparing a six-digit code; every message between the extension and the app is end-to-end encrypted.
• The extension writes no passwords or vault contents to disk.

REQUIREMENTS
• Server mode: a CipherMoth server, version 3.6.0 or newer.
• Desktop mode: the CipherMoth desktop app, version 3.9.0 or newer, and Chrome 133 or newer.

CipherMoth is free and open source (MIT).
Source code and releases: https://github.com/mr-grj/ciphermoth
Guide: https://github.com/mr-grj/ciphermoth/blob/master/docs/EXTENSION.md
```

**Category:** Privacy & Security

**Language:** English

**Graphics** (all from `extension/.e2e/store/`):

| Field | File | Required |
|---|---|---|
| Store icon (128×128, 96 px artwork + 16 px transparent padding) | `store-icon-128.png` | yes |
| Screenshots (1280×800, up to 5, in this order) | `screenshot-1-matches.png` … `screenshot-5-search.png` | at least 1 |
| Small promo tile (440×280) | `small-promo-tile-440x280.png` | no, but items without it are listed after those with it |
| Marquee promo tile (1400×560) | `marquee-1400x560.png` | no (only needed to be featured) |
| YouTube video | none | no |

**Additional fields:**
- Official URL: leave empty (needs a site verified in Google Search Console).
- Homepage URL: `https://github.com/mr-grj/ciphermoth`
- Support URL: `https://github.com/mr-grj/ciphermoth/issues`
- Mature content: off.

## Privacy practices tab

**Single purpose description:**

```text
Fill and copy logins from the user's own self-hosted CipherMoth password vault (their CipherMoth server or the CipherMoth desktop app on the same computer) into the current web page, only when the user asks.
```

**Permission justifications** (one field per permission in the manifest):

- **activeTab:**
  ```text
  When the user clicks the toolbar button or presses the fill shortcut, CipherMoth needs temporary access to that one tab: it reads the tab's origin to find matching logins in the user's own vault, and fills the login the user picks. It has no access to other tabs, and none until the user acts.
  ```
- **scripting:**
  ```text
  Injects the fill function into the active tab's top frame (through activeTab, only after the user's click or shortcut) to put the chosen username and password into the visible login fields. While a user-started unlock handoff is pending (at most 5 minutes), it also registers a small script on the user's own CipherMoth server origin only, which passes the new session from the CipherMoth web app to the extension. There are no other content scripts.
  ```
- **storage:**
  ```text
  Keeps the extension's settings in storage.local: the address of the user's own CipherMoth server or the choice of the desktop app, the matching options and a random installation id. In server mode the session token is kept only in the memory-only storage.session. No passwords or vault contents are stored.
  ```
- **alarms:**
  ```text
  Timers that must fire while the service worker is asleep: clearing a copied password from the clipboard after 30 seconds, ending the session when it expires, and expiring a pending unlock handoff after 5 minutes.
  ```
- **clipboardWrite:**
  ```text
  The user can copy a username, password or 2FA code from the popup. CipherMoth clears the clipboard again after 30 seconds.
  ```
- **offscreen:**
  ```text
  Chrome's extension service worker has no clipboard access, so an offscreen document (reason CLIPBOARD) clears a password CipherMoth copied after 30 seconds. It does nothing else.
  ```
- **clipboardRead** (optional):
  ```text
  Optional and off by default. Requested only when the user turns on "Only clear what CipherMoth copied". The extension then compares a SHA-256 hash of the clipboard with the hash of what it copied before clearing, so it never wipes something the user copied later. The clipboard content is never stored or sent.
  ```
- **nativeMessaging** (optional):
  ```text
  Optional. Requested only when the user chooses "CipherMoth app on this computer" in the extension's settings. The extension then talks to the CipherMoth desktop app's native messaging host (com.ciphermoth.desktop) on the same computer instead of a server, with no network involved.
  ```
- **Host permissions** (optional, `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*`, `http://[::1]/*`):
  ```text
  Optional. At setup the extension requests access to exactly one host name: the address of the user's own CipherMoth server that the user typed in (and its API address if the user entered a separate one), so it can call that server's API. The patterns are broad only because every user's server has a different address; the extension never requests any other host. Plain http is allowed only for localhost.
  ```

**Remote code:** "No, I am not using remote code." (Everything is bundled; the extension
pages' CSP is `script-src 'self'`.)

**Data usage:** tick **no** data type. The developer receives no data: the extension
sends logins and page origins only between the browser and the user's own CipherMoth
(their server or the desktop app on the same computer), never to the developer or a
third party (design section 1). Tick all three certifications:
- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

If a reviewer asks: the closest categories would be "Authentication information" (the
logins it fills) and "Website content" (it reads input fields to fill them), handled
only on the user's device and the user's own server.

**Privacy policy URL:** `https://github.com/mr-grj/ciphermoth/blob/master/docs/PRIVACY.md`

## Distribution tab

- Payments: free.
- Visibility: Public (or Unlisted: installable only with the link; same review).
- Regions: All regions.

## Submitting

- Always the **`ciphermoth-extension-chromium-store-X.Y.Z.zip`** package (no `key` in
  its manifest; the store refuses one with "key field is not allowed in manifest").
- First upload only: the CI-built store zip plus `key.pem` at the zip root
  (desktop/RELEASING.md); check the dashboard's Item ID is
  `gjdobbdnepjkgfpcmhjdagkcjholjkkd` before submitting.
- Later uploads: the release asset unchanged (Package tab → Upload new package).
- "Submit for review": untick "Publish automatically after the review" when the
  listing should go live at a chosen moment (up to 30 days after approval).
