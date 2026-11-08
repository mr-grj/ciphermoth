# Manual validation (every extension release)

The automated suites (`npm test`, `npm run test:e2e`, backend `tests/test_extension*.py`)
must be green first. Then, on the release candidate packages from CI (not a local
build), tick every box. Record the browser versions and anything odd in the PR.

Setup: a CipherMoth server on HTTPS (a real certificate, or one your OS trusts), a test
vault with a login for each real site below (use throwaway accounts), one login with a
2FA secret, one `http://` login (for example a router page), and a second vault with a
security key registered (YubiKey) for the handoff checks.

## 1. Each browser (latest stable)

Chrome · Brave · Firefox · Firefox ESR (the release browsers). Edge, Opera and Vivaldi are
best effort: a quick load-and-fill check when convenient.

For each browser:

- [ ] **Install** from the store (once listed) or the signed XPI (Firefox), and the
      unpacked/sideload path from the release zip after checking `SHA256SUMS`.
- [ ] **Permissions at install**: only "read and change data on websites you click on"
      style wording (activeTab), storage, clipboard write; no "all websites".
- [ ] **Onboarding**: settings open on install; connecting asks for exactly the vault's
      origin (and the API's, if separate). An `http://` non-localhost address is refused.
- [ ] **Unlock** with the master password; a wrong one says "Wrong master password".
- [ ] **Unlock in CipherMoth** on the security-key vault: the tab opens, unlock with the
      YubiKey, "Connect <browser> to this vault?" names the right browser, Connect closes
      the tab and the popup is unlocked. Cancel leaves the extension locked.
- [ ] **Fill** from the popup (click and Enter) and with **Ctrl+Shift+L / ⌘+Shift+L**
      (one match fills directly, several open the popup).
- [ ] **Remap both shortcuts** in the browser's shortcut settings; the new keys work.
- [ ] **Copy** username, password and 2FA code; the clipboard clears after 30 s. With
      "Only clear what CipherMoth copied" on, copy something else within 30 s: it stays.
- [ ] **Lock** (🔒), then **disconnect** from CipherMoth → Settings → Browser extension:
      the popup is locked on next open. Restarting the browser locks it too.
- [ ] **Light and dark** (switch the OS theme): popup and settings are readable, focus
      rings visible.
- [ ] **200 % zoom** (browser zoom on the popup and settings): nothing cut off or
      overlapping.
- [ ] **Screen reader** (VoiceOver on macOS, NVDA on Windows): the popup announces the
      page host, the search field, the list as a listbox with each login's name and
      username, every button by its purpose ("Copy password for GitHub"), and prompts.

## 1b. Desktop mode (each release browser; macOS at least, Windows and Linux when you can)

Setup: the desktop app built from the release commit (quit any other CipherMoth window
first: it uses the same vault folder), a vault with a few logins (one with 2FA), a
security key (YubiKey) registered and Touch ID enrolled for the Touch ID checks.

In the desktop app:

- [ ] **Off by default**: Settings → Browser extension shows "Allow browser extensions"
      off, and no manifest exists (macOS:
      `~/Library/Application Support/{Google/Chrome,BraveSoftware/Brave-Browser,Mozilla}/NativeMessagingHosts/com.ciphermoth.desktop.json`;
      Linux: `~/.config/{google-chrome,BraveSoftware/Brave-Browser}/NativeMessagingHosts/`,
      `~/.mozilla/native-messaging-hosts/`; Windows: `HKCU\Software\{Google\Chrome,BraveSoftware\Brave-Browser,Mozilla}\NativeMessagingHosts\com.ciphermoth.desktop`).
- [ ] **Turn it on**: "Set up for Chrome, Brave and Firefox" (the installed ones); the
      manifests exist and name only the CipherMoth extension ids and the host inside the
      app.

In each browser:

- [ ] **Choose "CipherMoth app on this computer"** in the extension's settings: the browser
      asks to "communicate with cooperating native applications" (Firefox: "Exchange
      messages with programs other than Firefox"). Nothing else is asked. Chrome and Brave
      then close and reopen the settings (the background restarts to use the permission).
- [ ] **Pair right away** after choosing (no "Something went wrong."), then: the popup
      and the app's dialog show the **same six digits**. **Don't
      allow** → the popup says pairing wasn't allowed and nothing is paired. Pair again,
      **Allow** → the popup lists logins; the app's Settings lists the browser.
- [ ] **Fill, copy, 2FA and the shortcut** work as in server mode (section 1).
- [ ] **App locked** (Log out, ⌘/Ctrl+Shift+L in the app, or its inactivity timeout): the
      popup says "CipherMoth is locked". **Unlock CipherMoth** brings the app forward;
      unlock with the master password, then (on separate tries) the **YubiKey** and
      **Touch ID**; the popup works again when reopened, without pairing again. (Adding
      the YubiKey in Settings → Security: its PIN field takes typing; Escape cancels.)
- [ ] **Lock CipherMoth** (🔒 in the popup) locks the app.
- [ ] **Quit the app**: the popup says "CipherMoth isn't running"; **Open CipherMoth**
      starts it.
- [ ] **Turn the switch off**: the popup says to turn browser extensions on; the manifests
      are gone. Turn it on again: the browser works without pairing again.
- [ ] **Remove** the browser in the app's Settings: the popup asks to pair again.
- [ ] **Switch the extension to your server and back**: server mode works, and back in
      desktop mode the pairing is still there.
- [ ] **No token in the browser**: in the extension's background console,
      `chrome.storage.session.get()` (Firefox: `browser.storage.session.get()`) holds no
      `session`, and `chrome.storage.local.get()` only `config` (and `installId`, a random
      non-secret id, once server mode was used; never `reopenOptions` after the restart).

## 2. Real sites

- [ ] GitHub, GitLab: username and password filled, sign-in works.
- [ ] Google, Microsoft (multi-step): "Username filled. Fill again on the next step.",
      then the password step fills.
- [ ] Apple ID (login form in a frame): nothing filled, the popup says the form may be inside a frame and offers Copy.
- [ ] Amazon (email first, then password): fills each step like Google and Microsoft.
      works.
- [ ] A React single-page app login (for example a self-hosted Grafana or the site of
      your choice): the app accepts the filled values (sign-in button enables).
- [ ] A site with shadow-DOM inputs: filled.
- [ ] A bank-style page with a virtual keyboard or read-only password field: a graceful
      refusal, nothing typed.
- [ ] An `http://` page (router): the "isn't secure" prompt; Fill anyway works only for
      the `http://` login saved for that address.
- [ ] A login picked from search on another site: the "saved for … Fill it on …?" prompt.

## 3. Hostile pages

- [ ] Tóth's public DOM-based extension clickjacking proof-of-concept pages (DEF CON 33,
      2025), if available: nothing is filled or revealed by clicking anywhere on them.
- [ ] The attack lab pages by hand in each browser: serve `extension/tests/attack-lab`
      (for example `npx serve extension/tests/attack-lab`) and open
      `case.html?c=hf-opacity-0`, `cj-overlay`, `if-attacker-child`: nothing filled.

## 4. Security review

- [ ] `/security-review` and `/code-review` at high effort on the full diff since the last
      extension release.
- [ ] Read the whole release diff of `extension/src` and `backend/api/endpoints/extension.py`,
      `backend/crud/extension.py`, `backend/url_match.py`, and for desktop mode
      `desktop/src-tauri/extension-link`, `desktop/src-tauri/native-host`,
      `desktop/src-tauri/src/extension.rs` and `desktop/core/desktop_core/extension.py`.
- [ ] `npm audit` clean beyond the accepted advisories (`node scripts/npm_audit.mjs extension`).
- [ ] Before the first store release: consider an external review.
