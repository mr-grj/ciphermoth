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
      `backend/crud/extension.py`, `backend/url_match.py`.
- [ ] `npm audit` clean beyond the accepted advisories (`node scripts/npm_audit.mjs extension`).
- [ ] Before the first store release: consider an external review.
