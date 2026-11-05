# Security

This is a password manager. Security isn't a feature here - it's the whole point. If you find something wrong, please don't open a public issue about it. Tell me privately first.

## Found something? Tell me here

Open a [GitHub Security Advisory](https://github.com/mr-grj/ciphermoth/security/advisories/new) - it's private by default, only visible to you and me. Describe what you found, how to reproduce it, and what you think the impact is. That's all I need to get started.

I'll acknowledge it within a few days. If it's real, I'll fix it and credit you in the release notes - unless you'd rather stay anonymous, which is also fine.

## What I actually care about

Things I want to know about:

- Anything that lets someone read passwords they shouldn't be able to
- Authentication or session bypass
- Encryption weaknesses or key leakage
- SQL injection, command injection, that whole family
- Anything that could expose the vault to an unauthorized party
- The browser extension filling a login where it should not (another site, a hidden field, a frame), or its session reaching more than it should

Things that are out of scope:

- Attacks that require physical access to the machine running the instance - if someone has that, it's already over
- Vulnerabilities in third-party dependencies that don't directly affect ciphermoth - please report those upstream
- Self-XSS or anything only exploitable by someone already authenticated with their own master password

## What the Python core knows

So you can judge reports (and your own deployment) against what CipherMoth actually does:

- The master password itself is never stored. The vault key is random and stored only wrapped (AES-256-GCM) under a key derived from the master password with Argon2id. The vault also stores a password commitment derived the same way, which lets the server reject a wrong password; like the wrapped key, it can be used to test guesses offline, but only at the full cost of one Argon2id run per guess, so there is no second, cheaper verifier (format 1's bcrypt hash is gone). The unwrapped key is never written to disk or logs. The format is specified in [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md).
- When you unlock, the server keeps the keys derived from the vault key in its own memory and gives your browser (or the CLI) a random session token instead. Only a SHA-256 digest of the token is kept. Every request checks the session, then checks its key against a check value stored in the vault. Sessions end after the configured inactivity timeout (plus at most 5 seconds for request latency), after 12 hours at most, on logout, when the master password changes, and when the server restarts; nothing about them is written to disk or logs. The inactivity timeout is a vault setting, so anyone holding a session can raise it (to 60 minutes at most); the 12-hour limit cannot be changed. While you're using the vault, the server process sees your secrets in plaintext, and Python cannot reliably erase a key from memory after a session ends.
- Clients never receive the vault key, and since v1.6.0 no route returns it or accepts it as a credential: a session token is the only way in. The `/check` route and `x-ciphermoth-key-derivation` header of v1.4.x clients are answered before any route runs (410 and 403, with an "update your client" message) without looking at the password or the key. The web UI from v1.5.0 and the CLI from v1.5.0 are the oldest clients that work. The trusted server process still derives the key, holds it in memory for the session and decrypts your entries while you use the vault; that is what lets the clients go without it.
- If a stored value fails its integrity check, that entry or attachment is left out of every listing and reported (web UI banner, `ciphermoth damaged`, `GET /api/vault/damaged`); backups and master password changes wait until it is removed or a snapshot is restored. Removing goes through `DELETE /api/vault/damaged/...`, which deletes a row only after checking that it really cannot be read.
- Everything in an entry is encrypted in the vault file with AES-256-GCM, names, usernames and descriptions included, and every encrypted value is bound to its own row and role, so moving one into another entry is detected. What remains readable is listed in [VAULT_FORMAT.md](docs/VAULT_FORMAT.md#4-sqlite-layout-schema-2): counts, trash membership, timestamps, sizes, which entries share a name, and the timeout settings. Someone who can write the file can still roll it (or a single entry) back to an older version, delete entries, or change those plaintext columns; that is not detected.
- Backups (`.cmbackup`) are complete and authenticated, encrypted with AES-256-GCM under Argon2id with their own salt and the master password current when they were made. Backup ZIPs from CipherMoth 2.0 and earlier used WinZip AES with PBKDF2-SHA1 at 1,000 iterations, which is much cheaper to brute-force, and kept entry names readable to anyone with the password; they can still be imported, but delete them once you have a new backup.

## Where the web UI keeps its session, and why

The browser keeps the session token in `sessionStorage` and sends it in an `x-ciphermoth-session` header. JavaScript running in the page can read it, so a cross-site scripting (XSS) bug could steal it. We considered an `HttpOnly`, `Secure`, `SameSite` cookie instead and decided against it for now:

- **It would not contain an XSS bug.** Injected script runs inside the unlocked UI, so it can call the API with the cookie and read every decrypted password directly. An `HttpOnly` cookie only stops it from copying the token for later use elsewhere, and a stolen token is already limited to the session's inactivity timeout and 12 hours.
- **It would break real deployments.** The UI and API are separate origins (ports 3000 and 8000 by default, often separate host names). Cookies across them need credentialed CORS. `Secure` cookies are dropped on the plain-`http` LAN addresses many people use. Browsers increasingly block cookies between unrelated sites.
- **It would add risks the header doesn't have.** Cookies are sent automatically, so every state-changing route would need cross-site request forgery (CSRF) protection; a custom header can't be sent cross-site without CORS approval. The CLI would still need the header, so there would be two authentication paths to keep correct.

What limits XSS instead:

- **A strict Content-Security-Policy.** No inline or remote scripts, no `eval`. Connections only to the UI's own origin, its API and GitHub's release address. Images only from the UI.
- **No HTML sinks.** The UI renders all text through React, and lint rules reject `innerHTML`, `dangerouslySetInnerHTML`, `eval` and similar sinks.
- **Little to steal.** The token is per tab, never in a URL, removed on logout and auto-lock, and useless after the session ends. API responses are `no-store`.

A policy cannot stop injected code from navigating the tab to another site with the token in the address, or from using WebRTC, and it ignores query strings on the allowed GitHub address; that is one more reason the UI accepts no HTML from anywhere.

Two session details worth knowing: closing a tab without logging out leaves its session open on the server until the inactivity timeout (a browser's "reopen closed tab" can restore it until then), and a duplicated tab shares the original's session, so logging out in one locks both.

## Updates and the supply chain

Release images (`ciphermoth-backend`, `ciphermoth-frontend`) are signed with [cosign](https://github.com/sigstore/cosign) - keyless, via GitHub OIDC - so each image's digest is provably built by CipherMoth's own release workflow. Verify them before you start a new version; the command is in [docs/UPDATING.md](docs/UPDATING.md).

Desktop updates use the official Tauri 2 updater, a fixed HTTPS GitHub Releases endpoint and an embedded public verification key. The private key is restricted to trusted release jobs. Artifact signatures bind the version and native platform filename; modified, unsigned, mismatched and older artifacts are refused before installation. The renderer cannot choose a key, endpoint, source URL or installer arguments. The user confirms installation; Rust clears the session and stops the Python core before replacing application files. Linux `.deb` installations use manual package updates. These signatures are separate from OS publisher signing: there is no Apple notarization or Windows Authenticode certificate.

The desktop has no backend network listener. Python owns keys and sessions, communicating over private framed pipes; React holds only an opaque token in memory. Its CSP permits native IPC, not arbitrary network requests. The optional Rust update check sends no vault information. The Docker edition checks GitHub from the browser and updates manually; the old Docker-socket updater is retired. See [update instructions](docs/UPDATING.md).

## The vault file and its snapshots

The vault is one SQLite file, `vault.db`, in the data folder (`/data` in the backend container), created with mode `0600` in a `0700` folder. It holds what this page describes as encrypted, plus the plaintext metadata listed above and the wrapped vault key. SQLite runs with `secure_delete` on, so deleted rows are overwritten in the file, but copies can survive in the write-ahead log (`vault.db-wal`) until its frames are reused, in filesystem snapshots, on SSDs (wear levelling) and in any backup of the volume. The WAL has a 16 MiB post-checkpoint retention target, not a hard size cap: active readers and large transactions can make it larger. After a master password change, old ciphertext can likewise remain there and in every earlier snapshot.

Snapshots (`ciphermoth-admin snapshot`) are raw copies of the vault file, with the same protection and the same metadata exposure. They open only with the master password that was current when they were taken, so an old snapshot also keeps working with an old master password: delete snapshots and backups you no longer need after changing a master password you believe was exposed. Vault files and snapshots written by CipherMoth 2.0 or earlier keep entry names, usernames and descriptions in plaintext.

## Biometric unlock

It is off by default. Turning it on is a trade you make for convenience, so here is exactly what it changes.

- **What it adds.** A second wrapped copy of the vault key (AES-256-GCM) in `device-unlock.json`, mode `0600`, next to `vault.db` but outside it, so it is in no snapshot or backup. It is wrapped under a 32-byte secret from the device's authenticator: a Secure Enclave key agreement in the macOS app, a passkey's PRF output in a browser. The secret is never stored. Only the master password can create this copy, because a session does not hold the raw vault key.
- **What the file gives a thief.** Nothing without the authenticator. The Secure Enclave key blob is usable only on that Mac and only after a fingerprint check. A copy of the vault folder alone stays as useless as the vault file.
- **What it weakens.** The vault now opens with the master password **or** with whatever that device accepts. Someone whose finger is enrolled on your Mac, or who is forced to touch it, gets in. On macOS only fingerprints that existed at enrollment count: adding or removing one ends the unlock until you turn it on again. A passkey follows the rules of the place that stores it: iCloud Keychain or a password manager may sync it to your other devices, and those devices can then produce the same secret if they can reach this server. Malware running as your user can also trigger a real system prompt and hope you touch it; it could equally capture a typed master password, and same-user compromise is outside what the vault protects against.
- **The reminder is a habit, not a boundary.** The server refuses a biometric unlock once 7, 14 or 30 days have passed since the last master password unlock, and also if the clock moved back. Someone who can rewrite `device-unlock.json` can skip the reminder, but already controls the account and still needs the authenticator.
- **What ends it.** Turning it off deletes that device's wrapped copy (a passkey stays in your OS password list, opening nothing; you can delete it there). Changing the master password replaces the vault key and removes every enrollment. A wrapped copy that outlives its vault key (for example after restoring a snapshot) fails the key check and is removed the first time it is used.
- **Server trust is unchanged.** Like the master password, the secret reaches the Python core at unlock. In the Docker edition it crosses the network, so use HTTPS for anything beyond localhost, which browsers require for passkeys anyway. No fingerprint or face data ever reaches CipherMoth.

## Security keys

Optional, off by default (Settings → Security). This is a second factor that takes part in the encryption, not only a login check.

- **What it changes in the vault.** A random 32-byte *factor key* joins the master password: the key record's commitment and key-wrapping key are derived from Argon2id(master password) together with the factor key (`docs/VAULT_FORMAT.md` section 3). Each registered security key holds a copy of the factor key wrapped (AES-256-GCM) under a secret only that key can produce: its WebAuthn PRF output (CTAP2 `hmac-secret`) for a random salt the vault stores. Its credential id, public key, relying party and salt are associated data of that wrapping, so swapping any of them in the file opens nothing.
- **What a thief gets.** The vault file, a snapshot or the master password alone: nothing, not even a way to test password guesses offline (the commitment needs the factor key). The key alone: nothing without the master password, and nothing without the key's PIN. Backups (`.cmbackup`) are deliberately protected by the master password alone, so they restore on a new install without the key: keep them as safe as the vault.
- **Every unlock is checked twice.** The key signs a fresh, single-use, 32-byte challenge (five minutes, bound to its purpose and, for changes inside a session, to that session), and the server verifies the signature, the relying party, the origin, user presence, **user verification** (the key's PIN) and that the signature counter moved forward (a cloned key is refused), with Yubico's `python-fido2`. Then the PRF secret must unwrap the factor key. A recorded PRF secret is useless without a fresh signature, and a forged signature is useless without the secret.
- **Why the PIN is required.** A key returns a different PRF secret with and without user verification, and browsers verify a key with a PIN whenever PRF is requested, so every client (browser, desktop app, CLI) must verify to get the same secret. It also means a stolen key needs its PIN, which the key locks after 8 wrong tries.
- **Where it works.** Chrome, Edge and Firefox over HTTPS or on `localhost` (WebAuthn scopes a credential to the host name it was registered on: register a key on each name you use), the desktop app (its core talks to the key over USB; the PIN goes over a private pipe, never a command line) and the CLI (over USB, on the computer the key is plugged into).
- **Losing keys.** Register a backup key and keep it somewhere safe, or keep a recovery code. Removing a key you lost stops it from opening the current vault file, but a copy of the file from before, together with that key and the master password of that time, still opens that copy: change the master password too. Removing the last key turns the factor off and wraps the vault key under the master password alone again.
- **Biometric unlock stays a separate way in.** Touch ID or a passkey wraps the vault key under that device's secret, so it opens the vault without the security key. Turning it on (and the periodic master password reminder) needs the security key. Leave it off if you want every unlock to need the key.

## The recovery code

Optional (Settings → Security), and strongly recommended once you use a security key.

- **What it is.** 160 random bits from the operating system's CSPRNG, shown once as eight groups of four Crockford base32 characters (case, spaces, dashes and the look-alikes O, I and L do not matter). It is never stored, not even hashed.
- **What the vault stores.** Argon2id (with its own salt) turns the code into an X25519 key pair. The vault keeps the public key, the vault key sealed to it (ephemeral X25519, HKDF-SHA256, AES-256-GCM) and an HMAC of the public key under the vault key. Sealing needs only the public key, so a master password change seals the new vault key to the same code without knowing it; the HMAC makes the change refuse a public key that someone who can write the file planted to receive future vault keys.
- **What it can do.** Whoever holds the code can set a new master password and open the vault, also without your security keys (that is its purpose: a forgotten password, lost keys). Treat it like the vault itself: write it down or print it and keep it offline. Guessing it is not practical (2^160 codes, each guess an Argon2id run plus the API's rate limit).
- **Using it** re-keys the vault exactly like a master password change, ends every other session, turns biometric unlock off and replaces the code with a new one shown once. Your security keys keep working (the vault keeps their factor key sealed under the vault key) unless you say you lost them, which removes them.
- **Without one**, nobody can reset a forgotten master password: not the server, not the maintainer.

## The browser extension

Optional (Chrome, Brave, Edge, Opera, Vivaldi, Firefox), for the server edition. It fills a login into the page you are on only when you click its button or press its shortcut. The full guide, with what it guarantees and what it cannot, is [docs/EXTENSION.md](docs/EXTENSION.md).

- **A session that can only fill.** Unlocking (with the master password in the extension's popup, or in the web app, which then hands a token to the extension) opens an *extension session*: a random token mapped to the vault key in the server's memory, like any session, with the same inactivity timeout and 12-hour limit, and ended by the same events (lock, master password change, recovery, restart). The server, not the extension, limits it to five routes under `/api/extension/`: the logins whose saved address matches a page, a search over logins (name, username, site), one login's username and password at the moment of a fill or copy, a 2FA code (never the secret), and a heartbeat. Every other route refuses it with `403 extension_scope`, and those five refuse a normal session. A test matrix classifies every API route for both kinds of token, deny by default. At most 8 extension sessions exist, apart from web sessions; Settings → Browser extension lists them (browser and times, never tokens) and disconnects any.
- **What the extension keeps.** The token sits in the browser's memory-only session storage, readable only by the extension's own pages, and goes when the browser exits. Its settings (the vault's address, two preferences) are the only thing written to disk. No password, entry name or token: the tests scan the whole browser profile for them after a session.
- **What it sends.** Only to the address you configured, only the page's origin (scheme, host and port) to find matches. Requests refuse redirects, send no cookies and fail on TLS errors. No favicons, analytics or remote configuration.
- **The handoff.** "Unlock in CipherMoth" opens your vault with a random single-use 256-bit request in the URL fragment (never sent to a server). After you confirm in the web app, it posts the token to its own page, where a script of the extension, registered only on your vault's address and only while that request is pending, passes it on. The extension accepts it once, from that tab's top frame, on that origin, with that request, within five minutes, and only after the server confirms it.
- **Filling.** Only after your click or shortcut (pages cannot trigger either), only the top frame, only when the page's origin still equals the one matched (checked again inside the page), only fields a person can see and use: not hidden, transparent, masked, clipped, covered, read-only, off-screen or in a frame, and never a sign-up form. Matching is exact (scheme, host, port) unless you turn on subdomains, which never crosses a public suffix. Nothing is ever drawn inside a page, so there is nothing to click-jack. Hostile test pages for all of this (an "attack lab") run in CI.
- **Limits.** The guarantees are per origin: once a visible field on the right site is filled, that site's own scripts can read it, as they could if you typed it. A stolen extension token can, until it expires or you disconnect it, read login passwords one by one (rate-limited) though nothing else. Malware running as your user can read browser memory. Reports about any of this are very welcome.

## One thing worth knowing

CipherMoth is built to run on a machine you trust and control - your home server, a VPS behind a firewall, a Raspberry Pi in your closet. It is not built to sit directly on the open internet without a reverse proxy, HTTPS, and some thought about who can reach it. If you're deploying it that way, the README has guidance. If something goes wrong because it was exposed without those precautions, that's a configuration problem, not a vulnerability.
