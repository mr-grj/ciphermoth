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

## One thing worth knowing

CipherMoth is built to run on a machine you trust and control - your home server, a VPS behind a firewall, a Raspberry Pi in your closet. It is not built to sit directly on the open internet without a reverse proxy, HTTPS, and some thought about who can reach it. If you're deploying it that way, the README has guidance. If something goes wrong because it was exposed without those precautions, that's a configuration problem, not a vulnerability.
