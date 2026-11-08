# Changelog

## [Unreleased]

The browser extension now fills from the desktop app too.

### Added

- **Desktop mode for the browser extension** ([docs/EXTENSION.md](docs/EXTENSION.md#desktop-mode)). In the desktop app, turn on **Settings → Browser extension → Allow browser extensions** (off by default); in the extension's settings choose **CipherMoth app on this computer**. Pair each browser once: the app asks "Allow <browser> to fill logins?" and shows a six-digit code that must match the one in the extension's popup. After that the extension fills, copies and shows 2FA codes whenever the app is unlocked; the popup offers **Unlock CipherMoth** (brings the app forward: master password, security key or Touch ID) and **Open CipherMoth** when it isn't running, and its lock button locks the app. Chrome, Brave and Firefox on macOS, Windows and Linux; Edge, Chromium and Vivaldi should work too. Needs Chrome 133 or Firefox 130 (WebCrypto X25519).
- The desktop app lists paired browsers in **Settings → Browser extension**, with **Remove**. Turning the switch off disconnects every browser and removes the native-host manifests it wrote (files on macOS and Linux, `HKCU` registry keys on Windows); the pairings stay.
- Every desktop package ships `ciphermoth-native-host` next to the app (an AppImage copies it into the app's data folder, since its mount path changes).

### Security

- Desktop mode uses no network. The browser starts the native host only for the CipherMoth extension; the host relays to the app over a same-user local socket or named pipe (permissions and peer checks on both ends). Pairing is an X25519 exchange with a commitment and a short authentication string; every later message is end-to-end AES-256-GCM between the extension and the app with per-connection keys and counter nonces, so the host sees no login and replayed or tampered messages end the connection. The app keeps the extension session's token; the extension holds only a non-extractable pairing key. Specified with frozen vectors (`testdata/vectors/extension-channel.json`) used by Rust, TypeScript and Python; tested end to end with the real host in Chromium and on the six desktop CI runners.

### Fixed

- Desktop app: adding a security key in **Settings → Security** no longer gets stuck at "Enter your security key's PIN" (the PIN field took no typing because the Settings dialog kept the focus).
- The desktop core no longer leaves a request unanswered when it carries an extension session's token (the native session-deadline lookup refused the token's scope instead of ignoring it).

### Changed

- The extension's settings start with **Fill from**: the desktop app or your server (one at a time; switching keeps a desktop pairing). Existing server setups are unchanged.
- The CLI is unchanged.

## [3.6.0] - 2026-11-06

A browser extension that fills a login only when you ask, and can do nothing else.

### Added

- **Browser extension** for Chrome, Brave (Chromium 120+) and Firefox 128+ (other Chromium browsers such as Edge, Opera and Vivaldi should work too), for the server edition ([docs/EXTENSION.md](docs/EXTENSION.md)). Click its toolbar button (or press **Ctrl+Shift+L**, **⌘+Shift+L** on a Mac) to see the logins saved for the page, search all your logins, and fill, copy the username or password, or copy a live 2FA code. Nothing appears inside web pages, nothing fills on page load, and it never asks to save logins. It fills only the top frame, only when the page's origin still matches, and only fields a person can see and use; it asks first before filling a login saved for another site or any plain-HTTP page, and refuses sign-up forms. Exact origin matching by default; **Match subdomains** never crosses a public suffix. Keyboard first (arrows, Enter, Ctrl/⌘+C, Ctrl/⌘+Shift+C, Esc), dark and light like the app. Copied values clear after 30 seconds (optionally only when the clipboard still holds CipherMoth's copy).
- **Unlock** in the extension with your master password, or **Unlock in CipherMoth**: the extension opens your vault, you unlock there (security key, passkey, Touch ID) and confirm "Connect <browser> to this vault?". Vaults that require a security key always use this.
- **Settings → Browser extension** in the web app: an install button for your browser (pointing at the guide until the store listings are published; once a browser of the same name is connected it says so instead), and the list of connected browsers (browser, connected, last used) with **Disconnect**.
- CLI: `ciphermoth browsers` lists the connected browsers and `ciphermoth browsers --disconnect <id>` disconnects one.
- API: extension sessions, which the server limits to filling. `POST /api/extension/unlock` (30/hr; a vault with a security key answers 409 `use_handoff`), `POST /api/extension/sessions` (a full session connects an extension, 10/hr), `GET /api/extension/sessions` and `DELETE /api/extension/sessions/{id}`, and for extension sessions only `POST /api/extension/matches`, `/search`, `/credential` (300/hr), `/totp` (300/hr), `/session` and `/lock`. An extension session on any other route is refused with 403 `extension_scope`, and those routes refuse normal sessions. One session per browser profile (a new unlock or connection replaces that installation's previous session, by an optional random `client` id), at most 8, separate from web sessions; they share the inactivity timeout, the 12-hour limit and every way a session ends. `/api/meta` lists `browser-extension`.
- Releases attach reproducible extension packages (`ciphermoth-extension-chromium-X.Y.Z.zip`, `ciphermoth-extension-firefox-X.Y.Z.zip` and, once Mozilla signing is configured, a signed `.xpi`) with build provenance; `extension/scripts/verify.mjs` rebuilds a tag and compares the checksums.

### Security

- The extension's guarantees are tested in CI against a live backend in Chromium, including an attack lab of hostile pages (DOM-based extension clickjacking, hidden-field harvesting, frames, lookalike and homograph hosts, navigation between popup and fill, form tricks, messages from pages and other extensions, synthetic key presses, hostile servers, clipboard) and a scan of the browser profile for secrets after use. URL matching is pinned by `testdata/vectors/url-matching.json`, shared by the server and the extension. See [SECURITY.md](SECURITY.md#the-browser-extension) for what it protects and its limits.

### Changed

- The Settings dialog keeps one size on every tab (wider, at most 768 px tall); longer content scrolls inside it instead of the dialog growing and shrinking as you switch tabs.
- The CLI is unchanged.

## [3.5.0] - 2026-11-05

Put many secrets in their place at once, and get an old password back when you need it.

### Added

- **Password history.** Right-click a login and choose **Password history**, press **H** on a selected row, or use the history button that appears next to the password when you hover a row. The dialog shows the current password and every earlier one (the last 10), newest first, each with when it was replaced and how long it was in use (hover for the exact time). Reveal a single value or all of them, copy one (the clipboard still clears itself), or **Use again** to make an earlier password current once more, for example when a website never accepted the new one. The password it replaces moves to the history, and the confirmation says when that would drop the oldest saved one. A value you went back to is marked "same as current". The edit form's history section uses the same rows. CLI: `ciphermoth password history <name>`.
- **Move entries to a folder together.** Select rows and choose **Move to folder** in the selection bar, or right-click an entry (or a selection) and pick **Move to folder…**. The picker lists your folders with how many entries each holds; type to filter them or to create a new one, pick **No folder** to take entries out of their folder, and press Enter (arrows change the pick, a double-click moves at once). A typed name that matches an existing folder in another case ("work") goes to that folder instead of starting a near-duplicate. Folder names are trimmed, never empty and at most 200 characters, with a counter near the limit; long names end in an ellipsis everywhere instead of stretching the layout. The move is all or nothing, and the toast offers **Undo**, which puts every entry back in the folder it came from.
- **Find entries with attachments or notes at a glance.** The Name column marks entries with attachments (a paperclip and how many) and logins with notes (a notes icon), each with a tooltip. A new **Filters** button next to the folder filter narrows the list to Favorites, Secure notes, Logins with notes, With attachments or With 2FA, each with how many entries it matches in the current folder and search. Several filters combine (an entry must match all of them), the button shows how many are on, and an empty result offers Clear filters.
- API: `POST /api/vault/entries/move` (`{"entries": [{"password_name": ...}], "folder": "Work"}`, `null` for no folder) moves up to 10,000 entries in one transaction and reports how many moved and how many were already there; `/api/meta` lists the `bulk-entry-move` feature. CLI: `ciphermoth password move <name>... --folder <folder>` (or `--no-folder`).

### Changed

- A moved entry counts as edited, so it is no longer marked as backed up (as when its folder is changed in the edit form). Entries already in the target folder are left untouched.
- The folder filter shows how many entries each folder holds (in its menu, and in its label once a folder is chosen: "Folder (10 entries)"), and long folder names end in an ellipsis instead of widening its menu.
- The entry form refuses a folder name over 200 characters with a clear message (and a counter near the limit) instead of the server's generic validation error.

### Fixed

- The sort arrow in the vault and Trash column headers is smaller, takes the header text's colour and no longer sits in a filled circle of a slightly different shade.
- The vault page no longer logs the names of selected entries to the browser console (a debugging line left in 3.3.0).

## [3.4.0] - 2026-11-03

A security key that takes part in the encryption itself, and a way back if you forget your master password.

### Added

- **Require a security key** (Settings → Security). Register a FIDO2 key such as a YubiKey and the vault is encrypted with your master password **and** the key together: a secret only that key can produce (its WebAuthn PRF / CTAP2 hmac-secret output) joins the master password in the key record. A copied vault file, snapshot or a stolen master password opens nothing without the key, and the file alone no longer even lets anyone test password guesses. Every unlock also checks the key's signature over a fresh, single-use challenge, its user verification (its PIN) and its signature counter (clone detection). Register a backup key too; any registered key unlocks. Works in Chrome, Edge and Firefox (HTTPS or localhost), in the desktop app (which talks to the key over USB) and in the CLI. Biometric unlock keeps working and needs the key to turn on.
- **Recovery code** (Settings → Security). A one-time code (160 random bits, eight groups of four) that sets a new master password if you forget yours, and gets you in if you lose your security keys: **Forgot master password?** on the unlock screen, or `ciphermoth recover`. Using it re-keys the vault, logs every other session out and shows a new code; your keys keep working unless you say you lost them. The vault stores only a public key and the vault key sealed to it (X25519), bound to the vault key, so a master password change keeps the code working without knowing it.
- **Change the master password from the app** (Settings → Security), with the strength meter. It re-encrypts everything under a new vault key and logs you out everywhere.
- Every security change (keys, recovery code, master password, biometric unlock, backups) asks for the master password again, and for the security key once one is required, so an unattended unlocked screen cannot make it.
- API: `POST /api/master_password/unlock/challenge`, `POST /api/master_password/recover`, `GET /api/security`, `POST /api/security/challenge`, `POST /api/security/keys/options`, `POST /api/security/keys`, `POST /api/security/keys/{id}/remove`, `POST /api/security/recovery-code` and `.../remove`; unlock, backup, master password change and biometric enrollment accept a `security_key` answer; `/api/meta` lists `security-keys` and `recovery-code`; `/api/master_password/status` says whether a key is required and whether a recovery code exists. CLI: unlock and `backup` ask the key (and its PIN) over USB; new `ciphermoth recover`.

### Changed

- **Vault schema 3.** The first start of this release upgrades a 3.3.0 vault in place, in one transaction, after keeping a copy of it in `snapshots/before-schema-3-<time>.db`. Nothing existing changes: a vault without keys or a recovery code works exactly as before. Older releases refuse a schema 3 vault (restore that snapshot to go back).
- The settings dialog has General and Security tabs.

## [3.3.0] - 2026-11-03

Tidy many secrets at once, and reach the everyday actions with a right-click.

### Added

- **Select several entries and move them to the trash together.** Tick rows (the header box selects every entry the current search or folder shows); the selection stays across pages and searches, a bar shows how many are selected and how many the current filter hides, and the confirmation lists every name. The move is all or nothing, and the toast offers **Undo**. Delete or Backspace moves the selection (or the focused row) to the trash, Escape clears it.
- **The Trash has the same selection**, with Restore and Delete forever for many entries at once. Deleting forever lists what goes and never confirms on Enter by itself; a restore that would clash with an active name changes nothing and says which name.
- **Quick actions**: double-click a row (or press Enter) to edit it, and right-click it for Copy username, Copy password (or note), Copy 2FA code, Copy website, Open website, Edit, Duplicate, favorite and Move to Trash. Right-clicking a selected row acts on the whole selection. Shift+right-click keeps the browser's own menu.
- API: `POST /api/vault/entries/trash`, `POST /api/vault/trash/restore` and `POST /api/vault/trash/purge` act on up to 10,000 entries in one transaction; `/api/meta` lists the `bulk-entry-actions` feature. CLI: `ciphermoth password delete` takes several names and moves them together.

- **Clear the search with one click**: an × appears in the search box once you type (Escape works too), and an empty result offers "Clear search".
- **A real menu bar in the macOS app**: New Login (⌘N), New Secure Note (⇧⌘N), Import, Back Up Vault, Find (⌘F), Trash, Vault Health, Settings (⌘,), Lock Vault (⇧⌘L), Check for Updates, a light/dark switch, and Help links to the project, its release notes and its issue tracker. Vault items are greyed out while the vault is locked, and a menu action never replaces a dialog you are working in.

### Changed

- Copy toasts say what was copied ("Password copied.").

### Fixed

- Quitting the desktop app (⌘Q) froze the window for about three seconds: the shutdown waited on the window it was trying to reset. It now closes at once (about 0.2 s) and still shuts the vault core down cleanly.

## [3.2.0] - 2026-11-02

Unlock with a touch, and a vault table that fits your window.

### Added

- **Unlock with Touch ID or another biometric**, as an option in Settings, next to the master password. The desktop app on Macs with Touch ID uses a Secure Enclave key tied to the current fingerprints; browsers use a passkey with the PRF extension (HTTPS or localhost, on a device with a fingerprint, face or PIN unlock). Turning it on needs the master password and it works only on that device. The master password is asked for again every 7, 14 or 30 days (14 by default) so it is not forgotten, and changing the master password ends every biometric unlock. The vault format and schema are unchanged. The CLI keeps using the master password.

### Changed

- **The vault table scrolls on its own**: the app bar, search and page controls stay in place at every window size. The page only scrolls when a window is too short to fit the table (landscape phones). Page size choices now go up to 100 (default 25) and are remembered per browser. A new search or folder filter returns to the first page, and each page starts at its first row.
- Smaller screens: the toolbar buttons become icons, unused or unfitting columns (folder, tags, 2FA) stay hidden until needed, row actions stay visible on touch screens, and the theme toggle no longer covers the page arrows.

### Security

- Update certifi to 2026.10.23, which no longer trusts the emSign root behind compromised eMudhra intermediates (PYSEC-2026-4320). This affects the `ciphermoth` CLI inside the Docker backend image when it connects to a remote HTTPS API; the desktop app does not include certifi.
- Update the frontend image's file server dependency fast-uri and the frontend's follow-redirects, Vite, Vitest and zod to versions with published fixes.

## [3.1.0] - 2026-10-17

CipherMoth is now a standalone desktop password manager for macOS, Windows and Linux. Your secrets stay in the dark; Docker remains available.

### Added

- Native desktop installers for Apple Silicon/Intel macOS, Windows x64/ARM64 and Linux x64/ARM64, with bundled Python 3.13 and SQLite. No development tools or backend listener.
- Optional GitHub release checks and user-confirmed Tauri updates, with mandatory signatures binding the release version and native architecture. Downloads can be canceled; verified installs lock the vault and preserve its local data.
- DMGs, NSIS installers, AppImages, Debian packages, updater signatures, `latest.json`, SHA-256 checksums and source provenance in one release. AppImage supports built-in updates; Debian uses manual package updates.
- Native clipboard clearing, automatic locking, private binary IPC and complete encrypted backups using the existing vault format. Passwords, notes, attachments, TOTP, generator, folders, history and Trash are shared with the Docker edition.

### Changed

- Production app identity is `com.ciphermoth.desktop`, with a separate vault from Alpha and Docker. Existing vaults are never moved automatically.
- Updater credentials are restricted to trusted release jobs. Installer signing for Apple/Microsoft verified-publisher status is not provided; OS warnings and managed-device restrictions may apply.
- Preserve explicitly injected empty session stores, enforcing the desktop single-session policy while retaining the server API.
- Wait for saved settings before checking for updates, so a disabled preference is respected after unlocking.

## [3.0.0] - 2026-10-16

CipherMoth 3.0 encrypts entry metadata and introduces complete, authenticated encrypted backups.

This release changes how the vault is encrypted (vault format 2) and replaces the backup format. **It needs a new vault**: it does not open or convert a vault created by CipherMoth 2.0, and never changes or deletes one. The format is specified in [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md).

### Upgrading

- **Make a backup in 2.0 before updating**, and a snapshot. A 2.0 vault is refused at startup with a message ("was created by CipherMoth 2.0 or earlier"); nothing is changed. Move it aside with the new `ciphermoth-admin set-aside` (it is moved into the snapshot folder, never deleted), start the new version, create a vault, and import the 2.0 backup ZIP. The steps, and how to go back to 2.0, are in [docs/UPDATING.md](docs/UPDATING.md#moving-from-ciphermoth-20-vault-format-1).
- The 2.0 backup ZIP carries active entries only (no trash, history, attachments or settings), as before. New backups are complete.
- **Rollback needs the preserved 2.0 vault.** CipherMoth 2.0 cannot open a 3.0 vault; a raw 2.0 SQLite snapshot is for recovery with 2.0, not import into 3.0. Updates remain manual; one-click updates are unavailable.
- Use the CLI of this release. A 2.0 CLI still works against this server, but its `backup` saves the new format under a `.zip` name and its `import` sends the current master password as the backup password.

### Security

- **Entry names, usernames and descriptions are encrypted.** Every entry is one AES-256-GCM document (name, type, username, password or note, website, 2FA secret, description, tags, folder, custom fields, password history, favorite), bound by its associated data to a random id of its own row, so an encrypted value cannot be moved to another entry or role without being detected. Attachment names, types and bytes are sealed the same way and bound to their entry. Entries are found by name through an HMAC-SHA256 index under a key derived from the vault key; there is no plaintext copy of any entry field in the file. What stays readable (counts, trash membership, timestamps, sizes, which entries share a name, the timeout settings) is listed in the format document.
- **A random vault key, wrapped under the master password.** Unlock derives a key with Argon2id (same parameters as before, now stored with the vault so they can be raised later) and unwraps the vault key with AES-256-GCM, after checking a password commitment. **The bcrypt password hash is gone**, so a stolen vault offers no check cheaper than Argon2id. Changing the master password creates a new vault key and salt and re-encrypts every entry and attachment, as before.
- **Complete, authenticated backups (`.cmbackup`).** A backup holds active and trashed entries with history, favorites and timestamps, attachments byte for byte, and the settings, encrypted with AES-256-GCM under Argon2id with the backup's own random salt and the current master password (checked before the file is written). A restore runs in one transaction after checking everything: a wrong password, a damaged, cut-off, reordered or inconsistent file changes nothing. The old ZIP format (WinZip AES, PBKDF2-SHA1 with 1,000 iterations) is no longer written.
- **Strict reads.** A stored value that fails authentication or its format check stops the request with `"code": "vault_damaged"` (500) and the entry's row number, instead of being shown or overwritten.
- A value SQLite cannot decode no longer makes every later write fail as busy: a connection that raised a database error is discarded instead of reused (Python's `sqlite3` kept the failed statement's old snapshot open).

### Added

- `ciphermoth-admin set-aside`: moves a vault this release cannot open (or any vault) with its write-ahead log into `snapshots/set-aside-<time>/`, so the next start creates a new one. Refuses while CipherMoth runs.
- Restoring a complete backup into a vault that already has entries merges: new entries are added, an entry with the same name is kept ("skip") or moved to the trash and replaced ("overwrite"), trashed entries already present are not added twice. Settings are restored only into an empty vault. The import report also counts restored trash entries, attachments and settings.
- A backup can be restored with the password it was made with, also after the master password changed or into another vault.
- **Damaged entries no longer block the vault.** An entry or attachment that fails its integrity check is left out of the listings and reported: a warning with a **Remove** button in the web UI, `ciphermoth damaged [--remove]`, `GET /api/vault/damaged` and `DELETE /api/vault/damaged/{entries|attachments}/{id}` (removes a row only if it really cannot be read). Backups and master password changes wait until damaged rows are removed or a snapshot is restored.

### Changed

- SQLite schema 2 (tables `vault`, `entries`, `attachments`). The schema version and the vault's cryptographic format version are checked separately; a newer one of either is refused at startup without changes.
- Complete backups are limited to **1 GiB** and **1,000,001 frames**, including the envelope; each entry frame is at most **64 MiB**, and each attachment frame at most **5 MiB**. Capacity checks reject supported writes before the vault outgrows its backup capacity.
- The architecture remains SQLite only: two containers and one persistent vault volume, with no PostgreSQL or updater service.
- Backups download as `ciphermoth_backup_<time>.cmbackup`. Large backups are staged as encrypted files; CSV imports and attachment uploads still stay in memory. Backup size bounds follow the backup format instead of the old HTTP upload cap.
- The CLI streams backup downloads and imports. Downloads are written privately to a unique `.partial` file and published only after a complete, flushed transfer, without overwriting an existing backup.
- Removed the misleading per-entry "backed up" indicators. Generating or requesting a download cannot establish that the browser saved it; the UI asks you to check the saved file.
- A failed damage scan now warns that the visible list may be incomplete and retains earlier damage findings. Import reports include restored Trash and settings even when no active entries were present.
- Trash restore and permanent deletion select the exact row clicked, even when multiple trashed entries share a name. The CLI lists row IDs and accepts `password restore/purge <name> --id <row-id>`.
- The import dialog and `ciphermoth import` ask for the **backup password** (the master password at the time of the backup) instead of the current master password.
- A master password change no longer touches entries' `updated` time.
- **Overwriting imports keep the replaced entry.** CSV imports and backup restores with "overwrite" move the existing entry to the trash, with its history and attachments, instead of overwriting it in place.
- The backup import reads its upload only after checking the session (one file, no database transaction while it arrives); the backup writer refuses to produce a file this release could not restore.
- The backend refuses to start when a write-ahead log or journal sits next to a missing or empty vault file, instead of letting SQLite discard it, and never creates a vault over entries that have no key record.
- Backup ZIPs from 2.0 must be encrypted; attachment download names lose every control character.

### Removed

- The bcrypt dependency, the Fernet columns and the format 1 test vectors (`fernet.json`, `key_check.json`, `bcrypt.json`); new frozen vectors are `vault-v2.json` and `backup-v2.json` with `backup-v2.cmbackup`.

## [2.0.0] - 2026-10-15

CipherMoth 2.0 keeps the vault in one SQLite file instead of a PostgreSQL server: two containers and one volume, no database credentials, nothing to set up. It requires a fresh installation: 2.0 does not read, convert or delete a PostgreSQL vault.

### Upgrading

- **This release starts a new, empty vault.** It does not convert the PostgreSQL database of v1.6.0 and earlier, and leaves that database untouched. To bring entries along, make an encrypted backup in the old version and import it into the new vault (active entries only: not the trash, password history, attachments or settings). The steps, and how to go back, are in [docs/UPDATING.md](docs/UPDATING.md#moving-from-a-postgresql-release-v160-and-older).
- **Use the new `docker-compose.prod.yml`.** A backend started from an older compose file stops with a message (exit code 78) instead of creating an empty vault inside its container. `POSTGRES_*` settings in `.env` are no longer used.
- **One-click updates are paused.** The updater was built around PostgreSQL snapshots and is retired. A v1.6.0 app still shows the update, but its updater refuses it ("needs updater protocol 3") before changing anything. From 2.0 on, update by hand: take a snapshot, then pull and restart (the update dialog shows the commands).
- **Encrypted backups (ZIP) are exports, not copies of the vault.** They hold active entries only. A complete copy is a snapshot (`ciphermoth-admin snapshot`).
- **Unchanged:** the encryption, the backup format and the session protocol. Entry names, usernames and descriptions are still stored in plaintext; encrypting them is the next planned format change.

### Added

- `ciphermoth-admin snapshot | check | restore` in the backend image: consistent snapshots of the running vault through SQLite's backup API, integrity checks of the vault or a snapshot, and an offline restore. A restore refuses while anything has the vault open, keeps the vault it replaces byte for byte (WAL included), and leaves a complete vault at every point if it is interrupted. `make prod-snapshot` runs a snapshot.
- The backend checks the vault file before serving: SQLite's quick integrity check, and that the file is a CipherMoth vault of a schema this release understands. A damaged, foreign or newer vault is refused without being changed.
- A request that cannot get the vault's write lock in time gets `503` with `"code": "busy"` and `Retry-After`, instead of an error.

### Changed

- Storage: SQLite (3.51.3 or newer, which fixes the WAL-reset corruption bug; the images ship 3.53) in WAL mode with full sync, foreign keys and `secure_delete`. The vault file is created `0600` in a `0700` folder. Only one backend can serve a vault folder at a time.
- The backend images run uv's managed CPython instead of the Debian Python image, so they carry a current SQLite.
- Write requests are serialized by SQLite's write lock, taken before their first statement; reads see a consistent snapshot and keep working while a write runs. A master password change derives its keys before it takes the lock, so other requests wait only for the re-encryption.
- Requests without a live session are refused before they touch the database.
- Unlocking and the session heartbeat never wait for a running write; backups and imports check the master password before they take the write lock.
- `GET /api/health` no longer reports `maintenance`.
- The security headers are added by a plain ASGI middleware instead of Starlette's `BaseHTTPMiddleware`, whose cancel scope made a cancelled request leak its database connection.
- A data folder the backend cannot write is refused at startup with the owner it found and the `chown` that fixes it.

### Removed

- PostgreSQL, `asyncpg`, Alembic and their configuration, the one-click updater (`ciphermoth-updater` image, `autoupdate` profile, `POST /api/updates/apply`, `GET /api/updates/apply/status`, maintenance mode, the migration gate), `make setup` and `backend/.db.env`.
- The repair of vaults without a key check (created before v1.4.6): every vault now has one from the start, and a key check that does not match a verified master password fails closed.

## [1.6.0] - 2026-10-13

Unlocking with a session is now the only way in: the vault key never leaves the server, for any client. This retires the compatibility path for v1.4.x apps and CLIs that v1.5.0 announced. Your vault, its database and your backups stay exactly as they are.

### Upgrading

- **Update as usual**, by hand or with one click. One-click updates work as in v1.5.1, with the same updater: there is nothing new to install. No database migration runs, and everyone is asked to unlock once, as after any update.
- **Nothing is converted.** The database, the encryption and the backup format are unchanged, and backups made by earlier releases restore as before.
- **Use a CLI from v1.5.0 or newer.** The CLI bundled in the backend image (`./cip`) is always current. A CLI from v1.4.x stops with a message asking you to update, and changes nothing.
- **Browser tabs left open since v1.4.6 or v1.4.7** reload into the current web UI on their next request; unlock again. Tabs from older releases show the refusal instead: reload them by hand.
- **Scripts** that called `POST /api/master_password/check` or sent `x-ciphermoth-key-derivation` must unlock with `POST /api/master_password/unlock` and send the returned token in `x-ciphermoth-session` (deprecated since v1.5.0).
- `CIPHERMOTH_LEGACY_KEY_AUTH` no longer exists. If your `.env` or compose file still sets it, it is ignored; you can delete the line.

### Security

- **Removed the vault key protocol of v1.4.x clients**, as announced in v1.5.0. No route returns the vault key or accepts it as a credential: unlocking with the master password opens a server-side session, and the session token is the only way in. Requests that still send the key in `x-ciphermoth-key-derivation` are refused (403, `"code": "invalid_key"`) on every route, even together with a valid session token, before any route runs and without touching the session. `POST /api/master_password/check` answers 410 (`"code": "upgrade_required"`) without checking the password, so it can no longer be used to obtain the key. Both answers say which client to update.

### Removed

- `POST /api/master_password/check`, the `x-ciphermoth-key-derivation` header, the `legacy-key-auth` feature in `/api/meta`, the `CIPHERMOTH_LEGACY_KEY_AUTH` setting, and the CLI's fallback to the vault key for servers older than v1.5.0. Against such a server, the CLI now stops and asks you to update the server (or use CLI 1.5.x).

## [1.5.1] - 2026-10-13

A reliability release for one-click updates. Nothing changes in your vault or its database.

### Upgrading

- **Update as usual.** One click, or `docker compose -f docker-compose.prod.yml pull && docker compose -f docker-compose.prod.yml up -d`. Nothing changes in the database, and everyone is asked to unlock once, as after any update.
- **If you use one-click updates, update the updater once.** It doesn't replace itself. After the update, the update dialog shows this command; run it once in your CipherMoth folder:

  ```shell
  docker compose -f docker-compose.prod.yml --profile autoupdate pull updater
  docker compose -f docker-compose.prod.yml --profile autoupdate up -d --no-deps updater
  ```

  Until you do, CipherMoth refuses one-click updates instead of risking your vault, and shows you the command again. Future releases that change the database will only install through the new updater.
- If a newer release than 1.5.1 is already out when you read this, the old updater will offer that one instead. Set `CIPHERMOTH_VERSION=1.5.1` in `.env`, run `docker compose -f docker-compose.prod.yml --profile autoupdate pull` and `... --profile autoupdate up -d`, then update with one click. See [docs/UPDATING.md](docs/UPDATING.md).

### Changed

- **One-click updates can now undo a failed database change.** Before applying an update, the updater pauses writes (the API answers 503 for a moment), takes a database snapshot and checks that it restores exactly. If the new version, its database migration or its web UI doesn't come up healthy, it puts that snapshot back and restarts the previous version. Before, it kept going when its backup failed and could only switch the images back.
- **Interrupted updates finish safely.** A crash, `docker stop`, reboot or power cut in the middle of an update is completed or rolled back when the updater starts again. If it ever cannot recover on its own, it keeps the API paused, says so in the app, and [docs/UPDATING.md](docs/UPDATING.md) explains what to do (`updater.sh retry` or a manual restore).
- **Stricter checks.** The updater also verifies the signature of the version it would roll back to, insists that the web UI (not just the backend) runs the new version, keeps its three newest snapshots, and ignores expired, repeated or malformed requests.

### Added

- `GET /api/health` reports the version, whether the database matches the release, and whether an update is in progress. The web UI serves `/version.json`.
- A release that changes the database refuses to migrate while an older updater is installing it, so the first such release cannot be installed by an updater that could not restore your vault. Updating by hand is not blocked, but it has no automatic rollback, so back up first.
- Release images carry an `io.ciphermoth.min-updater-protocol` label, and the updater refuses releases that need a newer updater.

## [1.5.0] - 2026-10-12

### Security

- **The web UI and the CLI no longer receive the vault key.** Unlocking now opens a session on the server: the key stays in the server's memory and the client keeps only a random session token, sent in an `x-ciphermoth-session` header (`Authorization` stays free for a reverse proxy's own login). A token that leaks (for example through a browser extension) stops working when the session ends and never reveals the key; previously a leaked key stayed valid until the master password changed. Until v1.6.0 the server still hands the key to clients that ask for it the old way, so v1.4.x clients keep working (see Deprecated).
- **Sessions end on the server.** The server enforces the inactivity timeout from Settings itself, with 5 seconds of tolerance for request latency, and a 12-hour maximum, so a forgotten tab or a copied token can't keep the vault open. Only real use counts as activity: the web UI reports keyboard, mouse and touch input at most every tenth of the timeout (between 1 and 15 seconds), and checking a session's remaining time, background requests and hidden tabs never extend it. The UI's countdown is taken only from the server's answers (a heartbeat that fails doesn't extend it) and is re-read every 15 seconds while the tab is visible, so it never outlasts the server's, also after another device shortens the timeout. It locks after a suspended laptop wakes up past the deadline, and after a tab was hidden longer than the hidden-tab setting even if the browser froze its timers. An expired session is deleted and cannot be revived, even by raising the timeout. Logging out, auto-lock and closing the session from the CLI end it on the server too. Changing the master password ends every session, including those of other devices, and so does any change of the vault key made outside this server process.
- **The web UI may only connect to its own API.** The frontend image's Content-Security-Policy allowed connections to any host (`connect-src *`). At start-up the image now allows only its own origin, the origin of `CIPHERMOTH_API_URL`, and the GitHub address of the optional update check, which makes it much harder for injected code to send the session token or vault contents elsewhere. It is not a complete barrier: a policy cannot stop navigation to another site or WebRTC, it ignores query strings on the allowed GitHub address, and with an IPv6 API address it can only restrict the scheme. The API URL is checked first: every value that worked before is still accepted (absolute `http(s)` URLs, `//host` URLs and relative paths, with a logged warning for a user name, query or fragment), and an unsafe value (another scheme, or characters that could rewrite the policy or the app) gets a page explaining what to fix instead of the app. Lint rules now reject the HTML and `eval` sinks such code would need.
- **Unlocking no longer stalls the server.** The deliberately slow Argon2id and bcrypt steps run off the request loop, so other requests keep being answered while someone unlocks. Argon2id derivations still run one at a time, which keeps memory at one 64 MiB derivation however many unlocks arrive together.

### Added

- `POST /api/master_password/unlock` returns a session token, `POST /api/master_password/lock` ends one, `GET /api/master_password/session` reports how long it has left without extending it, and `POST /api/master_password/session` records activity. `POST /api/master_password/create` returns a session token instead of the vault key: a v1.4.x browser tab that creates a new vault during the update gets a working vault and asks for the master password once more; scripts that create vaults must read `session_token` (or call the deprecated `/check`). `/api/meta` lists the `vault-sessions` feature, and `legacy-key-auth` while that is accepted.
- `CIPHERMOTH_LEGACY_KEY_AUTH=false` refuses clients that still use the vault key (see below) before v1.6.0 does. Existing installs keep their own `docker-compose.prod.yml`, which does not pass this variable on: add `CIPHERMOTH_LEGACY_KEY_AUTH: ${CIPHERMOTH_LEGACY_KEY_AUTH:-}` to the backend's `environment`, then check that `/api/meta` no longer lists `legacy-key-auth`.

### Changed

- **Everyone is asked to unlock once after updating.** Sessions live only in the server's memory, so restarting or updating the server also locks every open tab and the next request returns to the unlock screen. The backend must keep running a single worker process (the shipped images do).
- **The CLI** opens a session for each command and locks it when the command ends, even on errors. If a session expires while you are still answering prompts, it unlocks again once with the password you already typed. Against servers older than v1.5.0, which have no unlock route, it still uses the vault key, as those releases expect; it never falls back to that because of another error.
- **`CIPHERMOTH_API_URL` is checked when the UI starts.** Any value that worked in v1.4.7 keeps working. A value the check refuses shows a "CipherMoth cannot start" page that names the problem; the backend and your vault are unaffected, and a one-click update still reports success because the updater checks only the backend, so open the UI once after updating. An IPv6 address works, but the policy can then only restrict the scheme, so prefer a host name.
- **Settings:** the inactivity warning must now be shorter than the inactivity timeout on the server too (the UI already required it).

### Deprecated

- **`POST /api/master_password/check` and the `x-ciphermoth-key-derivation` header**, which hand the vault key to clients and accept it back, are kept so that v1.4.x CLIs and browser tabs that were open during the update keep working. They behave exactly as in v1.4.7 (the key must match the vault, under the same locks) and `/check` answers with a `Deprecation` header. **They will be removed in v1.6.0.** Update scripts that call the API directly to use `/unlock` and send the token in `x-ciphermoth-session`.

## [1.4.7] - 2026-10-11

### Fixed

- **Changes are saved before the API answers.** The database transaction was committed only after the response had been sent, so a request made immediately after a change could miss it, and a change whose commit failed was still reported as successful. The commit now happens first, and a failed commit returns an error.
- **Some entry names made an action hit a different entry** ([GHSA-cv6q-x5p4-j9cx](https://github.com/mr-grj/ciphermoth/security/advisories/GHSA-cv6q-x5p4-j9cx)). The API routes on the entry name, so deleting an entry named `x/purge` permanently deleted a trashed entry named `x`, and `ciphermoth password delete "x/attachments/1"` deleted an attachment of `x` while reporting success. Names containing `/` now reach exactly that entry. The web UI and CLI also name the entry in a header, so if a reverse proxy rewrites the address on the way (nginx decodes `%2F` when `proxy_pass` includes a path), the request is refused instead of acting on another entry; see "Pass request paths through unchanged" in CONTRIBUTING.md. Browsers rewrite `.` and `..` in a web address (purging a trashed `.` trashed an entry named `purge`), and `trash` collides with the trash list, so new entries can't use those three names; existing ones still open and can be renamed by editing them, and the web UI refuses to act on `.` or `..` until you do. The CLI sends names with `/` only to servers that route them correctly.
- **Imports can no longer break the vault.** CSV and backup imports skipped the checks the rest of the app applies, so an over-long description, name or URL, an invalid 2FA secret, or a malformed backup entry was stored as is, after which the whole vault list failed to load. A vault already affected by this opens again, and the entry can be fixed by editing it. Every imported row is now checked before anything is written; if any row is invalid nothing is imported and the error names the row and column. CSV rows get the same checks as a new entry. A CipherMoth backup restores exactly what the vault held, including values older imports stored over the usual limits, and refuses only what the vault can't store at all.
- **CSV cells larger than 128 KB** (long notes or passwords) made the import fail with a server error. They now import, and a CSV that can't be parsed gets a clear error with the line number.
- **Concurrent edits no longer lose passwords from the history.** Two edits of the same entry at the same moment each started from the same old value, so one replaced password vanished from the history. Concurrent attachment uploads could also push an entry past the 25 MB and 20-file limits. Edits and uploads to one entry are now applied one at a time.
- **Text the database can't store is refused with a clear message** instead of a server error: a NUL character in an entry name, username or description, or a broken Unicode escape anywhere in a request, including the master password.
- **Proton Pass CSV imports keep the login email** when the username column is empty. Any CSV column now falls back to the next matching column when its cell is blank.
- **CSV imports no longer drop records silently.** Secure notes from Bitwarden and Proton Pass exports were skipped while the import reported success; they now import as secure notes. Rows sharing a name (Chrome exports two accounts for one site that way) collapsed into one entry and were reported as "already exist"; each now imports, the later ones as `name (2)`, `name (3)`. Anything that still can't be imported (cards, identities, aliases, rows without a name or password) is listed with its row and the reason, in the web UI and the CLI.
- **Editing an entry whose name starts or ends with a space changed a different entry** with the trimmed name (such names can come from older imports). Edits now match the entry's name exactly.
- **Restoring or renaming onto a name that was just taken** returns a clear error instead of a server error.

### Security

- **Validation errors no longer echo what you sent.** A rejected master password (for example, too weak) or entry value was returned verbatim in the error response. Errors now name only the field and the problem.
- **Dependencies:** cryptography 50.0.0, anyio 4.14.2, Mako 1.4.2, axios 1.20.0 and react-router 7.18.4 clear every open advisory; none of the affected code paths were used by CipherMoth. The frontend image's file server is now pinned with a lockfile, which also updates `compression` to 1.8.2 (a denial-of-service fix that did apply to the UI port).

### Changed

- **Descriptions can be up to 10,000 characters** (was 1,024), so notes from Bitwarden or KeePass exports import instead of failing.
- **Backups and imports are checked against frozen test data from every release.** Vaults and backups created by v1.0.0 to v1.4.6, and vault databases from Dinopass v0.3.0, are proven to open, upgrade, decrypt and restore. Backups from v0.3.0 (`dinopass_backup.json`) are not importable. See [testdata/golden](testdata/golden/README.md).
- The backend now declares Python `>=3.13,<3.15`.

## [1.4.6] - 2026-10-10

### Security

- **Every vault route now checks that the key it receives is the vault's real key.** Until now the API only checked that a key was *present*, so a client that could reach the API could favorite, trash, restore or permanently delete entries, delete attachments, read and change settings and request an update without knowing the master password, could write entries encrypted with a key the vault can't read (which then broke the whole vault listing), and could learn entry names from error messages. Encrypted values (passwords, notes, 2FA secrets, attachments) were not returned without the real key in our testing. The vault now stores a small encrypted check value and every protected request must decrypt it. Existing vaults pick it up the first time you unlock after upgrading; until then, protected requests are refused, so an open browser tab from before the upgrade returns you to the unlock screen once. No data is re-encrypted and the vault format is unchanged.
- **A key stops working the moment the master password changes.** A browser tab or CLI session still holding the old key is refused instead of writing entries the new key can't read, and a change waits for writes already in progress so they get re-encrypted too.
- **Two vaults can no longer be created at the same time.** Simultaneous first-run requests could each create a master password; only one now succeeds.
- **Uploads stay in memory.** Attachments, CSV files and backup ZIPs larger than 1 MB were buffered to a temporary file before being encrypted. Request bodies are now capped per route (6 MB for attachments, 11 MB for imports, 16 MB for everything else) and parsed entirely in memory. Every file the old limits accepted (5 MB attachments, 10 MB imports) is still accepted, with the same error messages just above those limits.
- **Update requests must name a newer release.** The backend and the updater sidecar both refuse a target that is not strictly newer than the running version, before pulling anything. Signature verification is unchanged.
- **Logs no longer contain entry names.** Error logs name the failing endpoint and code location instead of the request URL and error message (which could include entry names or database parameters), and access log lines show `/api/passwords/{password_name}` instead of the name, with query strings removed.
- **The UI and API are published on `127.0.0.1` by default** in `docker-compose.prod.yml`. Set `CIPHERMOTH_BIND_ADDRESS=0.0.0.0` in your `.env` to reach them from other machines. This only applies once you use the new compose file; the one-click updater does not replace it.
- **The docs now describe what is and isn't encrypted.** Entry names, usernames and descriptions are stored in plaintext, the server holds the vault key in memory while you use it, and backup ZIPs use a much weaker key derivation than the vault. The README, `SECURITY.md` and the CLI docs previously overstated this.

### Upgrading

- **No database migration.** v1.4.6 adds one nullable column when it starts and leaves the schema revision as it was, so going back to v1.4.5, by hand or through the one-click updater's automatic rollback, keeps working. If you change the master password while on v1.4.5 and then upgrade again, every open session has to unlock once more.
- **The one-click updater does not update itself.** It restarts only the backend and frontend, so the updater container keeps the version it was started with. To get v1.4.6's updater (which also refuses older targets), run `make prod-up-autoupdate`, or `docker compose -f docker-compose.prod.yml --profile autoupdate up -d`, after upgrading.

### Fixed

- **`ciphermoth password delete` can remove an entry that no longer decrypts.** It checked that the entry existed by reading it first, so an entry written with a different key (the damage the first issue above allowed) could never be moved to the trash from the CLI. It now only stops when the entry doesn't exist. If an entry like that breaks your vault listing, `cip password delete <name> --yes` followed by `cip password purge <name> --yes` removes it; the error message names the entry.

### Changed

- **`GET`/`PATCH /api/settings` and `PATCH /api/master_password/update` require an unlocked vault** like every other vault route. The web UI and CLI already sent the key.
- **`backend/.db.env` is no longer tracked by git.** Pulling this change removes the file from your checkout. If you already have a dev database volume, restore the matching file with `git show v1.4.5:backend/.db.env > backend/.db.env`; otherwise `make setup` creates a fresh one. The old development password is in the history, so don't reuse it for anything else.

## [1.4.5] - 2026-07-26

### Added

- **`cip`, a one-word CLI for Docker installs.** If you set CipherMoth up with `install.sh` you never cloned the repo, so the `ciphermoth` command was out of reach entirely. The CLI now ships inside the backend image, and `install.sh` leaves a small `cip` script next to your compose file: `./cip password list`, no Python and no clone. Link it onto your PATH (`sudo ln -s ~/ciphermoth/cip /usr/local/bin/cip`) and it works from anywhere. It finds your install folder through symlinks, and tells you how to start the stack if it isn't running.
- **`ciphermoth password create --kind note`** creates a secure note from the terminal. Notes were previously web-only; the CLI now skips the login-specific prompts (username, URL, 2FA) and asks for the note body instead. `password update` does the same when editing a note.
- **Help text on every command.** `ciphermoth --help` and `ciphermoth password --help` listed each command with a blank description. Every command, argument, and option now explains itself.

### Security

- **The CLI addressed the wrong entry for names containing `#`, `?`, or `../`.** Entry names went into the request URL unencoded, so `password delete "notes#2024"` truncated at the `#` and trashed a different entry named `notes` while reporting success. `?` injected a query string and `../` escaped the `/passwords/` namespace onto unrelated endpoints. Names are now percent-encoded, so every command acts on exactly the entry you named or fails cleanly. This mattered most for `delete` and `purge`, where the wrong target means losing a secret you didn't mean to touch.
- **A warning before your master password crosses the network in the clear.** If `CIPHERMOTH_API_URL` points at a remote host over plain `http://`, the CLI now says so before prompting. Local use is unaffected and stays silent.
- **Backups written by `ciphermoth backup` are now `0600`** (owner-only) instead of world-readable, on top of the AES-256 encryption they already had.
- **Redirects are explicitly never followed**, so the key-derivation header and master password can't be replayed to a host chosen by whatever the API pointed at.

### Fixed

- **`ciphermoth password get` no longer crashes on passwords containing square brackets.** A value like `P[bold]ass` was parsed as terminal-formatting markup and blew up with a Python traceback instead of printing the password. Every value the CLI prints (passwords, notes, usernames, descriptions, custom fields, entry names) is now escaped, so you see exactly what you stored.
- **`ciphermoth password update` no longer forces a password change.** The value prompt now accepts a blank line to keep the current one, so you can correct a URL or a description without retyping the password. Typing a new value still asks you to repeat it, and a mismatch aborts.
- **Readable message when you hit a rate limit.** The API answered with a raw `{"error": "Rate limit exceeded: 10 per 1 hour"}` blob that the CLI printed verbatim and the web UI couldn't read at all, falling back to a generic "An error occurred". Both now get a plain sentence, and the CLI adds a hint about `CIPHERMOTH_RATE_LIMIT`.
- **Aligned, readable `password get` output.** Custom fields were printed in their own ragged column instead of lining up with the built-in labels, and multi-line secure notes ran back to the left margin after the first line. Everything now shares one column, sized to the longest label.

### Changed

- **Unlocking is limited to 30 attempts an hour instead of 10.** Every CLI command unlocks the vault once, so ten commands in an hour locked you out of the web UI too. Thirty guesses an hour is still hopeless against the enforced 12-character minimum, and `CIPHERMOTH_RATE_LIMIT` now reaches the production stack through `.env` if you want a different number.

## [1.4.4] - 2026-07-23

### Fixed

- **One-click update really finishes on its own now.** The update dialog could sit on "Working..." until you refreshed by hand, even though the update itself succeeded. Root cause: the updater wrote its progress file as `root` with `0600` permissions, so the non-root backend got "permission denied" reading it and reported `idle` - the dialog never saw the terminal state. Two fixes: the updater now writes that file world-readable (`0644`), and the dialog no longer depends on it at all - it watches the running version via `/api/meta` and reloads the moment the new version is live, so it recovers cleanly even across the backend restart or a stale status file.

## [1.4.3] - 2026-07-23

### Added

- **Light and dark themes.** The whole app now flips between a dark canvas (the black-and-glow look from the login screen) and a light one, and remembers your choice. Switch it with the little moth resting in the bottom-right corner: click it and it flutters off as the theme fades across the page. Buttons, forms, links, tags, toasts, the vault grid, and the health and update dialogs all follow along, and disabled buttons stay clearly visible on the dark surface.

## [1.4.2] - 2026-07-23

### Fixed

- **The one-click update dialog no longer gets stuck on "Working...".** After the update applied, the modal could sit on a loading spinner until you refreshed the page manually, because a status request that hung while the stack restarted froze the progress check. The dialog now polls resiliently (with a request timeout) and reloads on its own once the new version is live, and it shows real progress ("Verifying...", "Applying...") instead of a generic spinner.

## [1.4.1] - 2026-07-23

### Fixed

- **Clearer form errors.** When the server rejects an entry (an invalid 2FA secret, an over-long field, or too many tags or custom fields), the add/edit dialog now shows the actual reason instead of a stray "[object Object]". The name field is also capped at 255 characters as you type, so you can't overshoot the limit by accident.

## [1.4.0] - 2026-07-22

### Added

- **File attachments.** Attach files to any vault entry - recovery-code PDFs, license keys, SSH key files, anything up to 5 MB each (25 MB total per entry). Open an entry and use the **Attachments** section to upload, download, or remove files; the vault grid shows a paperclip with a count for entries that have them. Filenames (including non-ASCII names like `Preț.pdf`) and contents are Fernet-encrypted with your vault key exactly like passwords, re-encrypted on master-password change, and cascade-deleted when you permanently delete an entry - so the database never leaks what you've stored.
- **Secure notes.** Store free-form encrypted text (recovery codes, Wi-Fi credentials, passport details, anything) as a first-class item alongside logins. Pick "Secure note" when adding an entry and the form adapts to a single large note field; notes are encrypted at rest like everything else, preserve your exact text (leading/trailing whitespace and blank lines included), can carry folders, tags, and custom fields, and are skipped by password-specific features (2FA, strength, and the Vault Health report).
- **Folders.** Organise entries into folders. Add or pick a folder when creating or editing a password, filter the vault to a single folder from the toolbar, and see each entry's folder at a glance in its own column. The folder name is encrypted at rest like every other detail, included in backups, mapped from a folder/grouping/category column on CSV import, and searchable. `ciphermoth password create`/`update` now prompt for a folder too.
- **Custom fields per entry.** Each password can now carry arbitrary labelled fields (a PIN, a recovery code, a security-question answer…). Mark a field **hidden** to keep its value masked in views, like a password. Custom fields are encrypted at rest with the same vault key as everything else, included in backups, and searchable by label (and by value when not hidden). Up to 30 per entry.
- **Trash (soft-delete + restore).** Deleting a vault entry now moves it to a **Trash** instead of erasing it. A new Trash dialog lets you **restore** an entry or **delete it forever**. Trashed entries are excluded from the vault list, search, backups, imports, and vault-health - they simply wait until you restore or purge them, and a name freed by trashing can be reused right away. New CLI commands: `ciphermoth password trash`, `ciphermoth password restore <name>`, and `ciphermoth password purge <name>` (`password delete` now moves to trash).

### Changed

- **Redesigned Vault Health.** The health report now leads with a circular score gauge and a plain-language status (Healthy / Needs attention / At risk), a row of weak/reused/old stat tiles, and clearer issue cards you can tap to jump straight to the entry. Still computed entirely on your device.
- **Cleaner Add/Edit password modal.** The form now keeps your core credentials (name, username, website, password) front and centre, and tucks the extras (two-factor, tags, custom fields, notes, history) into tidy collapsible sections. Sections open automatically when an entry already has that content and stay collapsed when empty, so adding a password is uncluttered and editing never hides anything.

### Fixed

- **No more stray highlight on toolbar buttons.** Closing a dialog with Escape used to leave a dark pulsing blob on the button that opened it (a stuck focus ripple). Ripples are now off in favour of a crisp focus outline, so keyboard focus stays clearly visible without the artifact.
- **Release builds can't hang indefinitely.** Added a 30-minute timeout to the image-publish job so a stalled multi-arch build fails fast instead of hanging for hours and risking a partial release (e.g. backend published but frontend not).

## [1.3.1] - 2026-07-11

### Fixed

- **Reinstalling no longer locks you out.** Deleting the install folder and re-running `install.sh` used to generate a new database password while the old Postgres volume survived, causing `password authentication failed` on unlock. The installer now detects an existing `ciphermoth_postgres_data` volume without an `.env` and stops (or offers to wipe for a fresh start) instead of silently breaking the vault.

## [1.3.0] - 2026-07-11

### Fixed

- **One-click updates now find the images.** Release tags are `vX.Y.Z` but the published image tags are `X.Y.Z` (no leading `v`), so the updater was pulling a non-existent `:vX.Y.Z` and failing with "manifest unknown". It now maps the release tag to the image tag. Pinning `CIPHERMOTH_VERSION` also uses the un-prefixed form (e.g. `1.2.0`).
- **The "Update" chip no longer disappears on hover** (its hover background was overriding the glow with a dark colour, hiding the near-black label).

## [1.2.0] - 2026-07-11

## [1.1.0] - 2026-07-11

### Added

- **Update notifications.** CipherMoth now tells you when a newer release exists. The check runs entirely in your **browser** against GitHub's public API - the server never phones home - and can be switched off in Settings ("Check for updates") to keep an instance fully third-party-free.
- **One-click updates (opt-in).** An optional `updater` sidecar lets you upgrade from the in-app "Update" button: it pulls the new images, restarts, and runs migrations for you. It's **off by default**; enable it with `make prod-up-autoupdate` (or `docker compose -f docker-compose.prod.yml --profile autoupdate up -d`). Without it, the app still notifies you and shows the exact command to run.

### Security

- **Release images are now signed with cosign** (keyless / Sigstore, via GitHub OIDC). Every published `ciphermoth-{backend,frontend,updater}` image is signed by digest.
- **The self-updater verifies signatures before applying.** It pulls the target images, checks each digest was signed by the official release workflow's identity, and **refuses to run anything that fails verification** - so a compromised registry alone can't push a malicious build to your vault. It also snapshots the database before migrating and **auto-rolls-back** if the new version fails its health check. The privileged (Docker-socket) container has **no network listener**; it's driven only by a file the backend drops after an unlocked-vault, rate-limited request.

## [1.0.0] - 2026-07-11

### Changed

- **Renamed the project to CipherMoth** ("Your secrets stay in the dark."). Everything the app does is unchanged; this is a full rebrand of the name, UI theme, CLI (`ciphermoth`), Docker Compose projects, and GHCR images (`ghcr.io/mr-grj/ciphermoth-{backend,frontend}`). The per-request key header is now `x-ciphermoth-key-derivation` and backup archives contain `ciphermoth_backup.json`, so a backup taken before the rename must be restored before upgrading (or just re-export after).
- **New black-and-glow UI theme.** A minimal dark palette with a teal "glow" accent (`#7dd3c0`) and a moth mark replaces the old black-and-white dino look. Fonts are Space Grotesk + Space Mono, self-hosted (no Google Fonts CDN, in keeping with "talks to nobody"). Login, setup, and the initial unlock are now full-screen dark screens.
- **Simplified to one local stack + prebuilt prod.** Local development now runs a single build-from-source, hot-reload stack on `:3000`/`:8000` (`make dev`); the real vault runs from prebuilt GHCR images via `docker-compose.prod.yml` (`make prod-up`). The separate `:3100`/`:8100` dev stack and the build-from-source `make buildup` path are gone.

## [0.3.0] - 2026-07-10

### Added

- **Website, two-factor, tags and favorites per entry.** Each password can now carry a website, a TOTP secret, tags, and a favorite flag. All of them (except the favorite flag) are encrypted at rest with the same vault key, so the database still only ever holds ciphertext.
- **Built-in two-factor codes.** Paste a base32 secret or an `otpauth://` link and Dinopass shows the live rolling code, computed in your browser (and in the CLI via `password get`).
- **Password history.** When you change a password, the previous value is kept (encrypted, last 10) and can be revealed or copied from the edit dialog.
- **Vault health check.** A local, offline report that flags weak, reused, and stale passwords. It never sends anything anywhere.
- **CSV import from other managers.** Import a plain CSV exported from Chrome, Bitwarden, KeePass, Proton Pass and similar, from the web UI or `dinopass import-csv`. Columns are matched automatically.
- **`make setup`** generates `backend/.db.env` with a strong random database password so first-time setup is one command.
- **Separate personal and development stacks.** `make buildup` (your real vault) and `make dev` now run as distinct Docker Compose projects, each with its own database volume, network, and ports (dev on `3100`/`8100`), so you can run both at once and a dev sandbox can never see or clobber your real vault. `make clean` only ever wipes the dev database; tearing down the real vault is a separate, confirmation-guarded `make clean-prod`. New `make down`/`make dev-down` stop a stack without wiping its data.
- **Environment badge in the app bar.** The dev stack shows a loud amber **DEV** chip (plus an amber accent line); your real vault shows a calm **LIVE** chip. It's derived from the build itself (Vite dev server vs `vite build`), so there's nothing to configure - and it makes it hard to ever mistake the sandbox for the real thing.
- **Prebuilt images + a pull-and-run compose.** Release images are published to GHCR (`ghcr.io/mr-grj/dinopass-backend` and `-frontend`, multi-arch amd64/arm64) whenever a `v*.*.*` tag is pushed. A new `docker-compose.prod.yml` + `.env.prod.example` let you run Dinopass without cloning or building - grab the two files, set a database password, `docker compose -f docker-compose.prod.yml up -d`. The frontend image takes its API URL at container start, so one image works for any host.

### Security

- **Master password strength is now enforced on the server** (at least 12 characters and two character classes) when creating a vault or changing the master password, not just in the browser.

- **Full master password is now authenticated.** bcrypt truncates at 72 bytes, so a very long master password used to only be checked by its first 72 bytes. It's now pre-hashed with SHA-256 before bcrypt so the whole thing counts. This changes the stored hash format and is not backward compatible, so a vault created before this change needs to be set up again.
- **Rate-limited the master password change endpoint.** It verifies the current master password, so leaving it unlimited was a brute-force gap that bypassed the cap on the login check. It's now capped at 10/hour like the check endpoint.
- **Import rejects oversized uploads before reading them** into memory, and the reverse-proxy rate-limiting caveat is now documented in the README.

### Docs

- **README rework, with screenshots.** Added screenshots of the vault, the add/generate flow, the health report, and first-run setup; a "who it's for (and who it isn't)"; a "security status" note that says plainly it hasn't been independently audited; a threat model; and a clearer split between running Dinopass for real vs. developing on it. The full CLI reference moved into [`docs/CLI.md`](docs/CLI.md).

### Internal

- **Backend refactor** - moved exception translation to app-level handlers (endpoints no longer carry `@handle_*` decorator stacks), extracted the per-request key derivation into a FastAPI dependency so the CRUD layer only sees a plain string, simplified the dependency wiring with `Annotated` providers, and fixed the import path's N+1 lookups. No change to the API contract.
- **Fixed long-standing inconsistencies** - the CLI now sends the `username` field on create/update, the API version reads from package metadata instead of a hardcoded string, and the settings defaults live in one place.
- **Frontend refactor** - broke the 1,100-line `PasswordsPage` into a thin container plus focused pieces under `components/vault/` (form, generator, backup, import, empty state, column defs), extracted the secure generator and strength scoring into `src/lib/`, and added a shared `PasswordField` and `useClipboard` hook. No behavior or UI changes - just cleaner, DRYer, easier to follow.
- **Unified password-strength logic** - the vault (5-level) and login (4-level) scales now share one module (`src/lib/passwordStrength.js`) instead of two divergent copies.
- **ESLint 9** - added a flat-config ESLint setup (react-hooks + react-refresh) wired into `make lint`/`make check` and CI. `npm run lint` is clean; the frontend still installs with 0 vulnerabilities.

## [0.2.0] - 2026-03-15

First public release. I've been using this daily for a while and it hasn't eaten any passwords, so here we are.

### What's in it

- **Vault UI** - create, edit, delete, and search passwords from a single page. Search works across name, username, and description so you don't have to remember exactly what you called something
- **Username / email field** - because some sites want a username, some want an email, and some want both for reasons nobody has ever explained
- **Password generator** - configurable length (8-64) and character sets; uses `crypto.getRandomValues` with rejection sampling so the randomness is actually random, not "looks random enough"
- **Password strength indicator** - shows up in the form as you type and as an icon in the vault table, so you can feel appropriately judged by your old passwords
- **Encrypted backup** - exports everything as an AES-256 ZIP protected by your master password. Keep it somewhere safe
- **Backup import** - restore from a backup ZIP with skip or overwrite for conflicts
- **CLI** (`dinopass`) - full vault access from the terminal for when you can't be bothered to open a browser
- **Inactivity lock** - session clears itself after you've walked away; configurable how long it waits
- **Clipboard auto-clear** - copied passwords are wiped from the clipboard after a timeout, because paste history is a thing that exists
- **Settings page** - all the timeouts and delays are configurable from the UI, not hardcoded
- **Rate limiting** - all API routes are rate-limited so someone can't just hammer the login endpoint forever

### Security foundations

- Master password hashed with **bcrypt** - not stored, not reversible
- Passwords encrypted with **Fernet** (AES-128-CBC + HMAC-SHA256) using keys derived via **Argon2id** (64 MiB, 3 iterations, 4 lanes)
- Derived key lives only in `sessionStorage` for the duration of the session - the server never sees it
- Password generator uses `crypto.getRandomValues` with rejection sampling to eliminate modulo bias - the kind of detail that doesn't matter until it does
