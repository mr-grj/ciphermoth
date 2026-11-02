# CipherMoth vault format 2 and backup format 2

This is the specification of how CipherMoth stores a vault on disk (vault format 2, SQLite schema 2) and how it writes a complete encrypted backup (backup format 2, `.cmbackup`). It is written for reviewers and for anyone implementing a second reader (the planned desktop core runs this same Python code; a future JavaScript, Rust or mobile core would implement this document against `testdata/vectors/vault-v2.json` and `backup-v2.json`).

The reference implementation is `backend/helpers.py` (every primitive and every associated-data construction), `backend/crud/master_password.py` (unlock and rotation), `backend/crud/password.py` and `backend/crud/attachment.py` (records), `backend/crud/backup.py` (backups) and `backend/storage.py` (file identity).

Format 2 replaced format 1 (CipherMoth 2.0.x and earlier, Fernet columns, plaintext names, a bcrypt verifier) without a conversion: see "Compatibility" at the end.

## 1. Threat model

**Protected against (the vault file, a snapshot, a backup or a copy of any of them in the wrong hands, without the master password):**

- Reading any entry content: names, usernames, descriptions, passwords and note bodies, URLs, 2FA secrets, tags, folders, custom fields, password history, favorites, the login/note type, attachment names, types and bytes.
- Guessing the master password faster than one Argon2id evaluation (64 MiB, 3 passes) per guess. There is no second, cheaper verifier: format 1's bcrypt hash is gone.
- Linking entries across master password changes: a change replaces every key, so name-index values and ciphertexts change completely.

**Detected (someone who can write the file but does not know the master password):**

- Altering any ciphertext, nonce or tag: authenticated decryption fails, the request stops with "the vault file is damaged", nothing is shown or overwritten.
- Moving a ciphertext to another entry, attachment or role (an entry document into another row, attachment bytes onto another entry, an attachment's name into its content): every ciphertext is bound by its associated data to the random id of its own row (and an attachment also to its entry's id) and to its role.
- Changing an entry's name index so that a lookup lands on another entry: every read recomputes the index from the decrypted name and refuses a mismatch.
- Changing the stored KDF parameters, salt or format version: they are associated data of the wrapped vault key, and the password commitment depends on them.
- Planting a crafted wrapped key that decrypts under many candidate passwords (an AES-GCM "partitioning oracle"): unlock checks a password commitment before decrypting anything, so each unlock tests exactly one password.

**Not detected (documented limits):**

- **Rollback.** Replacing the whole file with an older copy, or one row with an older version of the same row, or one attachment with an older version of itself, looks valid. Detecting this needs a counter kept outside the file (the desktop app could keep one in the OS keychain later).
- **Deletion.** Removing rows (entries, attachments, history inside a rolled-back document) is not detected.
- **Plaintext columns.** The columns listed in section 4 are not authenticated: someone with write access can mark an entry as trashed or restore it from the trash, flip `backed_up`, change timestamps, or change the settings row (for example a longer inactivity timeout or a disabled clipboard wipe).

**Out of scope, as before:** an attacker who can read the server process's memory or run code as its user, a malicious client that holds a valid session (it can do anything the user can), a compromised browser or renderer, keyloggers. Python cannot erase keys from memory. Old plaintext or old-key ciphertext left in free pages, a WAL file, SSD blocks, filesystem snapshots or backups made before a change is not reachable by CipherMoth (see section 7).

## 2. Primitives

All from `cryptography` (OpenSSL), nothing hand-written:

| Use | Primitive |
|---|---|
| Password to key | Argon2id, version 0x13, no secret, no associated data, 32-byte output |
| Key separation | HKDF-SHA256 (RFC 5869), no salt, one fixed `info` label per key |
| Encryption | AES-256-GCM, random 96-bit nonce, 128-bit tag |
| Name index | HMAC-SHA256 |
| Comparisons | `hmac.compare_digest` |
| Randomness | `os.urandom` |

Default KDF parameters (OWASP 2024 interactive profile, unchanged from format 1): memory 65536 KiB, 3 iterations, 4 lanes, 16-byte random salt. The parameters are stored with the vault and with every backup, so they can be raised later without a format change. A reader accepts memory 19456 to 262144 KiB, 1 to 10 iterations and 1 to 8 lanes and refuses anything else before running the KDF, so a hostile file cannot make it allocate gigabytes.

**Master password input.** Leading and trailing Unicode `White_Space` is stripped (the API's `str_strip_whitespace`), then UTF-8. No Unicode normalization. Unchanged from format 1 (`testdata/vectors/argon2id.json`).

**Nonce budget.** Random 96-bit nonces under one key are safe for 2^32 encryptions. One vault key encrypts one document per entry write and two per attachment; a master password change replaces the key. A vault would need billions of edits under one password to approach the bound.

## 3. Key hierarchy

```
master password ──Argon2id(salt, params)──▶ D (32 bytes, never stored)
   D ──HKDF "ciphermoth/v2/password-commitment"──▶ password_check   (stored)
   D ──HKDF "ciphermoth/v2/key-wrapping"────────▶ KEK               (never stored)

vault key VK (32 random bytes, never stored in clear)
   wrapped_key = 0x02 ‖ nonce ‖ AES-256-GCM(KEK, nonce, VK, AD_wrap)   (stored)
   VK ──HKDF "ciphermoth/v2/record-encryption"──▶ K_rec   (entries and attachments)
   VK ──HKDF "ciphermoth/v2/name-index"─────────▶ K_idx   (name index)
   VK ──HKDF "ciphermoth/v2/key-check"──────────▶ key_check (stored)
```

`AD_wrap` = `"ciphermoth/v2/wrapped-vault-key"` ‖ u16 format version ‖ u32 memory KiB ‖ u32 iterations ‖ u32 lanes ‖ salt (all integers big-endian).

**Create.** Random salt and VK, derive D, store the singleton `vault` row (format version, KDF parameters, salt, `password_check`, `wrapped_key`, `key_check`) in one transaction. Until that row exists the vault is "not set up".

**Unlock.** Read the row and end the transaction, run Argon2id, compare `password_check` in constant time: a mismatch is a wrong password and nothing else happens (unlock is a read transaction; nothing is written). Then decrypt `wrapped_key` and compare `key_check`: either failing after a matching commitment means the row is damaged (400, logged, no session). Then the row is read again in a new transaction and a session is opened only if `key_check` is unchanged (a master password change that committed meanwhile wins).

**Sessions.** The server keeps VK (with its derived keys) in memory behind an opaque session token, exactly as in format 1 (Phase 2): clients, including the web UI and the future desktop renderer, only ever hold the token. Every vault request compares the session key's `key_check` with the stored one inside its transaction, so a key that another process replaced ends the session at first use.

**Master password change** (always a full re-key): verify the current password as in unlock, generate a new salt and a new random VK, derive and wrap, then in one write transaction confirm the row is unchanged, decrypt every entry document and attachment with the old keys, re-encrypt them with the new keys (new nonces), recompute every name index, and replace the row. Every session ends after the commit. Afterwards the old password unlocks nothing and the old VK decrypts nothing in the live file. Re-wrapping VK without re-encrypting for a KDF parameter upgrade is supported by the layout but not exposed yet.

**Biometric unlock** (optional, outside the vault file). `device-unlock.json` in the data folder, mode `0600`, holds one record per enrolled device: `credential_id`, `kind` (`passkey` or `secure-enclave`), `material` (what the authenticator needs to reproduce its secret) and `wrapped_key`, plus `last_password_at` and `password_interval_days`. Binary values are unpadded base64url.

```
secret S = 32 bytes from the authenticator, never stored
   passkey:         WebAuthn PRF output for salt = material (random 32 bytes), user verification required
   secure-enclave:  HKDF-SHA256(ECDH(Secure Enclave P-256 key, peer public key), salt = empty,
                    info = "ciphermoth/v2/secure-enclave-secret"), material = peer public key (65 bytes) ‖ key blob
K_device = HKDF(S, "ciphermoth/v2/device-unlock")
wrapped_key = 0x02 ‖ nonce ‖ AES-256-GCM(K_device, nonce, VK, AD_device)
AD_device = 0x02 ‖ "ciphermoth/v2" ‖ u32 length ‖ "device-unlock" ‖ u32 length ‖ credential_id
```

Enrolling verifies the master password as in unlock, since only that yields the raw VK. Unlocking refuses first if the password reminder is due (now − `last_password_at` ≥ the interval, or the clock moved back more than 5 minutes), then decrypts `wrapped_key` and compares the derived `key_check` with the vault's: a mismatch after a successful decryption means the record belongs to a replaced vault key and it is removed. A master password change deletes the file after its commit, and a new vault deletes a stale one. The file is not part of the vault format or schema version: a release without this feature ignores it, and a malformed file is ignored with a log line, leaving the master password as the way in.

**Why a separate commitment and not only GCM?** AES-GCM is not key-committing: one ciphertext can be built to decrypt under many keys. Unlock compares `password_check` first, so whatever is planted in `wrapped_key`, each unlock tests one password. The commitment costs an attacker exactly what testing the wrapped key would: one Argon2id per guess.

## 4. SQLite layout (schema 2)

`PRAGMA application_id` = `0x434D5448` ("CMTH"), `PRAGMA user_version` = 2. The SQLite settings (WAL, `synchronous=FULL`, `secure_delete=ON`, `foreign_keys=ON`, ...) are unchanged from schema 1 and listed in `CLAUDE.md`.

**`vault`** (at most one row, `id = 1`): `format_version` (2), `kdf` (`argon2id`), `kdf_memory_kib`, `kdf_iterations`, `kdf_lanes`, `kdf_salt` (16 bytes), `password_check` (32), `wrapped_key` (61), `key_check` (32), `created`, `updated`.

**`entries`**: `id` (integer, autoincrement, never reused), `uid` (16 random bytes, unique), `name_index` (32 bytes), `document` (sealed entry document), `backed_up`, `created`, `updated`, `deleted`. A partial unique index on `name_index WHERE deleted IS NULL` keeps active names unique; trashed entries may share a name with each other and with an active entry.

**`attachments`**: `id` (integer, autoincrement), `uid` (16 random bytes, unique), `entry_id` (foreign key, `ON DELETE CASCADE`), `size_bytes`, `meta` (sealed name and type), `content` (sealed bytes), `created`.

**`settings`**: the timing settings and the update-check switch, in clear.

**Sealed value** = `0x02` ‖ nonce (12) ‖ AES-256-GCM(K_rec, nonce, plaintext, AD) (ciphertext ‖ 16-byte tag).

**Associated data** = `0x02` ‖ `"ciphermoth/v2"` ‖ for each part: u32 length ‖ bytes:

| Value | Parts |
|---|---|
| Entry document | `"entry"`, entry `uid` |
| Attachment metadata | `"attachment-metadata"`, attachment `uid`, entry `uid` |
| Attachment content | `"attachment-content"`, attachment `uid`, entry `uid` |

**Entry document**: UTF-8 JSON object with exactly these keys, padded with trailing spaces to a multiple of 64 bytes before sealing (hides exact lengths):

```json
{"name": "...", "kind": "login|note", "username": null, "value": "...", "url": null,
 "totp_secret": null, "description": null, "tags": [], "custom_fields": [{"label": "", "value": "", "hidden": false}],
 "folder": null, "favorite": false, "history": [{"value": "...", "changed_at": "ISO-8601"}]}
```

A note keeps its body in `value`. Readers refuse unknown or missing keys and wrong types.

**Attachment metadata**: `{"filename": "...", "content_type": null}`, padded the same way. **Attachment content**: the raw bytes, not padded; a reader refuses content whose length differs from `size_bytes`.

**Name index** = HMAC-SHA256(K_idx, UTF-8 name), the exact name (no case folding or normalization, like the API). The API keeps addressing entries by name: a lookup computes the index and selects `name_index = ? AND deleted IS NULL`, then checks that the decrypted name is the requested one.

**Residual plaintext** (what the file still shows without the master password):

- That it is a CipherMoth vault, its schema and format version, the KDF parameters and salt.
- The number of entries and attachments, which entries are in the trash, and which attachments belong to which entry.
- Row ids (creation order), `created`, `updated` and `deleted` timestamps, the `backed_up` flag.
- Which entries share a name (equal `name_index`), in practice an entry and its trashed copies; nothing else about names. Values change completely after a master password change.
- Each entry document's length rounded up to 64 bytes, each attachment's exact size.
- The settings row (timeouts in milliseconds, update check on or off).
- When the master password last changed (the `vault` row's `updated` time) and how many entries and attachments were ever created, purged ones included (SQLite's id counter).
- Across two copies of the file (two snapshots, or a snapshot and the live vault): which entries changed, were renamed (their name index changed) or were trashed in between.

This is field-level encryption inside an ordinary SQLite file, not whole-file encryption: table names, the schema and the items above are visible to anyone who opens the file.

## 5. Backup format 2 (`.cmbackup`)

A backup is the portable, password-protected export of everything in a vault: active and trashed entries with every field, history, favorite and timestamps, attachments byte for byte, and the settings. It is not a copy of the vault file; `ciphermoth-admin snapshot` makes those (raw, local, tied to the vault's own keys) and serves another purpose.

```
header (75 bytes)
  magic        8   "CMBACKUP"
  version      2   u16 = 2
  kdf          1   u8 = 1 (Argon2id v1.3)
  memory_kib   4   u32
  iterations   4   u32
  lanes        4   u32
  salt        16
  frames       4   u32, at least 1
  commitment  32   HKDF(B, "ciphermoth/backup/v2/key-commitment")
frame × frames (nothing may follow the last one)
  length       4   u32, ciphertext length including the tag
  nonce       12
  ciphertext  length   AES-256-GCM(K_frame, nonce, plaintext, header ‖ u32 index ‖ u8 last)
```

`B` = Argon2id(password, salt, parameters), `K_frame` = HKDF(B, `"ciphermoth/backup/v2/frame-encryption"`). The password is the vault's master password at the time of the backup (verified before the backup is written); the salt is new for every backup, independent of the vault's. `last` is 1 for the final frame and 0 otherwise.

Frame 0 is a small UTF-8 JSON envelope (at most 64 MiB):

```json
{"format": "ciphermoth-backup", "version": 2, "exported_at": "ISO-8601", "app_version": "x.y.z", "entries_count": 2,
 "settings": {"inactivity_ms": 120000, "warn_before_ms": 60000, "hidden_ms": 60000, "debounce_ms": 1000,
              "clipboard_clear_ms": 30000, "update_check_enabled": true}}
```

The next `entries_count` frames are entry documents (one JSON object each, at most 64 MiB). Each is followed immediately by the frames for its attachments (raw bytes, at most 5 MiB each), in the order listed in that entry:

```json
{"name": "...", "kind": "login", "username": null, "value": "...", "url": null, "totp_secret": null,
 "description": null, "tags": [], "custom_fields": [], "folder": null, "favorite": false,
 "history": [], "created": "...", "updated": "...", "deleted": null,
 "attachments": [{"filename": "...", "content_type": null, "size": 1, "sha256": "hex", "created": "..."}]}
```

This layout keeps many-entry vaults from accumulating into one large JSON allocation. The maximum is 1,000,001 total frames (one envelope plus at most 1,000,000 entry and attachment frames) and 1 GiB for the complete `.cmbackup` file. A vault entry's encoded document is limited to 64 MiB minus 32 KiB of framing/metadata allowance; each attachment's encoded metadata is limited to 2 KiB. Before each write commits, the vault checks `sum(length(entry document)) + 32 KiB per entry + sum(length(attachment metadata) + length(attachment content)) + 256 bytes per attachment + 4 KiB fixed overhead` against the 1 GiB cap, and enforces the frame-count limit. Supported operations therefore stop before the data can outgrow the complete-backup capacity. Restore rejects a frame over its limit before allocating it.

**Reading** (frame authentication is sequential; database writes are in one transaction and any later failure rolls them all back):

1. Parse the header; refuse a wrong magic or version, unknown KDF, parameters outside the accepted range, a frame count above the limit.
2. Run Argon2id, compare the commitment in constant time: a mismatch is "wrong password".
3. Decrypt frame 0 with its index and `last` flag; parse the envelope strictly. Then parse each entry frame strictly, checking types, timestamps, attachment counts and active-name uniqueness.
4. For each entry, decrypt its attachment frames in order, check their length and SHA-256 against that entry's metadata, re-encrypt them under the vault key and store them. A frame that fails authentication, a missing frame (truncation), a frame after the last one or trailing bytes aborts the transaction: the vault is left exactly as it was.

Wrong password, tampering, truncation, reordering, a frame from another backup and a malformed envelope or entry all fail cleanly with nothing committed. Memory use is bounded by one entry frame and one attachment, plus bounded row identifiers and lookup indexes; the uploaded backup itself is ciphertext and may be spooled to a temporary file by the server.

**Restoring into a vault.** Entries are added with their timestamps and history; an active entry whose name already exists is skipped or, with "overwrite", the existing one is moved to the Trash (with its history and attachments) and the backup's version takes its place, so nothing is lost. CSV imports and 2.0 backup ZIPs overwrite the same way. A trashed entry is skipped if the vault already has a trashed entry with the same name and deletion time (restoring one backup twice adds nothing). Settings are restored only into a vault that has no entries yet. Restored entries count as backed up.

## 6. Versioning

Three independent numbers, each refused when newer than the code understands:

- SQLite `user_version`: the table layout (schema). 2 since this format.
- `vault.format_version`: the cryptographic layout. 2.
- The backup header `version`: 2. (Version 1 was the WinZip-AES ZIP of CipherMoth up to 2.0.x; it can still be imported, see below.)

A file with another schema or a newer format is refused at startup, before anything is written; the message says what to do. So is a write-ahead log or rollback journal next to a missing or empty vault file (it belongs to a vault that was moved away, and SQLite would discard it). An empty file gets the schema in one transaction; until a master password is set, the vault is reported as not set up, and a vault is never created over entries that have no key record.

## 6a. Damaged rows

A value that fails authentication or its format check is never shown and never overwritten. Listings leave that entry or attachment out (and log its row id); `GET /api/vault/damaged` lists such rows, and `DELETE /api/vault/damaged/{entries|attachments}/{id}` removes one only after checking, under the write lock, that it really cannot be read (removing an entry removes its attachments). Backups and master password changes refuse to run while damaged rows remain, because they would have to drop or carry them. The web UI shows a banner and the CLI has `ciphermoth damaged [--remove]`. Restoring a snapshot from before the damage is the alternative that keeps everything.

## 7. What changes do not erase

A master password change re-encrypts the live file, and SQLite's `secure_delete` overwrites freed pages, but copies made earlier keep the old keys: snapshots, backups, a WAL file copied while it held old frames, SSD wear levelling, filesystem snapshots and Time Machine. Anyone who has such a copy and the old password can read it. The same holds for plaintext names in vaults or ZIP backups written by CipherMoth 2.0.x or earlier.

## 8. Compatibility

- **Vaults written by CipherMoth 2.0.x (schema 1, format 1)** are refused, unchanged, with instructions: make a backup in 2.0.x, set the old file aside with `ciphermoth-admin set-aside` (it is moved, never deleted), start a new vault and import the backup. There is no in-place conversion.
- **Backup ZIPs (format 1)** from CipherMoth 1.x and 2.0.x can still be imported. They are lossy (no history, trash, attachments, settings or timestamps) and protected only by WinZip AES with 1000 PBKDF2-SHA1 iterations; make a new backup afterwards and delete the old ZIPs. This reader is the only format 1 code left and can be removed once 2.0.x is no longer in use.
