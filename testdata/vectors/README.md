# CipherMoth cryptographic test vectors

Frozen known-answer vectors for every cryptographic construction a CipherMoth vault depends on. They exist so that any implementation (the Python backend today, a TypeScript, Rust or mobile core later) can prove it reads and writes the same vault format. All values are synthetic.

**Frozen means frozen.** A vector never changes once committed. If the format changes, add a new file or a new section. The vectors of a format that the code no longer reads are removed together with that code (git history keeps them): vault format 1's `fernet.json`, `key_check.json` and `bcrypt.json` went with format 1.

The Python tests are in `backend/tests/test_vectors.py`; the frontend runs `totp.json` in `frontend/src/lib/totp.test.js`.

## Files

Every JSON file has `format` (`ciphermoth-test-vectors/1`), `name` and `description`, then its vectors. Byte strings are lowercase hex (`*_hex`); keys and tokens are the ASCII strings as stored.

| File | Covers |
|---|---|
| `argon2id.json` | Argon2id with the default parameters, plus `api_input`: which characters the API strips from a master password before it reaches the KDF. The `key` values are base64url of the 32-byte output; format 1 used that string as a Fernet key, format 2 uses the raw bytes |
| `vault-v2.json` | Vault format 2: key derivation, password commitment, wrapped vault key, derived keys, name index, sealed entries and attachments with their associated data, and sealed values that must be refused |
| `backup-v2.json` + `backup-v2.cmbackup` | Backup format 2: a real file with fixed salt and nonces, its keys, header, envelope, entry frames and attachment frame |
| `totp.json` | RFC 6238 TOTP for stored secrets |
| `extension-channel.json` | The browser extension's desktop channel: X25519 pairing with a commitment, the six-digit code, the pairing and connection keys, AES-256-GCM messages with counter nonces, and messages that must be refused. Used by the Rust app and host, the extension's TypeScript and the desktop QA harness |
| `backup_zip.json` + `backup-v1.zip` | Backup format 1 (the ZIP of 2.0 and earlier), still importable: a real archive, its password and its JSON |

## The constructions

**Master password input.** The API strips leading and trailing Unicode `White_Space` (pydantic's `str_strip_whitespace`), then encodes UTF-8. No Unicode normalization: NFC and NFD forms of the same password are different passwords. Characters that are not `White_Space`, such as U+200B or U+001C, are kept even though Python's `str.strip()` would remove U+001C.

**Vault format 2 and backup format 2** are specified in [docs/VAULT_FORMAT.md](../../docs/VAULT_FORMAT.md); each JSON file's `description` repeats the construction it covers. In short: Argon2id (m=65536 KiB, t=3, p=4, 32 bytes) gives `derived`; HKDF-SHA256 with fixed labels gives the password commitment and the key-wrapping key; a random vault key is wrapped with AES-256-GCM; HKDF of the vault key gives the record key, the name-index key and the key check; records are `0x02 || nonce || AES-256-GCM(...)` with length-prefixed associated data naming the role and the record ids; the name index is HMAC-SHA256 of the UTF-8 name.

**TOTP.** RFC 6238 with HMAC-SHA1. Secrets are stored upper-case, unpadded base32 with no spaces; pad to a multiple of 8 before decoding.

**Backup ZIP (format 1).** One member, `ciphermoth_backup.json`, deflated and encrypted with WinZip AES-256 (AE-2; PBKDF2-HMAC-SHA1, 1000 iterations, 16-byte salt) under the UTF-8 master password. It is a lossy export: no history, trash, attachments, settings or timestamps. CipherMoth only reads it now.

## Regenerating

`backend/tests/tools/generate_vectors.py` is the reference construction, written against the primitive libraries rather than the application code. It refuses to overwrite existing files (`--only NAME...` writes new ones). A test checks that it still reproduces the frozen JSON and `backup-v2.cmbackup` byte for byte, so a library upgrade that changed any output would fail loudly instead of being frozen in. `backup-v1.zip` cannot be reproduced (the ZIP salt is random) and is only ever read.
