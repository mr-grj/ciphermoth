# Frozen vaults

Vault files written by released CipherMoth versions, used to test that a newer
release upgrades them in place. Never regenerate one with current code: each file
must stay exactly what its release wrote.

| File | Written by | Master password | Contents |
|---|---|---|---|
| `schema-2-v3.3.0.db` | CipherMoth 3.3.0 (schema 2, format 2) | `correct horse battery 2026` | Active `Bank` and `GitHub` (username `moth`, passwords `bank-secret-2` / `gh-secret-1`), `GitHub` has the attachment `note.txt` (`attachment bytes`), `Old` (`old-secret-3`) in the trash |
