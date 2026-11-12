"""Release diagnostics against repository-owned frozen v3 vectors (no IPC route)."""

import json


def run_all(folder):
    import sqlite3

    import helpers
    from storage import require_supported_sqlite

    require_supported_sqlite()
    count = 0
    vectors = json.loads((folder / "vault-v2.json").read_text(encoding="utf-8"))
    for vector in vectors["vaults"]:
        derived = helpers.argon2id(
            vector["password"], bytes.fromhex(vector["salt_hex"])
        )
        assert derived.hex() == vector["derived_hex"]
        material = helpers.KeyMaterial(
            params=helpers.DEFAULT_KDF,
            salt=bytes.fromhex(vector["salt_hex"]),
            password_check=bytes.fromhex(vector["password_check_hex"]),
            wrapped_key=bytes.fromhex(vector["wrapped_key_hex"]),
            key_check=bytes.fromhex(vector["key_check_hex"]),
        )
        key = helpers.open_key_material(derived, material)
        assert key.check.hex() == vector["key_check_hex"]
        count += 1
    key = helpers.VaultKey(bytes.fromhex(vectors["vaults"][0]["vault_key_hex"]))
    for vector in vectors["name_index"]:
        assert key.name_index(vector["name"]).hex() == vector["index_hex"]
        count += 1

    def opened(vector):
        parts = [bytes.fromhex(part) for part in vector["parts_hex"]]
        functions = {
            b"entry": key.open_entry,
            b"attachment-metadata": key.open_attachment_metadata,
            b"attachment-content": key.open_attachment_content,
        }
        return functions[parts[0]](*parts[1:], bytes.fromhex(vector["sealed_hex"]))

    for vector in vectors["records"]:
        assert opened(vector).hex() == vector["plaintext_hex"]
        count += 1
    for vector in vectors["rejected"]:
        try:
            opened(vector)
        except helpers.DecryptionFailed:
            count += 1
        else:
            raise AssertionError("altered record accepted")
    import hashlib
    import io

    from backup_format import BackupReader

    backup = json.loads((folder / "backup-v2.json").read_text(encoding="utf-8"))
    data = (folder / backup["file"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == backup["file_sha256"]
    reader = BackupReader(io.BytesIO(data))
    derived = helpers.argon2id(backup["password"], reader.header.salt)
    assert derived.hex() == backup["derived_hex"]
    backup_key = helpers.BackupKey(derived)
    assert backup_key.matches(reader.header)
    assert json.loads(reader.read(backup_key, 1 << 20)) == backup["manifest"]
    assert json.loads(reader.read(backup_key, 1 << 20)) == backup["entries"][0]
    assert reader.read(backup_key, 1 << 20).hex() == backup["attachment_hex"]
    assert json.loads(reader.read(backup_key, 1 << 20)) == backup["entries"][1]
    reader.finish()
    count += 6
    return {"passed": count, "sqlite": sqlite3.sqlite_version}
