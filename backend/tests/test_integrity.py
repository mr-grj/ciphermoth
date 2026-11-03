import base64
import json
import os
import sqlite3
from contextlib import closing

import httpx
import pytest

from storage import VAULT_FILE
from tests.integrity import (
    VaultContents,
    VaultIntegrityError,
    assert_same_vault,
    diff_ciphertext,
    diff_vaults,
    raw_vault,
    read_vault,
)
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    auth,
    create_vault,
    data_dir,
    db_execute,
    engine,
    entry,
    reset_vault,
    stored_vault_key,
    unlock,
    vault_key,
)

BLOB = os.urandom(4096) + b"\x00\xff"


async def _scan(key: str, **options: object) -> VaultContents:
    async with engine.connect() as conn:
        return await read_vault(conn, key, **options)  # ty: ignore[invalid-argument-type]


async def _rich_vault(client: httpx.AsyncClient) -> str:
    headers = auth(await create_vault(client))
    login = entry(
        "GitHub",
        "first-Value-1",
        username="moth@example.com",
        url="https://github.com",
        totp_secret="JBSWY3DPEHPK3PXP",
        description="work",
        tags=["dev", "ops"],
        custom_fields=[{"label": "PIN", "value": "1234", "hidden": True}],
        folder="Work",
        favorite=True,
    )
    for item in (
        login,
        entry("Notes ✉", "  body\n\n", kind="note"),
        entry("Old", "old-Value-1"),
    ):
        assert (
            await client.post("/passwords/create", json=item, headers=headers)
        ).is_success
    for value in ("second-Value-2", "third-Value-3"):
        resp = await client.patch(
            "/passwords/update",
            json={
                "password": login,
                "new_password": {**login, "password_value": value},
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
    resp = await client.post(
        "/passwords/GitHub/attachments",
        files={"file": ("scan ț.bin", BLOB, "application/octet-stream")},
        headers=headers,
    )
    assert resp.status_code == 200
    assert (await client.delete("/passwords/Old", headers=headers)).is_success
    return await stored_vault_key()


async def _github() -> tuple[int, bytes]:
    key = await vault_key()
    [(entry_id, uid)] = await db_execute(
        "SELECT id, uid FROM entries WHERE name_index = :index",
        index=key.name_index("GitHub"),
    )
    return entry_id, bytes(uid)


async def _reseal_github(**changes: object) -> None:
    """Rewrite GitHub's document with the right key and binding but a changed
    content, as only someone holding the vault key could."""
    key = await vault_key()
    entry_id, uid = await _github()
    [(sealed,)] = await db_execute(
        "SELECT document FROM entries WHERE id = :id", id=entry_id
    )
    document = json.loads(key.open_entry(uid, bytes(sealed)))
    document.update(changes)
    for name, value in changes.items():
        if value is _DROP:
            del document[name]
    await db_execute(
        "UPDATE entries SET document = :d WHERE id = :id",
        d=key.seal_entry(uid, json.dumps(document).encode()),
        id=entry_id,
    )


_DROP = object()


async def test_a_healthy_vault_scans_clean_and_matches_the_api(
    client: httpx.AsyncClient,
) -> None:
    key = await _rich_vault(client)

    vault = await _scan(key, master_password=MASTER_PASSWORD)

    assert vault.key_check == "valid"
    assert vault.vault_rows == 1
    assert vault.revision == 3
    github = vault.active["GitHub"]
    assert github.value == "third-Value-3"
    assert [h[0] for h in github.history] == ["second-Value-2", "first-Value-1"]
    assert github.custom_fields == (("PIN", "1234", True),)
    assert github.tags == ("dev", "ops")
    assert github.favorite
    [attachment] = github.attachments
    assert attachment.filename == "scan ț.bin"
    assert attachment.size_bytes == len(BLOB)
    assert vault.active["Notes ✉"].value == "  body\n\n"
    assert vault.active["Notes ✉"].kind == "note"
    assert [e.name for e in vault.trash] == ["Old"]

    headers = auth(await unlock(client))
    listing = (await client.get("/passwords", headers=headers)).json()
    for item in listing:
        scanned = vault.active[item["password_name"]]
        assert scanned.value == item["password_value"]
        assert scanned.url == item["url"]
        assert list(scanned.tags) == item["tags"]


async def test_the_wrong_key_reports_every_encrypted_value(
    client: httpx.AsyncClient,
) -> None:
    await _rich_vault(client)
    wrong = base64.urlsafe_b64encode(os.urandom(32)).decode()

    vault = await _scan(wrong, strict=False)

    assert vault.key_check == "invalid"
    failing = {(p.table, p.column) for p in vault.problems}
    assert ("entries", "document") in failing
    assert ("attachments", "content") in failing
    assert ("attachments", "meta") in failing
    with pytest.raises(VaultIntegrityError):
        await _scan(wrong)


@pytest.mark.parametrize(
    ("changes", "column"),
    [
        ({"tags": "not a list"}, "tags"),
        ({"tags": [1]}, "tags"),
        ({"custom_fields": [{"label": 5}]}, "custom_fields"),
        ({"history": [{"value": "x", "changed_at": "yesterday"}]}, "history"),
        ({"kind": "card"}, "kind"),
        ({"surprise": True}, "document"),
        ({"folder": _DROP}, "document"),
        ({"name": "Somebody else"}, "name_index"),
    ],
)
async def test_damage_the_app_would_refuse_is_reported(
    client: httpx.AsyncClient, changes: dict, column: str
) -> None:
    key = await _rich_vault(client)
    await _reseal_github(**changes)

    with pytest.raises(VaultIntegrityError) as raised:
        await _scan(key)

    assert [p.column for p in raised.value.problems] == [column]


@pytest.mark.parametrize(
    ("sql", "column"),
    [
        ("UPDATE attachments SET size_bytes = 1", "size_bytes"),
        (
            "UPDATE entries SET updated = datetime(created, '-1 day') "
            "WHERE deleted IS NULL",
            "updated",
        ),
    ],
)
async def test_plaintext_column_damage_is_reported(
    client: httpx.AsyncClient, sql: str, column: str
) -> None:
    key = await _rich_vault(client)
    await db_execute(sql)

    with pytest.raises(VaultIntegrityError) as raised:
        await _scan(key)

    assert {p.column for p in raised.value.problems} == {column}


async def test_a_flipped_ciphertext_byte_is_reported(client: httpx.AsyncClient) -> None:
    key = await _rich_vault(client)
    entry_id, _ = await _github()
    [(token,)] = await db_execute(
        "SELECT document FROM entries WHERE id = :id", id=entry_id
    )
    flipped = bytearray(token)
    flipped[len(flipped) // 2] ^= 0x01
    await db_execute(
        "UPDATE entries SET document = :t WHERE id = :id", t=bytes(flipped), id=entry_id
    )

    with pytest.raises(VaultIntegrityError, match="document: does not authenticate"):
        await _scan(key)


async def test_ciphertext_moved_to_another_row_or_role_is_reported(
    client: httpx.AsyncClient,
) -> None:
    key = await _rich_vault(client)
    github, _ = await _github()
    await db_execute(
        "UPDATE entries SET document = (SELECT document FROM entries WHERE id = :g) "
        "WHERE id <> :g",
        g=github,
    )
    await db_execute("UPDATE attachments SET content = meta")

    vault = await _scan(key, strict=False)

    reasons = {(p.table, p.row_id, p.column) for p in vault.problems}
    moved = {row_id for table, row_id, _ in reasons if table == "entries"}
    assert github not in moved and len(moved) == 2
    assert ("attachments", 1, "content") in reasons


async def test_orphaned_attachments_and_duplicate_rows_are_reported(
    client: httpx.AsyncClient,
) -> None:
    key = await _rich_vault(client)
    with closing(sqlite3.connect(data_dir() / VAULT_FILE)) as unchecked:
        [(index_sql,)] = unchecked.execute(
            "SELECT sql FROM sqlite_schema WHERE name = 'uq_entries_name_active'"
        ).fetchall()
        unchecked.execute("UPDATE attachments SET entry_id = 999")
        unchecked.execute("DROP INDEX uq_entries_name_active")
        unchecked.execute(
            "INSERT INTO entries (uid, name_index, document, backed_up) "
            "SELECT randomblob(16), name_index, document, 0 FROM entries "
            "WHERE deleted IS NULL LIMIT 1"
        )
        unchecked.commit()
    try:
        vault = await _scan(key, strict=False)
    finally:
        with closing(sqlite3.connect(data_dir() / VAULT_FILE)) as unchecked:
            unchecked.execute("DELETE FROM entries")
            unchecked.execute(index_sql)
            unchecked.commit()

    reasons = sorted(str(p) for p in vault.problems)
    assert any("entry_id: no such entry" in r for r in reasons)
    assert any("does not authenticate" in r for r in reasons)


async def test_rotation_keeps_every_plaintext_and_replaces_every_ciphertext(
    client: httpx.AsyncClient,
) -> None:
    key = await _rich_vault(client)
    before = await _scan(key)
    async with engine.connect() as conn:
        tokens_before = await raw_vault(conn)

    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(await unlock(client)),
    )
    assert resp.status_code == 200, resp.text
    new_key = await stored_vault_key(NEW_MASTER_PASSWORD)

    after = await _scan(new_key, master_password=NEW_MASTER_PASSWORD)
    assert_same_vault(before, after, compare=[*PLAINTEXT, "created", "updated"])
    assert after.key_check == "valid"
    async with engine.connect() as conn:
        tokens_after = await raw_vault(conn)
    changed = diff_ciphertext(tokens_before, tokens_after)
    expected = sum(
        len(tokens_after[table]) * len(columns)
        for table, columns in (
            ("vault", ("wrapped_key",)),
            ("entries", ("document",)),
            ("attachments", ("meta", "content")),
        )
    )
    assert len(changed) == expected
    for table, column in (("entries", "name_index"), ("vault", "kdf_salt")):
        for row_id, row in tokens_after[table].items():
            assert row[column] != tokens_before[table][row_id][column]
    with pytest.raises(VaultIntegrityError):
        await _scan(key)


PLAINTEXT = (
    "kind",
    "username",
    "description",
    "value",
    "url",
    "totp_secret",
    "tags",
    "custom_fields",
    "folder",
    "history",
    "favorite",
)


async def test_a_complete_backup_restores_every_entry_losslessly(
    client: httpx.AsyncClient,
) -> None:
    key = await _rich_vault(client)
    original = await _scan(key)
    resp = await client.post(
        "/passwords/backup",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(await unlock(client)),
    )
    archive = resp.content
    await reset_vault()
    token = await create_vault(client, NEW_MASTER_PASSWORD)
    new_key = await stored_vault_key(NEW_MASTER_PASSWORD)
    resp = await client.post(
        "/passwords/import",
        data={"master_password": MASTER_PASSWORD},
        files={"file": ("b.cmbackup", archive, "application/octet-stream")},
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["trashed"] == 1
    assert resp.json()["attachments"] == 1
    restored = await _scan(new_key, master_password=NEW_MASTER_PASSWORD)

    assert_same_vault(original, restored, compare=[*PLAINTEXT, "created", "updated"])
    assert all(e.backed_up for e in restored.entries)
    assert restored.settings == original.settings


async def test_diff_rejects_unknown_fields() -> None:
    empty = VaultContents(None, 0, "absent", (), ())
    with pytest.raises(ValueError, match="nonsense"):
        diff_vaults(empty, empty, compare=["nonsense"])
    assert json.dumps(diff_vaults(empty, empty)) == "[]"
