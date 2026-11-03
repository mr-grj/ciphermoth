import asyncio
import base64
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import helpers
from crud.engine import Database
from main import app
from storage import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    VAULT_FILE,
    StorageError,
    check_file,
    set_aside,
    snapshot,
)
from tests.integrity import hkdf
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    auth,
    client_for_data_dir,
    crash_after_committing,
    create_vault,
    data_dir,
    db_execute,
    db_snapshot,
    entry,
    raw_vault_key,
    stored_vault_key,
    unlock,
)
from vault_admin import app as admin_app

ROTATE = {
    "master_password": MASTER_PASSWORD,
    "new_master_password": NEW_MASTER_PASSWORD,
}
CANARY = "Zq7Canary"


def _canaries(label: str) -> str:
    return f"{CANARY}-{label}-{os.urandom(3).hex()}"


def _format_1_vault(path: Path) -> None:
    """A vault as CipherMoth 2.0 left it: schema 1, plaintext names, the last
    change committed only to the WAL."""
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "CREATE TABLE master_password (id INTEGER PRIMARY KEY, salt BLOB, "
            "hash_key TEXT, key_check BLOB)"
        )
        connection.execute(
            "CREATE TABLE passwords (id INTEGER PRIMARY KEY, password_name TEXT, "
            "password_value BLOB)"
        )
        connection.execute(
            "INSERT INTO passwords (password_name, password_value) "
            "VALUES ('old-entry', x'00')"
        )
        connection.commit()
    crash_after_committing(
        path.parent,
        "INSERT INTO passwords (password_name, password_value) "
        "VALUES ('only-in-wal', x'00')",
    )


def _files(folder: Path) -> dict[str, bytes]:
    """The vault's files, without the -shm SQLite needs for locking and an
    empty -wal that a read-only open may create next to a WAL vault."""
    return {
        path.name: path.read_bytes()
        for path in sorted(folder.glob(f"{VAULT_FILE}*"))
        if path.name != f"{VAULT_FILE}-shm"
        and not (path.name.endswith("-wal") and path.stat().st_size == 0)
    }


async def test_a_new_vault_is_format_2_with_a_wrapped_key_and_no_verifier(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    [row] = await db_execute(
        "SELECT format_version, kdf, kdf_memory_kib, kdf_iterations, kdf_lanes, "
        "length(kdf_salt), length(password_check), length(wrapped_key), "
        "length(key_check) FROM vault"
    )
    assert row == (2, "argon2id", 65536, 3, 4, 16, 32, 61, 32)
    tables = {
        name
        for (name,) in await db_execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
        )
    }
    assert tables >= {"vault", "entries", "attachments", "settings"}
    assert not tables & {"master_password", "passwords", "password_attachments"}
    [(user_version,)] = await db_execute("PRAGMA user_version")
    assert user_version == SCHEMA_VERSION == 3


async def test_the_schema_has_no_plaintext_entry_columns_or_indexes() -> None:
    allowed = {
        "vault": {
            "id",
            "created",
            "updated",
            "format_version",
            "kdf",
            "kdf_memory_kib",
            "kdf_iterations",
            "kdf_lanes",
            "kdf_salt",
            "password_check",
            "wrapped_key",
            "key_check",
            "factor_key_escrow",
        },
        "entries": {
            "id",
            "uid",
            "created",
            "updated",
            "deleted",
            "name_index",
            "document",
            "backed_up",
        },
        "attachments": {
            "id",
            "uid",
            "created",
            "entry_id",
            "size_bytes",
            "meta",
            "content",
        },
        # A security key's name is sealed; the rest identifies the credential.
        "security_keys": {
            "id",
            "uid",
            "created",
            "last_used",
            "credential_id",
            "public_key",
            "rp_id",
            "prf_salt",
            "sign_count",
            "wrapped_factor_key",
            "name",
        },
        "recovery": {
            "id",
            "created",
            "kdf_memory_kib",
            "kdf_iterations",
            "kdf_lanes",
            "salt",
            "public_key",
            "sealed_key",
            "binding",
        },
    }
    for table, columns in allowed.items():
        found = {row[1] for row in await db_execute(f"PRAGMA table_info({table})")}
        assert found == columns, table
    indexed = {
        row[0]
        for (sql,) in await db_execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND sql IS NOT NULL"
        )
        for row in [sql.split("(", 1)[1].split(")")[0].split(", ")]
    }
    assert indexed <= {"name_index", "entry_id"}


async def test_entry_content_never_reaches_the_vault_files_snapshots_or_backups(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    """
    Every field of an entry and an attachment carries a unique marker; none
    of them may appear, in UTF-8 or UTF-16, anywhere in the vault file, its
    WAL, a snapshot or a backup, before or after a rotation. This proves the
    values are not written in clear; it cannot prove what an encrypted value
    reveals, or what the operating system keeps elsewhere (swap, freed SSD
    blocks, other copies).
    """
    headers = auth(await create_vault(client))
    markers = {
        field: _canaries(field)
        for field in (
            "name",
            "username",
            "value",
            "url",
            "description",
            "tag",
            "folder",
            "label",
            "hidden",
            "history",
            "note",
            "filename",
            "type",
            "content",
            "trashed",
        )
    }
    login = entry(
        markers["name"],
        markers["value"],
        username=markers["username"],
        url=f"https://{markers['url']}.test",
        description=markers["description"],
        tags=[markers["tag"]],
        folder=markers["folder"],
        custom_fields=[{"label": markers["label"], "value": markers["hidden"]}],
    )
    for item in (
        {**login, "password_value": markers["history"]},
        entry(markers["note"] + "-name", markers["note"], kind="note"),
        entry(markers["trashed"], markers["trashed"] + "-value"),
    ):
        resp = await client.post("/passwords/create", json=item, headers=headers)
        assert resp.status_code == 200, resp.text
    resp = await client.patch(
        "/passwords/update",
        json={"password": {"password_name": markers["name"]}, "new_password": login},
        headers=headers,
    )
    assert resp.status_code == 200
    resp = await client.post(
        f"/passwords/{markers['name']}/attachments",
        files={
            "file": (
                markers["filename"] + ".txt",
                (markers["content"] * 50).encode(),
                f"text/{markers['type']}",
            )
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert (
        await client.delete(f"/passwords/{markers['trashed']}", headers=headers)
    ).is_success
    backup = await client.post(
        "/passwords/backup", json={"master_password": MASTER_PASSWORD}, headers=headers
    )
    assert backup.status_code == 200
    first_snapshot = snapshot(data_dir(), tmp_path / "before.db")
    resp = await client.patch("/master_password/update", json=ROTATE, headers=headers)
    assert resp.status_code == 200, resp.text
    second_snapshot = snapshot(data_dir(), tmp_path / "after.db")

    secrets = [
        MASTER_PASSWORD,
        NEW_MASTER_PASSWORD,
        await stored_vault_key(NEW_MASTER_PASSWORD),
        *markers.values(),
    ]
    raw = await raw_vault_key(NEW_MASTER_PASSWORD)
    artifacts = {
        **{name: data for name, data in _files(data_dir()).items()},
        "backup": backup.content,
        "snapshot before rotation": first_snapshot.read_bytes(),
        "snapshot after rotation": second_snapshot.read_bytes(),
    }
    for where, data in artifacts.items():
        for secret in secrets:
            for encoded in (secret.encode(), secret.encode("utf-16-le")):
                assert encoded not in data, f"{secret!r} in {where}"
        assert raw not in data, where
        assert hkdf(raw, "ciphermoth/v2/record-encryption") not in data, where


async def test_a_wrong_password_changes_nothing_on_disk(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    await client.post("/passwords/create", json=entry("kept"), headers=headers)
    before = await db_snapshot()
    for password in (WRONG_MASTER_PASSWORD, MASTER_PASSWORD + " ", "x" * 1024):
        resp = await client.post(
            "/master_password/unlock", json={"master_password": password}
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is (password.strip() == MASTER_PASSWORD)
    resp = await client.patch(
        "/master_password/update",
        json={**ROTATE, "master_password": WRONG_MASTER_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 403
    assert await db_snapshot() == before


async def _rewrap(params: helpers.KdfParams, password: str = MASTER_PASSWORD) -> None:
    raw = await raw_vault_key(password)
    salt = os.urandom(16)
    material = helpers.seal_key_material(
        helpers.argon2id(password, salt, params), raw, params, salt
    )
    await db_execute(
        "UPDATE vault SET kdf_memory_kib = :m, kdf_iterations = :t, kdf_lanes = :p, "
        "kdf_salt = :salt, password_check = :check, wrapped_key = :wrapped",
        m=params.memory_kib,
        t=params.iterations,
        p=params.lanes,
        salt=salt,
        check=material.password_check,
        wrapped=material.wrapped_key,
    )


async def test_other_kdf_parameters_unlock_and_a_rotation_updates_them(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    await client.post("/passwords/create", json=entry("kept"), headers=headers)
    await _rewrap(helpers.KdfParams(memory_kib=32768, iterations=2, lanes=2))

    token = await unlock(client)
    resp = await client.get("/passwords/kept", headers=auth(token))
    assert resp.status_code == 200
    resp = await client.patch(
        "/master_password/update", json=ROTATE, headers=auth(token)
    )
    assert resp.status_code == 200, resp.text
    [params] = await db_execute(
        "SELECT kdf_memory_kib, kdf_iterations, kdf_lanes FROM vault"
    )
    assert params == (65536, 3, 4)
    assert (
        await client.get(
            "/passwords/kept", headers=auth(await unlock(client, NEW_MASTER_PASSWORD))
        )
    ).status_code == 200


@pytest.mark.parametrize(
    ("memory", "iterations", "lanes"),
    [(4 * 1024 * 1024, 3, 4), (65536, 1000, 4), (65536, 3, 64), (1024, 3, 4)],
    ids=["4-GiB", "1000-passes", "64-lanes", "1-MiB"],
)
async def test_hostile_kdf_parameters_are_refused_before_deriving(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    memory: int,
    iterations: int,
    lanes: int,
) -> None:
    headers = auth(await create_vault(client))
    await db_execute(
        "UPDATE vault SET kdf_memory_kib = :m, kdf_iterations = :t, kdf_lanes = :p",
        m=memory,
        t=iterations,
        p=lanes,
    )
    before = await db_snapshot()

    def never(*args: object) -> bytes:
        raise AssertionError("the KDF ran with hostile parameters")

    monkeypatch.setattr(helpers, "Argon2id", never)
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 400
    assert "Unsupported key derivation parameters" in resp.json()["detail"]
    resp = await client.patch("/master_password/update", json=ROTATE, headers=headers)
    assert resp.status_code == 400
    assert await db_snapshot() == before


async def test_names_are_exact_strings_found_only_through_their_index(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    names = ["Mölle", "Mölle", "mölle", "a/b", "a b", "a  b", "日本 🦋", "x" * 255]
    for name in names:
        resp = await client.post(
            "/passwords/create", json=entry(name, f"v-{name}"), headers=headers
        )
        assert resp.status_code == 200, (name, resp.text)
    resp = await client.post(
        "/passwords/create", json=entry("  a b  "), headers=headers
    )
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"]
    listing = (await client.get("/passwords", headers=headers)).json()
    assert [p["password_name"] for p in listing] == sorted(names)
    key = helpers.VaultKey(await raw_vault_key())
    indexes = {bytes(i) for (i,) in await db_execute("SELECT name_index FROM entries")}
    assert indexes == {key.name_index(name) for name in names}
    for name in names:
        resp = await client.get(
            "/passwords/" + name.replace("/", "%2F"), headers=headers
        )
        assert resp.json()["password_value"] == f"v-{name}"


async def test_trash_name_reuse_rename_and_restore_follow_the_index(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    for item in (entry("site", "first"), entry("other", "other-v")):
        await client.post("/passwords/create", json=item, headers=headers)
    assert (await client.delete("/passwords/site", headers=headers)).is_success
    resp = await client.post(
        "/passwords/create", json=entry("site", "second"), headers=headers
    )
    assert resp.status_code == 200
    assert (await client.delete("/passwords/site", headers=headers)).is_success
    resp = await client.post(
        "/passwords/create", json=entry("site", "third"), headers=headers
    )
    assert resp.status_code == 200
    trash = (await client.get("/passwords/trash", headers=headers)).json()
    assert [t["password_value"] for t in trash] == ["second", "first"]

    resp = await client.post("/passwords/site/restore", headers=headers)
    assert resp.status_code == 400
    resp = await client.patch(
        "/passwords/update",
        json={"password": {"password_name": "site"}, "new_password": entry("other")},
        headers=headers,
    )
    assert resp.status_code == 400
    resp = await client.patch(
        "/passwords/update",
        json={
            "password": {"password_name": "site"},
            "new_password": entry("moved", "third"),
        },
        headers=headers,
    )
    assert resp.status_code == 200
    resp = await client.post("/passwords/site/restore", headers=headers)
    assert resp.status_code == 200
    assert (await client.get("/passwords/site", headers=headers)).json()[
        "password_value"
    ] == "second"
    resp = await client.delete("/passwords/site", headers=headers)
    resp = await client.delete("/passwords/site/purge", headers=headers)
    assert resp.status_code == 200
    trash = (await client.get("/passwords/trash", headers=headers)).json()
    assert [t["password_value"] for t in trash] == ["first"]


async def test_cancelled_unlocks_creations_and_rotations_leave_nothing_behind(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = asyncio.Event()
    original = helpers.derive

    async def slow_derive(
        password: str, salt: bytes, params: helpers.KdfParams = helpers.DEFAULT_KDF
    ) -> bytes:
        entered.set()
        await asyncio.sleep(30)
        return await original(password, salt, params)

    monkeypatch.setattr(helpers, "derive", slow_derive)
    creating = asyncio.create_task(
        client.post(
            "/master_password/create", json={"master_password": MASTER_PASSWORD}
        )
    )
    await entered.wait()
    creating.cancel()
    with pytest.raises(asyncio.CancelledError):
        await creating
    assert await db_execute("SELECT count(*) FROM vault") == [(0,)]
    assert len(app.state.vault_sessions) == 0
    monkeypatch.undo()

    token = await create_vault(client)
    await client.post("/passwords/create", json=entry("kept"), headers=auth(token))
    before = await db_snapshot()
    for request in (
        lambda: client.post(
            "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
        ),
        lambda: client.patch(
            "/master_password/update", json=ROTATE, headers=auth(token)
        ),
    ):
        entered.clear()
        monkeypatch.setattr(helpers, "derive", slow_derive)
        task = asyncio.create_task(request())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        monkeypatch.undo()
    assert await db_snapshot() == before
    assert len(app.state.vault_sessions) == 1
    assert (await client.get("/passwords/kept", headers=auth(token))).status_code == 200
    from tests.support import engine

    assert engine.sync_engine.pool.checkedout() == 0


async def test_a_format_1_vault_is_refused_untouched_and_can_be_set_aside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "data"
    folder.mkdir()
    _format_1_vault(folder / VAULT_FILE)
    before = _files(folder)
    assert f"{VAULT_FILE}-wal" in before

    database = Database(folder)
    with pytest.raises(StorageError, match="CipherMoth 2.0 or earlier") as refused:
        await database.prepare()
    await database.dispose()
    assert "set-aside" in str(refused.value)
    assert "Nothing was changed" in str(refused.value)
    assert _files(folder) == before
    assert any("CipherMoth 2.0" in p for p in check_file(folder / VAULT_FILE))

    monkeypatch.setenv("CIPHERMOTH_DATA_DIR", str(folder))
    storage_settings = __import__("settings").get_storage_settings
    storage_settings.cache_clear()
    try:
        runner = CliRunner()
        result = runner.invoke(admin_app, ["set-aside"], input="n\n")
        assert result.exit_code == 1
        assert _files(folder) == before
        result = runner.invoke(admin_app, ["set-aside", "--yes"])
        assert result.exit_code == 0, result.output
    finally:
        storage_settings.cache_clear()
    [kept] = list((folder / "snapshots").iterdir())
    assert _files(kept) == before
    assert _files(folder) == {}
    with closing(sqlite3.connect(kept / VAULT_FILE)) as connection:
        names = connection.execute(
            "SELECT password_name FROM passwords ORDER BY id"
        ).fetchall()
    assert names == [("old-entry",), ("only-in-wal",)]

    async with client_for_data_dir(folder) as client:
        resp = await client.get("/master_password/status")
        assert resp.json() == {
            "initialized": False,
            "security_key_required": False,
            "recovery_code": False,
        }
        await create_vault(client)
    assert check_file(folder / VAULT_FILE) == []


async def test_set_aside_refuses_while_the_vault_is_served_and_needs_a_file(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "data"
    assert set_aside(folder) is None
    async with client_for_data_dir(folder) as client:
        await create_vault(client)
        app_for_folder = __import__("main").get_application(database=Database(folder))
        async with app_for_folder.router.lifespan_context(app_for_folder):
            with pytest.raises(StorageError, match="Another CipherMoth process"):
                set_aside(folder)
    assert (folder / VAULT_FILE).exists()


@pytest.mark.parametrize("version", [3, 99])
async def test_a_newer_vault_format_is_refused_untouched(
    tmp_path: Path, version: int
) -> None:
    folder = tmp_path / "data"
    async with client_for_data_dir(folder) as client:
        await create_vault(client)
    with closing(sqlite3.connect(folder / VAULT_FILE)) as connection:
        connection.execute("UPDATE vault SET format_version = ?", (version,))
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = _files(folder)

    database = Database(folder)
    with pytest.raises(
        StorageError, match=f"newer CipherMoth \\(vault format {version}"
    ):
        await database.prepare()
    await database.dispose()
    assert _files(folder) == before
    assert any("vault format" in p for p in check_file(folder / VAULT_FILE))


async def test_an_interrupted_vault_creation_leaves_a_vault_that_is_not_set_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "data"
    async with client_for_data_dir(folder) as client:

        async def failing_flush(self) -> None:
            raise RuntimeError("power cut before the key record was written")

        monkeypatch.setattr("sqlalchemy.ext.asyncio.AsyncSession.flush", failing_flush)
        resp = await client.post(
            "/master_password/create", json={"master_password": MASTER_PASSWORD}
        )
        monkeypatch.undo()
        assert resp.status_code == 500
        assert (await client.get("/master_password/status")).json() == {
            "initialized": False,
            "security_key_required": False,
            "recovery_code": False,
        }
        token = await create_vault(client)
        assert (await client.get("/passwords", headers=auth(token))).status_code == 200


async def test_the_key_record_binds_its_parameters_and_salt(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    for column, value in (
        ("kdf_salt", os.urandom(16)),
        ("password_check", os.urandom(32)),
        ("wrapped_key", b"\x02" + os.urandom(60)),
    ):
        [(original,)] = await db_execute(f"SELECT {column} FROM vault")
        await db_execute(f"UPDATE vault SET {column} = :v", v=value)
        resp = await client.post(
            "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
        )
        expected_damage = column == "wrapped_key"
        assert resp.status_code == (400 if expected_damage else 200), column
        if not expected_damage:
            assert resp.json()["valid"] is False, column
        await db_execute(f"UPDATE vault SET {column} = :v", v=original)
    assert (await unlock(client)) is not None


def test_session_keys_hold_no_raw_vault_key() -> None:
    raw = os.urandom(32)
    key = helpers.VaultKey(raw)
    assert "VaultKey(...)" == repr(key)
    assert not hasattr(key, "__dict__")
    held = [getattr(key, name) for name in key.__slots__]
    assert raw not in [h for h in held if isinstance(h, bytes)]
    assert base64.urlsafe_b64encode(raw).decode() not in repr(held)


async def test_the_api_refuses_a_document_whose_name_does_not_match_its_index(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    for item in (entry("alpha", "alpha-v"), entry("beta", "beta-v")):
        await client.post("/passwords/create", json=item, headers=headers)
    key = helpers.VaultKey(await raw_vault_key())
    [(alpha_id, alpha_uid)] = await db_execute(
        "SELECT id, uid FROM entries WHERE name_index = :i", i=key.name_index("alpha")
    )
    [(beta_document, beta_uid)] = await db_execute(
        "SELECT document, uid FROM entries WHERE name_index = :i",
        i=key.name_index("beta"),
    )
    document = key.open_entry(bytes(beta_uid), bytes(beta_document))
    await db_execute(
        "UPDATE entries SET document = :d WHERE id = :id",
        d=key.seal_entry(bytes(alpha_uid), document),
        id=alpha_id,
    )
    before = await db_snapshot()
    for request in (
        client.get("/passwords/alpha", headers=headers),
        client.delete("/passwords/alpha", headers=headers),
    ):
        resp = await request
        assert resp.status_code == 500, resp.text
        assert resp.json()["code"] == "vault_damaged"
        assert "beta-v" not in resp.text
    listing = (await client.get("/passwords", headers=headers)).json()
    assert [p["password_value"] for p in listing] == ["beta-v"]
    damaged = (await client.get("/vault/damaged", headers=headers)).json()
    assert damaged["entries"] == [alpha_id]
    assert await db_snapshot() == before
    assert (await client.get("/passwords/beta", headers=headers)).status_code == 200


@pytest.mark.parametrize(
    "change",
    [
        {"surprise": True},
        {"folder": None, "drop": "folder"},
        {"favorite": "yes"},
        {"tags": [1]},
        {"kind": "card"},
        {"history": [{"value": "x", "changed_at": "soon"}]},
    ],
    ids=["unknown-key", "missing-key", "wrong-type", "tag-type", "kind", "history"],
)
async def test_the_api_refuses_documents_this_release_did_not_write(
    client: httpx.AsyncClient, change: dict
) -> None:
    import json

    headers = auth(await create_vault(client))
    await client.post("/passwords/create", json=entry("alpha"), headers=headers)
    key = helpers.VaultKey(await raw_vault_key())
    [(entry_id, uid, sealed)] = await db_execute(
        "SELECT id, uid, document FROM entries"
    )
    document = json.loads(key.open_entry(bytes(uid), bytes(sealed)))
    dropped = change.pop("drop", None)
    document.update(change)
    if dropped:
        del document[dropped]
    await db_execute(
        "UPDATE entries SET document = :d WHERE id = :id",
        d=key.seal_entry(bytes(uid), json.dumps(document).encode()),
        id=entry_id,
    )
    resp = await client.get("/passwords/alpha", headers=headers)
    assert resp.status_code == 500, resp.text
    assert resp.json()["code"] == "vault_damaged"
    assert (await client.get("/passwords", headers=headers)).json() == []
    damaged = (await client.get("/vault/damaged", headers=headers)).json()
    assert damaged["entries"] == [entry_id]


@pytest.mark.parametrize("vault_state", ["missing", "empty"])
async def test_a_journal_without_its_vault_is_never_discarded(
    tmp_path: Path, vault_state: str
) -> None:
    folder = tmp_path / "data"
    folder.mkdir()
    _format_1_vault(folder / VAULT_FILE)
    wal = (folder / f"{VAULT_FILE}-wal").read_bytes()
    assert wal
    original = (folder / VAULT_FILE).read_bytes()
    (folder / VAULT_FILE).unlink()
    if vault_state == "empty":
        (folder / VAULT_FILE).write_bytes(b"")

    database = Database(folder)
    with pytest.raises(StorageError, match="journal belongs to a vault"):
        await database.prepare()
    await database.dispose()
    assert (folder / f"{VAULT_FILE}-wal").read_bytes() == wal

    kept = set_aside(folder)
    assert kept is not None and (kept / f"{VAULT_FILE}-wal").read_bytes() == wal
    async with client_for_data_dir(folder) as client:
        assert (await client.get("/master_password/status")).json() == {
            "initialized": False,
            "security_key_required": False,
            "recovery_code": False,
        }
    assert original


async def test_a_new_vault_is_never_created_over_entries_without_a_key_record(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    await client.post("/passwords/create", json=entry("orphan"), headers=headers)
    await db_execute("DELETE FROM vault")
    before = await db_snapshot()
    resp = await client.post(
        "/master_password/create", json={"master_password": NEW_MASTER_PASSWORD}
    )
    assert resp.status_code == 400
    assert "damaged" in resp.json()["detail"]
    assert await db_snapshot() == before
