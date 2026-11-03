"""
Schema 3 upgrades a vault written by CipherMoth 3.3.0 (schema 2) in place, after
keeping a snapshot of it exactly as that release left it.
"""

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

import storage
from tests.authenticator import SoftKey
from tests.support import add_security_key, auth, client_for_data_dir

pytestmark = pytest.mark.asyncio

FROZEN = Path(__file__).resolve().parents[2] / "testdata" / "vaults"
PASSWORD = "correct horse battery 2026"


def _pragma(path: Path, name: str) -> int:
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
        return connection.execute(f"PRAGMA {name}").fetchone()[0]


def _install(tmp_path: Path) -> Path:
    folder = tmp_path / "data"
    folder.mkdir(mode=0o700)
    shutil.copyfile(FROZEN / "schema-2-v3.3.0.db", folder / storage.VAULT_FILE)
    (folder / storage.VAULT_FILE).chmod(0o600)
    return folder


async def test_a_3_3_0_vault_is_upgraded_after_a_snapshot(tmp_path: Path) -> None:
    folder = _install(tmp_path)
    assert storage.check_file(folder / storage.VAULT_FILE) == []

    async with client_for_data_dir(folder) as client:
        resp = await client.post(
            "/master_password/unlock", json={"master_password": PASSWORD}
        )
        assert resp.json()["valid"] is True, resp.text
        token = resp.json()["session_token"]
        entries = (await client.get("/passwords", headers=auth(token))).json()
        assert {(e["password_name"], e["password_value"]) for e in entries} == {
            ("Bank", "bank-secret-2"),
            ("GitHub", "gh-secret-1"),
        }
        github = next(e for e in entries if e["password_name"] == "GitHub")
        assert github["attachment_count"] == 1
        trash = (await client.get("/passwords/trash", headers=auth(token))).json()
        assert [t["password_value"] for t in trash] == ["old-secret-3"]

        # The new features work on the upgraded vault.
        key = SoftKey()
        assert (
            await add_security_key(client, auth(token), key, master_password=PASSWORD)
        ).status_code == 200

    live = folder / storage.VAULT_FILE
    assert _pragma(live, "user_version") == storage.SCHEMA_VERSION == 3
    [kept] = sorted((folder / storage.SNAPSHOT_DIR).glob("before-schema-3-*.db"))
    assert _pragma(kept, "user_version") == 2
    assert storage.check_file(kept) == []


async def test_the_upgrade_runs_once(tmp_path: Path) -> None:
    folder = _install(tmp_path)
    for _ in range(2):
        async with client_for_data_dir(folder) as client:
            assert (await client.get("/master_password/status")).json()["initialized"]
    assert len(list((folder / storage.SNAPSHOT_DIR).glob("before-schema-3-*"))) == 1


async def test_an_upgrade_that_fails_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _install(tmp_path)

    def broken(connection) -> None:
        connection.exec_driver_sql("CREATE TABLE half_done (id INTEGER)")
        raise RuntimeError("power cut")

    monkeypatch.setitem(storage._UPGRADES, 2, broken)
    with pytest.raises(RuntimeError):
        async with client_for_data_dir(folder):
            pass
    live = folder / storage.VAULT_FILE
    assert _pragma(live, "user_version") == 2
    with closing(sqlite3.connect(f"{live.as_uri()}?mode=ro", uri=True)) as connection:
        tables = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_schema")
        }
    assert "half_done" not in tables
    assert "security_keys" not in tables
