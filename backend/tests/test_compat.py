import httpx
import pytest

from settings import get_api_settings
from tests.support import (
    MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    auth,
    create_vault,
    db_execute,
    entry,
    legacy_backup_zip,
    reset_vault,
    stored_vault_key,
    unlock,
)

FULL_LOGIN = entry(
    "GitHub #work",
    "gh-Secret-1",
    username="moth@example.com",
    url="https://github.com",
    totp_secret="otpauth://totp/GitHub:moth?secret=jbsw y3dp ehpk 3pxp&issuer=GitHub",
    description="work account",
    tags=["dev", " dev ", "ops"],
    custom_fields=[
        {"label": "Recovery", "value": "abcd-efgh", "hidden": True},
        {"label": "", "value": "dropped"},
    ],
    folder="Work",
    favorite=True,
)
NOTE = entry("Wi-Fi ключ", "  line one\n\tline two\n\n", kind="note")


async def _get(client: httpx.AsyncClient, key: str, name: str) -> dict:
    resp = await client.get(f"/passwords/{name.replace('#', '%23')}", headers=auth(key))
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_vault_lifecycle_and_unlock(client: httpx.AsyncClient) -> None:
    resp = await client.get("/master_password/status")
    assert resp.json() == {
        "initialized": False,
        "security_key_required": False,
        "recovery_code": False,
    }
    assert (await client.get("/meta")).json() == {
        "version": get_api_settings().version,
        "features": [
            "bulk-entry-actions",
            "bulk-entry-move",
            "entry-names-with-slash",
            "recovery-code",
            "security-keys",
            "vault-sessions",
        ],
    }

    resp = await client.post(
        "/master_password/create", json={"master_password": "short"}
    )
    assert resp.status_code == 422

    key = await create_vault(client)
    assert (await client.get("/master_password/status")).json() == {
        "initialized": True,
        "security_key_required": False,
        "recovery_code": False,
    }
    resp = await client.post(
        "/master_password/create", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 403

    tokens = {key, await unlock(client), await unlock(client, f"  {MASTER_PASSWORD}  ")}
    assert len(tokens) == 3
    for token in tokens:
        assert (await client.get("/passwords", headers=auth(token))).status_code == 200
    resp = await client.post(
        "/master_password/check", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 410
    assert await stored_vault_key() not in resp.text
    resp = await client.post(
        "/master_password/unlock", json={"master_password": WRONG_MASTER_PASSWORD}
    )
    assert resp.json() == {
        "valid": False,
        "session_token": None,
        "idle_timeout_ms": None,
    }


async def test_entries_notes_totp_history_and_favorites(
    client: httpx.AsyncClient,
) -> None:
    key = await create_vault(client)
    headers = auth(key)
    for item in (FULL_LOGIN, NOTE):
        resp = await client.post("/passwords/create", json=item, headers=headers)
        assert resp.status_code == 200, resp.text
    resp = await client.post("/passwords/create", json=NOTE, headers=headers)
    assert resp.status_code == 400

    login = await _get(client, key, "GitHub #work")
    assert login["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert login["tags"] == ["dev", "ops"]
    assert login["custom_fields"] == [
        {"label": "Recovery", "value": "abcd-efgh", "hidden": True}
    ]
    assert login["folder"] == "Work"
    assert login["favorite"] is True
    note = await _get(client, key, "Wi-Fi ключ")
    assert note["password_value"] == "  line one\n\tline two\n\n"
    assert note["kind"] == "note"

    resp = await client.post(
        "/passwords/create",
        json=entry("bad-totp", totp_secret="not base32!"),
        headers=headers,
    )
    assert resp.status_code == 422

    renamed = {**FULL_LOGIN, "password_name": "GitHub", "password_value": "gh-2"}
    resp = await client.patch(
        "/passwords/update",
        json={"password": FULL_LOGIN, "new_password": renamed},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    login = await _get(client, key, "GitHub")
    assert login["password_value"] == "gh-2"
    assert [h["value"] for h in login["password_history"]] == ["gh-Secret-1"]

    listing = await client.get("/passwords", headers=headers)
    assert [p["password_name"] for p in listing.json()] == ["GitHub", "Wi-Fi ключ"]

    resp = await client.post(
        "/passwords/backup", json={"master_password": MASTER_PASSWORD}, headers=headers
    )
    assert resp.status_code == 200
    resp = await client.patch(
        "/passwords/GitHub/favorite", json={"favorite": False}, headers=headers
    )
    assert resp.status_code == 200
    login = await _get(client, key, "GitHub")
    assert login["favorite"] is False
    assert login["backed_up"] is False


async def test_using_an_earlier_password_again_keeps_the_rest_of_the_entry(
    client: httpx.AsyncClient,
) -> None:
    """The body the web UI's password history sends to make an old value current
    again: only the name identifies the entry, every other field is resent."""
    key = await create_vault(client)
    headers = auth(key)
    resp = await client.post("/passwords/create", json=FULL_LOGIN, headers=headers)
    assert resp.status_code == 200, resp.text
    name = FULL_LOGIN["password_name"]
    for value in ("second-Value-2", "third-Value-3"):
        before = await _get(client, key, name)
        payload = {
            "password": {"password_name": name},
            "new_password": {
                field: before[field]
                for field in (
                    "password_name",
                    "kind",
                    "username",
                    "url",
                    "totp_secret",
                    "description",
                    "tags",
                    "custom_fields",
                    "folder",
                    "favorite",
                )
            }
            | {"password_value": value},
        }
        resp = await client.patch("/passwords/update", json=payload, headers=headers)
        assert resp.status_code == 200, resp.text
    before = await _get(client, key, name)
    old = before["password_history"][1]["value"]
    assert old == FULL_LOGIN["password_value"]

    payload["new_password"]["password_value"] = old
    resp = await client.patch("/passwords/update", json=payload, headers=headers)
    assert resp.status_code == 200, resp.text

    after = await _get(client, key, name)
    assert after["password_value"] == old
    assert [h["value"] for h in after["password_history"]] == [
        "third-Value-3",
        "second-Value-2",
        old,
    ]
    unchanged = ("username", "url", "totp_secret", "description", "tags")
    for field in (*unchanged, "custom_fields", "folder", "favorite", "kind"):
        assert after[field] == before[field], field


async def test_trash_restore_and_purge(client: httpx.AsyncClient) -> None:
    key = await create_vault(client)
    headers = auth(key)
    await client.post("/passwords/create", json=entry("site"), headers=headers)
    resp = await client.post(
        "/passwords/site/attachments",
        files={"file": ("a.txt", b"attached", "text/plain")},
        headers=headers,
    )
    assert resp.status_code == 200

    assert (await client.delete("/passwords/site", headers=headers)).status_code == 200
    assert (await client.get("/passwords/site", headers=headers)).status_code == 404
    trash = (await client.get("/passwords/trash", headers=headers)).json()
    assert [t["password_name"] for t in trash] == ["site"]
    assert trash[0]["attachment_count"] == 1

    resp = await client.post("/passwords/site/restore", headers=headers)
    assert resp.status_code == 200
    listing = await client.get("/passwords/site/attachments", headers=headers)
    assert len(listing.json()) == 1

    await client.delete("/passwords/site", headers=headers)
    resp = await client.post(
        "/passwords/create", json=entry("site", "replacement-1"), headers=headers
    )
    assert resp.status_code == 200
    resp = await client.post("/passwords/site/restore", headers=headers)
    assert resp.status_code == 400

    resp = await client.delete("/passwords/site/purge", headers=headers)
    assert resp.status_code == 200
    assert await db_execute("SELECT id FROM attachments") == []
    assert (await _get(client, key, "site"))["password_value"] == "replacement-1"
    resp = await client.get("/passwords/trash", headers=headers)
    assert resp.json() == []


async def test_attachments(client: httpx.AsyncClient) -> None:
    key = await create_vault(client)
    headers = auth(key)
    await client.post("/passwords/create", json=entry("docs"), headers=headers)

    resp = await client.post(
        "/passwords/docs/attachments",
        files={"file": ("Preț.pdf", b"%PDF-\x00\xff", "application/pdf")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    att = resp.json()
    assert att["filename"] == "Preț.pdf"

    download = await client.get(
        f"/passwords/docs/attachments/{att['id']}", headers=headers
    )
    assert download.content == b"%PDF-\x00\xff"
    assert download.headers["content-type"] == "application/pdf"
    assert "filename*=UTF-8''Pre%C8%9B.pdf" in download.headers["content-disposition"]

    resp = await client.post(
        "/passwords/docs/attachments",
        files={"file": ("empty.txt", b"", "text/plain")},
        headers=headers,
    )
    assert resp.status_code == 400

    resp = await client.delete(
        f"/passwords/docs/attachments/{att['id']}", headers=headers
    )
    assert resp.status_code == 200
    listing = await client.get("/passwords/docs/attachments", headers=headers)
    assert listing.json() == []


async def test_csv_import_skip_and_overwrite(client: httpx.AsyncClient) -> None:
    key = await create_vault(client)
    headers = auth(key)
    await client.post("/passwords/create", json=entry("mail", "old-1"), headers=headers)
    csv_bytes = (
        "﻿Title,Login,Password,Website,Notes,Folder,TOTP\n"
        "mail,me,new-1,https://mail.test,hello,Personal,JBSWY3DPEHPK3PXP\n"
        "shop,me,shop-1,,,,\n"
    ).encode()

    resp = await client.post(
        "/passwords/import/csv",
        data={"on_conflict": "skip"},
        files={"file": ("x.csv", csv_bytes, "text/csv")},
        headers=headers,
    )
    assert resp.json() == {
        "imported": 1,
        "skipped": 1,
        "overwritten": 0,
        "total": 2,
        "ignored": 0,
        "ignored_rows": [],
        "renamed": 0,
        "renamed_rows": [],
        "trashed": 0,
        "attachments": 0,
        "settings_restored": False,
    }
    assert (await _get(client, key, "mail"))["password_value"] == "old-1"

    resp = await client.post(
        "/passwords/import/csv",
        data={"on_conflict": "overwrite"},
        files={"file": ("x.csv", csv_bytes, "text/csv")},
        headers=headers,
    )
    assert resp.json()["overwritten"] == 2
    mail = await _get(client, key, "mail")
    assert mail["password_value"] == "new-1"
    assert mail["folder"] == "Personal"
    assert mail["totp_secret"] == "JBSWY3DPEHPK3PXP"


async def test_backup_export_and_restore_into_a_fresh_vault(
    client: httpx.AsyncClient,
) -> None:
    key = await create_vault(client)
    headers = auth(key)
    for item in (FULL_LOGIN, NOTE):
        await client.post("/passwords/create", json=item, headers=headers)

    resp = await client.post(
        "/passwords/backup",
        json={"master_password": WRONG_MASTER_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 403
    resp = await client.post(
        "/passwords/backup", json={"master_password": MASTER_PASSWORD}, headers=headers
    )
    assert resp.status_code == 200
    archive = resp.content
    assert archive.startswith(b"CMBACKUP")
    for secret in (b"GitHub #work", "Wi-Fi ключ".encode(), b"ciphermoth-backup"):
        assert secret not in archive
    exported = await client.get("/passwords", headers=headers)

    await reset_vault()
    new_key = await create_vault(client)
    assert new_key != key
    resp = await client.post(
        "/passwords/import",
        data={"master_password": WRONG_MASTER_PASSWORD},
        files={"file": ("b.cmbackup", archive, "application/octet-stream")},
        headers=auth(new_key),
    )
    assert resp.status_code == 403
    resp = await client.post(
        "/passwords/import",
        data={"master_password": MASTER_PASSWORD},
        files={"file": ("b.cmbackup", archive, "application/octet-stream")},
        headers=auth(new_key),
    )
    assert resp.json()["imported"] == 2
    restored = await client.get("/passwords", headers=auth(new_key))
    fields = ("password_name", "kind", "username", "password_value", "url")
    fields += ("totp_secret", "description", "tags", "custom_fields", "folder")
    assert [{f: p[f] for f in fields} for p in restored.json()] == [
        {f: p[f] for f in fields} for p in exported.json()
    ]

    legacy = legacy_backup_zip(
        [{"name": "legacy", "value": "v1-backup", "description": "old format"}],
        MASTER_PASSWORD,
    )
    resp = await client.post(
        "/passwords/import",
        data={"master_password": MASTER_PASSWORD},
        files={"file": ("old.zip", legacy, "application/zip")},
        headers=auth(new_key),
    )
    assert resp.json()["imported"] == 1


async def test_settings_round_trip_and_validation(client: httpx.AsyncClient) -> None:
    key = await create_vault(client)
    headers = auth(key)
    defaults = (await client.get("/settings", headers=headers)).json()
    assert defaults["inactivity_ms"] == 120_000
    changed = {**defaults, "clipboard_clear_ms": 10_000, "update_check_enabled": False}
    resp = await client.patch("/settings", json=changed, headers=headers)
    assert resp.json() == changed
    resp = await client.patch(
        "/settings", json={**changed, "inactivity_ms": 1}, headers=headers
    )
    assert resp.status_code == 422
    assert (await client.get("/settings", headers=headers)).json() == changed


async def test_writes_are_committed_before_the_response(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await create_vault(client)

    async def failing_commit(self) -> None:
        raise RuntimeError("commit failed")

    monkeypatch.setattr("sqlalchemy.ext.asyncio.AsyncSession.commit", failing_commit)
    resp = await client.post(
        "/passwords/create", json=entry("never-saved"), headers=auth(key)
    )
    monkeypatch.undo()

    assert resp.status_code == 500
    assert await db_execute("SELECT id FROM entries") == []
