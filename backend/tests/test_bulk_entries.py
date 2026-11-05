"""Moving several entries to the trash, restoring and purging them together."""

import json

import httpx

from tests.support import (
    Headers,
    auth,
    create_vault,
    db_execute,
    db_snapshot,
    entry,
    plant_entry,
    read_current_vault,
)


async def _vault(client: httpx.AsyncClient, *names: str) -> Headers:
    headers = auth(await create_vault(client))
    for name in names:
        resp = await client.post("/passwords/create", json=entry(name), headers=headers)
        assert resp.status_code == 200, resp.text
    return headers


async def _names(client: httpx.AsyncClient, headers: Headers, path: str) -> list[str]:
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    return sorted(row["password_name"] for row in resp.json())


async def _trash(client: httpx.AsyncClient, headers: Headers, *names: str):
    return await client.post(
        "/vault/entries/trash",
        json={"entries": [{"password_name": n} for n in names]},
        headers=headers,
    )


async def _refs(client: httpx.AsyncClient, headers: Headers) -> list[dict]:
    rows = (await client.get("/passwords/trash", headers=headers)).json()
    return [{"password_name": r["password_name"], "entry_id": r["id"]} for r in rows]


async def test_trashing_several_entries_moves_exactly_those(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b", "c", "a/b", "x/purge")
    resp = await _trash(client, headers, "a", "a/b", "x/purge")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"count": 3, "detail": "3 entries moved to trash."}
    assert await _names(client, headers, "/passwords") == ["b", "c"]
    assert await _names(client, headers, "/passwords/trash") == ["a", "a/b", "x/purge"]


async def test_one_missing_entry_trashes_nothing(client: httpx.AsyncClient) -> None:
    headers = await _vault(client, "a", "b")
    before = await db_snapshot()
    resp = await _trash(client, headers, "a", "missing", "b")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "No password found for 'missing' in the vault."
    assert await db_snapshot() == before


async def test_bulk_requests_are_validated(client: httpx.AsyncClient) -> None:
    headers = await _vault(client, "a")
    before = await db_snapshot()
    for body in (
        {"entries": []},
        {"entries": [{"password_name": "a"}, {"password_name": "a"}]},
        {"entries": [{"password_name": ""}]},
        {"entries": [{"password_name": "a\x00"}]},
        {"names": ["a"]},
    ):
        resp = await client.post("/vault/entries/trash", json=body, headers=headers)
        assert resp.status_code in (400, 422), (body, resp.text)
    resp = await client.post(
        "/vault/trash/purge",
        json={"entries": [{"password_name": "a", "entry_id": 0}]},
        headers=headers,
    )
    assert resp.status_code == 422
    assert await db_snapshot() == before


async def test_restoring_several_entries(client: httpx.AsyncClient) -> None:
    headers = await _vault(client, "a", "b", "c")
    await _trash(client, headers, "a", "b", "c")
    refs = [r for r in await _refs(client, headers) if r["password_name"] != "c"]
    resp = await client.post(
        "/vault/trash/restore", json={"entries": refs}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["detail"] == "2 entries restored."
    assert await _names(client, headers, "/passwords") == ["a", "b"]
    assert await _names(client, headers, "/passwords/trash") == ["c"]


async def test_restore_refuses_a_taken_name_and_changes_nothing(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b")
    await _trash(client, headers, "a", "b")
    resp = await client.post("/passwords/create", json=entry("b"), headers=headers)
    assert resp.status_code == 200
    before = await db_snapshot()
    resp = await client.post(
        "/vault/trash/restore",
        json={"entries": await _refs(client, headers)},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "An active password named 'b' already exists." in resp.json()["detail"]
    assert await db_snapshot() == before


async def test_restore_refuses_two_trashed_copies_of_one_name(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "dup")
    await _trash(client, headers, "dup")
    await client.post("/passwords/create", json=entry("dup"), headers=headers)
    await _trash(client, headers, "dup")
    refs = await _refs(client, headers)
    assert len(refs) == 2
    before = await db_snapshot()
    resp = await client.post(
        "/vault/trash/restore", json={"entries": refs}, headers=headers
    )
    assert resp.status_code == 400
    assert "More than one selected entry is named 'dup'." in resp.json()["detail"]
    assert await db_snapshot() == before
    resp = await client.post(
        "/vault/trash/restore", json={"entries": refs[:1]}, headers=headers
    )
    assert resp.status_code == 200, resp.text


async def test_purging_several_entries_takes_their_attachments(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b", "keep")
    resp = await client.post(
        "/passwords/a/attachments",
        files={"file": ("a.txt", b"attached", "text/plain")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    await _trash(client, headers, "a", "b", "keep")
    refs = [r for r in await _refs(client, headers) if r["password_name"] != "keep"]
    resp = await client.post(
        "/vault/trash/purge", json={"entries": refs}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"count": 2, "detail": "2 entries permanently deleted."}
    assert await _names(client, headers, "/passwords/trash") == ["keep"]
    snapshot = await db_snapshot()
    assert len(snapshot["entries"]) == 1
    assert snapshot["attachments"] == []


async def test_purge_never_reaches_an_active_entry_or_a_wrong_name(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "active", "gone")
    await _trash(client, headers, "gone")
    active_id = (await client.get("/passwords/active", headers=headers)).json()["id"]
    gone = (await _refs(client, headers))[0]
    before = await db_snapshot()
    for entries in (
        [gone, {"password_name": "active", "entry_id": active_id}],
        [{"password_name": "active", "entry_id": gone["entry_id"]}],
    ):
        resp = await client.post(
            "/vault/trash/purge", json={"entries": entries}, headers=headers
        )
        assert resp.status_code == 404, resp.text
    assert await db_snapshot() == before


async def _move(client: httpx.AsyncClient, headers: Headers, folder, *names: str):
    return await client.post(
        "/vault/entries/move",
        json={"entries": [{"password_name": n} for n in names], "folder": folder},
        headers=headers,
    )


async def _folders(client: httpx.AsyncClient, headers: Headers) -> dict[str, object]:
    rows = (await client.get("/passwords", headers=headers)).json()
    return {row["password_name"]: row["folder"] for row in rows}


async def test_moving_several_entries_moves_exactly_those(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b", "c", "a/b")
    resp = await _move(client, headers, "Work", "a", "a/b")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "count": 2,
        "unchanged": 0,
        "detail": "2 entries moved to 'Work'.",
    }
    assert await _folders(client, headers) == {
        "a": "Work",
        "a/b": "Work",
        "b": None,
        "c": None,
    }
    await read_current_vault()


async def test_a_move_keeps_everything_else_about_the_entry(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    full = entry(
        "full",
        username="me@example.com",
        url="https://example.com",
        totp_secret="JBSWY3DPEHPK3PXP",
        description="notes",
        tags=["x", "y"],
        custom_fields=[{"label": "PIN", "value": "1234", "hidden": True}],
        folder="Old",
        favorite=True,
    )
    assert (
        await client.post("/passwords/create", json=full, headers=headers)
    ).is_success
    changed = {
        "password": full,
        "new_password": {**full, "password_value": "new-Va1ue!"},
    }
    assert (
        await client.patch("/passwords/update", json=changed, headers=headers)
    ).is_success
    resp = await client.post(
        "/passwords/full/attachments",
        files={"file": ("a.txt", b"attached", "text/plain")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    attachment_id = resp.json()["id"]
    before = (await client.get("/passwords/full", headers=headers)).json()

    resp = await _move(client, headers, "New", "full")
    assert resp.status_code == 200, resp.text

    after = (await client.get("/passwords/full", headers=headers)).json()
    assert after.pop("folder") == "New"
    assert before.pop("folder") == "Old"
    assert after.pop("updated") >= before.pop("updated")
    assert after == before
    resp = await client.get(
        f"/passwords/full/attachments/{attachment_id}", headers=headers
    )
    assert resp.content == b"attached"
    await read_current_vault()


async def test_null_takes_entries_out_of_their_folder(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    for name, folder in (("a", "Work"), ("b", "Home"), ("c", None)):
        resp = await client.post(
            "/passwords/create", json=entry(name, folder=folder), headers=headers
        )
        assert resp.status_code == 200, resp.text
    resp = await _move(client, headers, None, "a", "b", "c")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "count": 2,
        "unchanged": 1,
        "detail": "2 entries taken out of their folder. 1 entry already there.",
    }
    assert await _folders(client, headers) == {"a": None, "b": None, "c": None}


async def test_entries_already_in_the_folder_are_left_untouched(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    for name, folder in (("in", "Work"), ("out", None)):
        resp = await client.post(
            "/passwords/create", json=entry(name, folder=folder), headers=headers
        )
        assert resp.status_code == 200, resp.text
    await db_execute("UPDATE entries SET backed_up = 1")
    before = {row[0]: row for row in (await db_snapshot())["entries"]}

    resp = await _move(client, headers, "Work", "in", "out")
    assert resp.status_code == 200, resp.text
    assert resp.json()["count"] == 1
    assert resp.json()["unchanged"] == 1

    after = {row[0]: row for row in (await db_snapshot())["entries"]}
    rows = {
        r["password_name"]: r
        for r in (await client.get("/passwords", headers=headers)).json()
    }
    untouched, moved = rows["in"]["id"], rows["out"]["id"]
    assert after[untouched] == before[untouched]
    assert after[moved] != before[moved]
    assert rows["in"]["backed_up"] is True
    # The folder is part of what a restore brings back, so moving is an edit.
    assert rows["out"]["backed_up"] is False

    before = await db_snapshot()
    resp = await _move(client, headers, "Work", "in", "out")
    assert resp.json() == {
        "count": 0,
        "unchanged": 2,
        "detail": "0 entries moved to 'Work'. 2 entries already there.",
    }
    assert await db_snapshot() == before


async def test_folder_names_are_trimmed_and_otherwise_kept_exactly(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b", "c", "d")
    longest = "F" * 200
    for folder, stored in (
        ("  Work  ", "Work"),
        ("work", "work"),
        ("Personal / Banking", "Personal / Banking"),
        ("🦋 Секреты", "🦋 Секреты"),
        (f"  {longest}\t", longest),
    ):
        resp = await _move(client, headers, folder, "a")
        assert resp.status_code == 200, (folder, resp.text)
        assert (await _folders(client, headers))["a"] == stored
    await _move(client, headers, "Work", "b")
    await _move(client, headers, "work", "c")
    folders = await _folders(client, headers)
    assert (folders["b"], folders["c"]) == ("Work", "work")


async def test_empty_or_oversized_folder_names_move_nothing(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a")
    before = await db_snapshot()
    for folder in ("", "   ", "\t\n", "F" * 201, " " + "F" * 201, "\ud800"):
        resp = await client.post(
            "/vault/entries/move",
            content=json.dumps({"entries": [{"password_name": "a"}], "folder": folder}),
            headers=[*headers, (b"content-type", b"application/json")],
        )
        assert resp.status_code == 422, (folder, resp.text)
    resp = await _move(client, headers, " ", "a")
    assert "Folder name can't be empty." in resp.text
    for body in (
        {"entries": [{"password_name": "a"}]},
        {"entries": [{"password_name": "a"}], "folder": 3},
        {"entries": [{"password_name": "a"}], "folder": ["Work"]},
        {"entries": [], "folder": "Work"},
        {"entries": [{"password_name": "a"}, {"password_name": "a"}], "folder": "W"},
        {"entries": [{"password_name": ""}], "folder": "Work"},
    ):
        resp = await client.post("/vault/entries/move", json=body, headers=headers)
        assert resp.status_code == 422, (body, resp.text)
    assert await db_snapshot() == before


async def test_one_missing_or_trashed_entry_moves_nothing(
    client: httpx.AsyncClient,
) -> None:
    headers = await _vault(client, "a", "b", "gone")
    await _trash(client, headers, "gone")
    before = await db_snapshot()
    for names, missing in ((("a", "missing", "b"), "missing"), (("a", "gone"), "gone")):
        resp = await _move(client, headers, "Work", *names)
        assert resp.status_code == 404, resp.text
        assert (
            resp.json()["detail"] == f"No password found for '{missing}' in the vault."
        )
    assert await db_snapshot() == before


async def test_a_damaged_entry_moves_nothing(client: httpx.AsyncClient) -> None:
    headers = await _vault(client, "a")
    await plant_entry("broken", folder=7)
    before = await db_snapshot()
    resp = await _move(client, headers, "Work", "a", "broken")
    assert resp.status_code == 500, resp.text
    assert resp.json()["code"] == "vault_damaged"
    assert await db_snapshot() == before
