"""Moving several entries to the trash, restoring and purging them together."""

import httpx

from tests.support import Headers, auth, create_vault, db_snapshot, entry


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
