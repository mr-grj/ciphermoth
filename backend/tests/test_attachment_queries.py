import httpx
import pytest
from sqlalchemy import Connection, event, inspect
from sqlalchemy.orm import Session

from models import AttachmentModel
from tests.support import auth, create_vault, db_execute, engine, entry


async def test_attachment_listing_does_not_load_file_contents(
    client: httpx.AsyncClient,
) -> None:
    headers = auth(await create_vault(client))
    await client.post("/passwords/create", headers=headers, json=entry("files"))
    contents = b"synthetic-file-body" * 1024
    for name in ("first.bin", "second.bin"):
        response = await client.post(
            "/passwords/files/attachments",
            headers=headers,
            files={"file": (name, contents, "application/octet-stream")},
        )
        assert response.status_code == 200

    loaded_contents: list[bool] = []

    def attachment_loaded(_session: Session, instance: object) -> None:
        if isinstance(instance, AttachmentModel):
            loaded_contents.append("content" not in inspect(instance).unloaded)

    event.listen(Session, "loaded_as_persistent", attachment_loaded)
    try:
        listed = await client.get("/passwords/files/attachments", headers=headers)
    finally:
        event.remove(Session, "loaded_as_persistent", attachment_loaded)
    assert listed.status_code == 200
    assert [item["filename"] for item in listed.json()] == ["first.bin", "second.bin"]
    assert loaded_contents == [False, False]
    for item in listed.json():
        downloaded = await client.get(
            f"/passwords/files/attachments/{item['id']}", headers=headers
        )
        assert downloaded.status_code == 200
        assert downloaded.content == contents


@pytest.mark.parametrize("attachment_count", [1, 60])
async def test_damage_scan_uses_a_bounded_number_of_queries(
    client: httpx.AsyncClient, attachment_count: int
) -> None:
    headers = auth(await create_vault(client))
    ids = []
    for number in range(attachment_count):
        name = f"files-{number // 20}"
        if number % 20 == 0:
            created = await client.post(
                "/passwords/create", headers=headers, json=entry(name)
            )
            assert created.status_code == 200
        uploaded = await client.post(
            f"/passwords/{name}/attachments",
            headers=headers,
            files={"file": ("test.txt", b"synthetic content", "text/plain")},
        )
        assert uploaded.status_code == 200
        ids.append(uploaded.json()["id"])
    await db_execute(
        "UPDATE attachments SET content = :broken WHERE id = :id",
        broken=b"broken",
        id=ids[-1],
    )
    selects = 0

    def count_selects(
        _connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        nonlocal selects
        if statement.lstrip().upper().startswith("SELECT"):
            selects += 1

    event.listen(engine.sync_engine, "before_cursor_execute", count_selects)
    try:
        response = await client.get("/vault/damaged", headers=headers)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count_selects)
    assert response.status_code == 200
    assert response.json() == {"entries": [], "attachments": [ids[-1]]}
    # Leave room for fixed authorization work, but no query per file or parent.
    assert selects <= 8
