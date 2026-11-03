from collections.abc import Awaitable, Callable

import httpx
import pytest

from main import app
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    Headers,
    auth,
    create_vault,
    db_snapshot,
    entry,
    forged_keys,
    forged_tokens,
    legacy_backup_zip,
    retired_key_header,
    stored_vault_key,
    unlock,
)

Spec = Callable[[httpx.AsyncClient, Headers, dict], Awaitable[httpx.Response]]

PUBLIC_ROUTES = {
    ("GET", "/api/master_password/status"),
    ("POST", "/api/master_password/unlock"),
    ("POST", "/api/master_password/lock"),
    ("POST", "/api/master_password/create"),
    ("GET", "/api/master_password/device-unlock"),
    ("POST", "/api/master_password/device-unlock/unlock"),
    ("GET", "/api/meta"),
    ("GET", "/api/health"),
}

SETTINGS_BODY = {
    "inactivity_ms": 300_000,
    "warn_before_ms": 30_000,
    "hidden_ms": 120_000,
    "debounce_ms": 500,
    "clipboard_clear_ms": 15_000,
    "update_check_enabled": False,
}

CSV_BODY = b"name,username,password,url\ncsv-entry,someone,csv-Pass-1,https://x.test\n"


def _alpha() -> dict:
    return entry("alpha", username="moth@example.com")


PROTECTED_ROUTES: dict[tuple[str, str], Spec] = {
    ("GET", "/api/master_password/session"): lambda c, h, x: c.get(
        "/master_password/session", headers=h
    ),
    ("POST", "/api/master_password/session"): lambda c, h, x: c.post(
        "/master_password/session", headers=h
    ),
    ("GET", "/api/passwords"): lambda c, h, x: c.get("/passwords", headers=h),
    ("GET", "/api/passwords/trash"): lambda c, h, x: c.get(
        "/passwords/trash", headers=h
    ),
    ("GET", "/api/passwords/{password_name}"): lambda c, h, x: c.get(
        "/passwords/alpha", headers=h
    ),
    ("POST", "/api/passwords/create"): lambda c, h, x: c.post(
        "/passwords/create", json=entry("delta"), headers=h
    ),
    ("PATCH", "/api/passwords/update"): lambda c, h, x: c.patch(
        "/passwords/update",
        json={"password": _alpha(), "new_password": {**_alpha(), "url": "x.test"}},
        headers=h,
    ),
    ("PATCH", "/api/passwords/{password_name}/favorite"): lambda c, h, x: c.patch(
        "/passwords/alpha/favorite", json={"favorite": True}, headers=h
    ),
    ("DELETE", "/api/passwords/{password_name}"): lambda c, h, x: c.delete(
        "/passwords/alpha", headers=h
    ),
    ("POST", "/api/passwords/{password_name}/restore"): lambda c, h, x: c.post(
        "/passwords/beta/restore", headers=h
    ),
    ("DELETE", "/api/passwords/{password_name}/purge"): lambda c, h, x: c.delete(
        "/passwords/beta/purge", headers=h
    ),
    ("GET", "/api/passwords/{password_name}/attachments"): lambda c, h, x: c.get(
        "/passwords/alpha/attachments", headers=h
    ),
    ("POST", "/api/passwords/{password_name}/attachments"): lambda c, h, x: c.post(
        "/passwords/alpha/attachments",
        files={"file": ("new.bin", b"\x00\x01payload", "application/octet-stream")},
        headers=h,
    ),
    (
        "GET",
        "/api/passwords/{password_name}/attachments/{attachment_id}",
    ): lambda c, h, x: c.get(
        f"/passwords/alpha/attachments/{x['attachment_id']}", headers=h
    ),
    (
        "DELETE",
        "/api/passwords/{password_name}/attachments/{attachment_id}",
    ): lambda c, h, x: c.delete(
        f"/passwords/alpha/attachments/{x['attachment_id']}", headers=h
    ),
    ("POST", "/api/passwords/import"): lambda c, h, x: c.post(
        "/passwords/import",
        data={"master_password": MASTER_PASSWORD, "on_conflict": "overwrite"},
        files={"file": ("backup.zip", x["backup_zip"], "application/zip")},
        headers=h,
    ),
    ("POST", "/api/passwords/import/csv"): lambda c, h, x: c.post(
        "/passwords/import/csv",
        data={"on_conflict": "overwrite"},
        files={"file": ("export.csv", CSV_BODY, "text/csv")},
        headers=h,
    ),
    ("POST", "/api/passwords/backup"): lambda c, h, x: c.post(
        "/passwords/backup", json={"master_password": MASTER_PASSWORD}, headers=h
    ),
    ("GET", "/api/settings"): lambda c, h, x: c.get("/settings", headers=h),
    ("PATCH", "/api/settings"): lambda c, h, x: c.patch(
        "/settings", json=SETTINGS_BODY, headers=h
    ),
    ("GET", "/api/vault/damaged"): lambda c, h, x: c.get("/vault/damaged", headers=h),
    ("POST", "/api/vault/entries/trash"): lambda c, h, x: c.post(
        "/vault/entries/trash",
        json={"entries": [{"password_name": "alpha"}]},
        headers=h,
    ),
    ("POST", "/api/vault/trash/restore"): lambda c, h, x: c.post(
        "/vault/trash/restore",
        json={"entries": [{"password_name": "beta", "entry_id": x["beta_id"]}]},
        headers=h,
    ),
    ("POST", "/api/vault/trash/purge"): lambda c, h, x: c.post(
        "/vault/trash/purge",
        json={"entries": [{"password_name": "beta", "entry_id": x["beta_id"]}]},
        headers=h,
    ),
    ("DELETE", "/api/vault/damaged/{kind}/{row_id}"): lambda c, h, x: c.delete(
        "/vault/damaged/entries/1", headers=h
    ),
    ("POST", "/api/master_password/device-unlock/enroll"): lambda c, h, x: c.post(
        "/master_password/device-unlock/enroll",
        json={
            "master_password": MASTER_PASSWORD,
            "credential_id": "matrix-device",
            "kind": "passkey",
            "material": "c2FsdA",
            "secret": "A" * 43,
        },
        headers=h,
    ),
    ("PATCH", "/api/master_password/device-unlock"): lambda c, h, x: c.patch(
        "/master_password/device-unlock",
        json={"password_interval_days": 30},
        headers=h,
    ),
    ("DELETE", "/api/master_password/device-unlock/{credential_id}"): (
        lambda c, h, x: c.delete(
            "/master_password/device-unlock/matrix-device", headers=h
        )
    ),
    ("PATCH", "/api/master_password/update"): lambda c, h, x: c.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=h,
    ),
}

ROUTE_IDS = [f"{method} {path}" for method, path in PROTECTED_ROUTES]
REACHED = {("DELETE", "/api/vault/damaged/{kind}/{row_id}"): 400}


async def seed(client: httpx.AsyncClient, headers: Headers) -> dict:
    for item in (
        _alpha(),
        entry("beta"),
        entry("gamma", "note body\n", kind="note"),
    ):
        resp = await client.post("/passwords/create", json=item, headers=headers)
        assert resp.status_code == 200, resp.text
    resp = await client.post(
        "/passwords/alpha/attachments",
        files={"file": ("doc.bin", b"\x00\xffbinary", "application/octet-stream")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    attachment_id = resp.json()["id"]
    resp = await client.delete("/passwords/beta", headers=headers)
    assert resp.status_code == 200, resp.text
    await client.get("/settings", headers=headers)
    backup_zip = legacy_backup_zip(
        [{"name": "from-backup", "value": "restored-Value-1"}], MASTER_PASSWORD
    )
    trash = await client.get("/passwords/trash", headers=headers)
    return {
        "attachment_id": attachment_id,
        "backup_zip": backup_zip,
        "beta_id": trash.json()[0]["id"],
    }


def _expected_rejection(headers: Headers) -> tuple[int, str]:
    names = {name.lower() for name, _ in headers}
    if b"x-ciphermoth-key-derivation" in names:
        return 403, "invalid_key"
    return 401, "invalid_session"


async def _assert_rejected_without_side_effects(
    client: httpx.AsyncClient,
    spec: Spec,
    ctx: dict,
    credentials: dict[str, Headers],
    *,
    expect_code: bool = True,
) -> None:
    before = await db_snapshot()
    for label, headers in credentials.items():
        resp = await spec(client, headers, ctx)
        status, code = _expected_rejection(headers)
        if expect_code:
            assert resp.status_code == status, (
                f"{label}: {resp.status_code} {resp.text}"
            )
            assert resp.json().get("code") == code, label
        else:
            assert resp.status_code in (401, 403), f"{label}: {resp.text}"
        assert await db_snapshot() == before, f"{label} changed the database"


def _as_key_headers(keys: dict[str, str | bytes | None]) -> dict[str, Headers]:
    return {
        label: retired_key_header(key) for label, key in keys.items() if key is not None
    }


def test_every_api_route_is_classified() -> None:
    routes = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        if path.startswith("/api")
        for method in operations
    }
    assert routes == PUBLIC_ROUTES | set(PROTECTED_ROUTES)


@pytest.mark.parametrize("route", list(PROTECTED_ROUTES), ids=ROUTE_IDS)
async def test_forged_session_tokens_are_rejected(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await seed(client, auth(token))
    spec = PROTECTED_ROUTES[route]
    key = await stored_vault_key()

    await _assert_rejected_without_side_effects(
        client, spec, ctx, await forged_tokens(client, token, key)
    )

    resp = await spec(client, auth(token), ctx)
    assert resp.status_code == REACHED.get(route, 200), resp.text


@pytest.mark.parametrize("route", list(PROTECTED_ROUTES), ids=ROUTE_IDS)
async def test_the_vault_key_is_never_accepted_as_a_credential(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await seed(client, auth(token))
    spec = PROTECTED_ROUTES[route]
    key = await stored_vault_key()
    keys = {"real key": key, **forged_keys(key)}
    credentials = {
        **_as_key_headers(keys),
        **{
            f"open session and {label}": auth(token) + headers
            for label, headers in _as_key_headers(keys).items()
        },
        "open session and key header first": retired_key_header(key) + auth(token),
        "key header in capitals": [(b"X-CipherMoth-Key-Derivation", key.encode())],
    }

    await _assert_rejected_without_side_effects(client, spec, ctx, credentials)

    resp = await spec(client, auth(token), ctx)
    assert resp.status_code == REACHED.get(route, 200), resp.text


@pytest.mark.parametrize("route", list(PROTECTED_ROUTES), ids=ROUTE_IDS)
async def test_sessions_and_keys_from_before_a_rotation_are_rejected(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await seed(client, auth(token))
    other = await unlock(client)
    old_key = await stored_vault_key()
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text

    spec = PROTECTED_ROUTES[route]
    await _assert_rejected_without_side_effects(
        client,
        spec,
        ctx,
        {
            "rotating session": auth(token),
            "other session": auth(other),
            "stale key": retired_key_header(old_key),
        },
    )


@pytest.mark.parametrize("route", list(PROTECTED_ROUTES), ids=ROUTE_IDS)
async def test_uninitialized_vault_rejects_everything(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    ctx = {"attachment_id": 1, "backup_zip": b"PK", "beta_id": 1}
    credentials = {
        **_as_key_headers(forged_keys("A" * 43 + "=")),
        "random token": auth("A" * 43),
    }
    await _assert_rejected_without_side_effects(
        client, PROTECTED_ROUTES[route], ctx, credentials, expect_code=False
    )
