"""
Browser extension sessions and routes (docs/EXTENSION.md): session lifecycle,
unlock, the handoff, matching, credentials and 2FA codes, what never leaves
the server, read transactions, logs and speed. The authorization matrix lives
in test_extension_authz.py.
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

import crud.extension
import helpers
from api.rate_limit import limiter
from crud.engine import Database
from main import app, get_application
from tests.authenticator import SoftKey
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    add_security_key,
    auth,
    create_recovery_code,
    create_vault,
    data_dir,
    db_execute,
    db_snapshot,
    entry,
    fresh_vault_sessions,
    plant_entry,
    stored_vault_key,
    unlock,
    vault_key,
    write_lock_held,
)
from tests.test_rotation_races import FirstDerivationWaits
from tests.test_sessions import FakeClock
from vault_sessions import (
    EXPIRY_TOLERANCE_MS,
    MAX_LIFETIME_MS,
    Scope,
    VaultSessions,
)

GITHUB = "https://github.com"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
NOTE_BODY = "note-canary-7f3a: the safe is behind the moth painting"
HISTORY_VALUE = "old-password-canary-19bd"
DESCRIPTION = "description-canary-5c21"
FIELD_VALUE = "custom-field-canary-0e7d"


@pytest.fixture
def app_clock() -> Iterator[FakeClock]:
    fake = FakeClock()
    app.state.vault_sessions = fresh_vault_sessions(fake)
    yield fake


def sessions() -> VaultSessions:
    return app.state.vault_sessions


async def extension_unlock(
    client: httpx.AsyncClient, master_password: str = MASTER_PASSWORD
) -> str:
    resp = await client.post(
        "/extension/unlock",
        json={"master_password": master_password, "browser": "Firefox"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True
    return resp.json()["session_token"]


async def populated(client: httpx.AsyncClient) -> str:
    token = await create_vault(client)
    for item in (
        entry(
            "GitHub",
            "gh-Secret-1",
            username="moth@example.com",
            url="https://github.com/login",
            totp_secret=TOTP_SECRET,
            description=DESCRIPTION,
            custom_fields=[{"label": "PIN", "value": FIELD_VALUE, "hidden": True}],
        ),
        entry("GitHub (work)", "gh-Work-2", username="work@example.com", url=GITHUB),
        entry("Zebra GitHub", "gh-Zebra-3", url="github.com", favorite=True),
        entry("GitLab", "gl-Secret-4", username="moth", url="https://gitlab.com"),
        entry("Insecure", "http-Secret-5", url="http://intranet.test"),
        entry("Subdomain", "sub-Secret-6", url="example.com"),
        entry("No URL", "nourl-Secret-7"),
        entry("Notes on GitHub", NOTE_BODY, kind="note", url=GITHUB),
        entry("Trashed GitHub", "trash-Secret-8", url=GITHUB),
    ):
        resp = await client.post("/passwords/create", json=item, headers=auth(token))
        assert resp.status_code == 200, resp.text
    resp = await client.patch(
        "/passwords/update",
        json={
            "password": {"password_name": "GitLab"},
            "new_password": entry(
                "GitLab", "gl-Secret-4b", username="moth", url="https://gitlab.com"
            ),
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    resp = await client.patch(
        "/passwords/update",
        json={
            "password": {"password_name": "GitLab"},
            "new_password": entry(
                "GitLab", "gl-Secret-4c", username="moth", url="https://gitlab.com"
            ),
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    resp = await client.delete("/passwords/Trashed%20GitHub", headers=auth(token))
    assert resp.status_code == 200, resp.text
    return token


async def ids_by_name(client: httpx.AsyncClient, token: str) -> dict[str, int]:
    resp = await client.get("/passwords", headers=auth(token))
    ids = {p["password_name"]: p["id"] for p in resp.json()}
    trash = await client.get("/passwords/trash", headers=auth(token))
    ids.update({p["password_name"]: p["id"] for p in trash.json()})
    return ids


async def post(
    client: httpx.AsyncClient, token: str, path: str, body: dict | None = None
) -> httpx.Response:
    return await client.post(f"/extension/{path}", json=body, headers=auth(token))


# --- session lifecycle ----------------------------------------------------


def test_extension_sessions_have_their_own_cap_and_never_evict_full_ones(
    app_clock: FakeClock,
) -> None:
    store = VaultSessions(
        idle_timeout_ms=60_000,
        max_sessions=3,
        max_extension_sessions=8,
        clock=app_clock,
    )
    key = helpers.VaultKey(b"k" * 32)
    full = [store.open(key) for _ in range(3)]
    extension = [store.open_extension(key, "Chrome")[0] for _ in range(20)]
    for token in full:
        assert store.resolve(token) is key
    live = [t for t in extension if _alive(store, t, Scope.EXTENSION)]
    assert live == extension[-8:]
    assert len(store.extension_sessions()) == 8
    store.open(key)
    assert len(store.extension_sessions()) == 8
    assert not _alive(store, full[0], Scope.FULL)


def _alive(store: VaultSessions, token: str, scope: Scope) -> bool:
    try:
        store.resolve(token, refresh=False, scope=scope)
    except Exception:
        return False
    return True


def test_extension_sessions_expire_like_full_ones(app_clock: FakeClock) -> None:
    store = VaultSessions(idle_timeout_ms=60_000, tolerance_ms=0, clock=app_clock)
    key = helpers.VaultKey(b"k" * 32)
    idle, _ = store.open_extension(key, "Chrome")
    busy, _ = store.open_extension(key, "Firefox")
    for _ in range(3):
        app_clock.advance(40_000)
        store.resolve(busy, scope=Scope.EXTENSION)
    assert not _alive(store, idle, Scope.EXTENSION)
    app_clock.advance(MAX_LIFETIME_MS)
    assert store.drop_expired() == 1
    assert not _alive(store, busy, Scope.EXTENSION)
    assert store.extension_sessions() == []


def test_the_sweeper_and_listing_drop_expired_extension_sessions(
    app_clock: FakeClock,
) -> None:
    store = VaultSessions(idle_timeout_ms=60_000, tolerance_ms=0, clock=app_clock)
    key = helpers.VaultKey(b"k" * 32)
    store.open_extension(key, "Chrome")
    assert len(store.extension_sessions()) == 1
    app_clock.advance(60_001)
    assert store.drop_expired() == 1
    assert len(store) == 0


CLIENT = "c" * 22
OTHER_CLIENT = "d" * 22


def test_one_session_per_extension_installation(app_clock: FakeClock) -> None:
    store = VaultSessions(idle_timeout_ms=60_000, clock=app_clock)
    key = helpers.VaultKey(b"k" * 32)
    full = store.open(key)
    first, _ = store.open_extension(key, "Chrome", CLIENT)
    other, _ = store.open_extension(key, "Chrome", OTHER_CLIENT)
    anonymous, _ = store.open_extension(key, "Chrome")
    second, handle = store.open_extension(key, "Chrome", CLIENT)
    assert not _alive(store, first, Scope.EXTENSION)
    for token in (other, anonymous, second):
        assert _alive(store, token, Scope.EXTENSION)
    assert _alive(store, full, Scope.FULL)
    assert len(store.extension_sessions()) == 3
    assert handle in {info.handle for info in store.extension_sessions()}
    # Sessions without an installation id never replace each other.
    store.open_extension(key, "Chrome")
    assert _alive(store, anonymous, Scope.EXTENSION)


async def test_a_new_unlock_or_handoff_replaces_the_installations_session(
    client: httpx.AsyncClient,
) -> None:
    token = await populated(client)
    tokens = []
    for _ in range(2):
        resp = await client.post(
            "/extension/unlock",
            json={"master_password": MASTER_PASSWORD, "client": CLIENT},
        )
        tokens.append(resp.json()["session_token"])
    resp = await client.post(
        "/extension/sessions",
        json={"browser": "Chrome", "client": CLIENT},
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    tokens.append(resp.json()["session_token"])
    assert [(await post(client, t, "session")).status_code for t in tokens] == [
        401,
        401,
        200,
    ]
    listed = (await client.get("/extension/sessions", headers=auth(token))).json()
    assert len(listed) == 1


@pytest.mark.parametrize("bad", ["short", "c" * 44, "c" * 21 + "!", 42])
async def test_installation_ids_are_validated(
    client: httpx.AsyncClient, bad: object
) -> None:
    token = await populated(client)
    resp = await client.post(
        "/extension/unlock", json={"master_password": MASTER_PASSWORD, "client": bad}
    )
    assert resp.status_code == 422
    resp = await client.post(
        "/extension/sessions",
        json={"browser": "Chrome", "client": bad},
        headers=auth(token),
    )
    assert resp.status_code == 422
    assert sessions().extension_sessions() == []


def test_listing_never_shows_tokens_and_handles_are_not_tokens(
    app_clock: FakeClock,
) -> None:
    store = VaultSessions(idle_timeout_ms=60_000, clock=app_clock)
    key = helpers.VaultKey(b"k" * 32)
    token, handle = store.open_extension(key, "Chrome")
    [info] = store.extension_sessions()
    assert info.handle == handle != token
    assert token not in repr(info)
    assert not store.revoke_extension(token)
    full = store.open(key)
    assert not store.revoke_extension(full)
    assert store.revoke_extension(handle)
    assert store.extension_sessions() == []
    assert store.resolve(full) is key


async def test_idle_extension_sessions_expire_on_the_server(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    await populated(client)
    idle = await extension_unlock(client)
    busy = await extension_unlock(client)
    for _ in range(3):
        app_clock.advance(50_000)
        resp = await post(client, busy, "matches", {"origin": GITHUB})
        assert resp.status_code == 200
    resp = await post(client, idle, "matches", {"origin": GITHUB})
    assert resp.status_code == 401
    assert resp.json()["code"] == "invalid_session"
    app_clock.advance(120_000 + EXPIRY_TOLERANCE_MS + 1)
    assert (await post(client, busy, "session")).status_code == 401


async def test_the_heartbeat_reports_the_vault_inactivity_setting(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await populated(client)
    resp = await client.patch(
        "/settings",
        json={
            "inactivity_ms": 600_000,
            "warn_before_ms": 30_000,
            "hidden_ms": 120_000,
            "debounce_ms": 500,
            "clipboard_clear_ms": 15_000,
            "update_check_enabled": False,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    extension = await extension_unlock(client)
    # The heartbeat is activity (the popup was opened), so it restarts the
    # timeout; status reads elsewhere do not.
    for _ in range(3):
        app_clock.advance(400_000)
        resp = await post(client, extension, "session")
        assert resp.status_code == 200
        assert resp.json() == {"idle_timeout_ms": 600_000, "expires_in_ms": 600_000}
    app_clock.advance(600_000 + EXPIRY_TOLERANCE_MS + 1)
    assert (await post(client, extension, "session")).status_code == 401


def test_extension_routes_declare_their_rate_limits() -> None:
    """The test environment raises every limit (CIPHERMOTH_RATE_LIMIT), so check
    the declarations and their defaults."""
    import inspect

    from api.endpoints import extension

    limited = set(limiter._route_limits)
    for route, default in (
        ("unlock", "30/hour"),
        ("connect", "10/hour"),
        ("credential", "300/hour"),
        ("totp", "300/hour"),
    ):
        assert f"api.endpoints.extension.{route}" in limited, route
        assert f'rate("{default}")' in inspect.getsource(getattr(extension, route))


@pytest.mark.parametrize("change", ["rotation", "recovery"])
async def test_master_password_changes_end_extension_sessions(
    client: httpx.AsyncClient, change: str
) -> None:
    token = await populated(client)
    code = await create_recovery_code(client, auth(token))
    unlocked = await extension_unlock(client)
    connected = (
        await client.post(
            "/extension/sessions", json={"browser": "Chrome"}, headers=auth(token)
        )
    ).json()["session_token"]
    if change == "rotation":
        resp = await client.patch(
            "/master_password/update",
            json={
                "master_password": MASTER_PASSWORD,
                "new_master_password": NEW_MASTER_PASSWORD,
            },
            headers=auth(token),
        )
    else:
        resp = await client.post(
            "/master_password/recover",
            json={
                "recovery_code": code,
                "new_master_password": NEW_MASTER_PASSWORD,
                "keep_security_keys": True,
            },
        )
    assert resp.status_code == 200, resp.text
    for extension in (unlocked, connected):
        assert (await post(client, extension, "session")).status_code == 401
    assert sessions().extension_sessions() == []


async def test_shutdown_ends_extension_sessions(tmp_path: Path) -> None:
    store = fresh_vault_sessions()
    other = get_application(database=Database(tmp_path), vault_sessions=store)
    async with other.router.lifespan_context(other):
        transport = httpx.ASGITransport(app=other)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver/api"
        ) as client:
            await populated(client)
            await extension_unlock(client)
            assert len(store.extension_sessions()) == 1
    assert len(store) == 0


async def test_locking_the_web_app_leaves_a_connected_extension_alone(
    client: httpx.AsyncClient,
) -> None:
    token = await populated(client)
    resp = await client.post(
        "/extension/sessions", json={"browser": "Chrome"}, headers=auth(token)
    )
    extension = resp.json()["session_token"]
    await client.post("/master_password/lock", headers=auth(token))
    assert (await post(client, extension, "session")).status_code == 200


# --- unlock ----------------------------------------------------------------


async def test_unlock_opens_an_extension_session_and_never_returns_the_key(
    client: httpx.AsyncClient,
) -> None:
    await populated(client)
    resp = await client.post(
        "/extension/unlock",
        json={"master_password": MASTER_PASSWORD, "browser": "Firefox"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"valid", "session_token", "idle_timeout_ms"}
    assert (await stored_vault_key()) not in resp.text
    [info] = sessions().extension_sessions()
    assert info.browser == "Firefox"
    resp = await client.get("/passwords", headers=auth(body["session_token"]))
    assert resp.status_code == 403
    assert resp.json()["code"] == "extension_scope"


async def test_a_wrong_password_opens_no_extension_session(
    client: httpx.AsyncClient,
) -> None:
    await populated(client)
    resp = await client.post(
        "/extension/unlock", json={"master_password": WRONG_MASTER_PASSWORD}
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": False,
        "session_token": None,
        "idle_timeout_ms": None,
    }
    assert sessions().extension_sessions() == []


async def test_unlock_without_a_vault_is_not_found(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/extension/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 404


async def test_a_vault_with_a_security_key_asks_for_the_handoff_before_any_kdf(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await populated(client)
    resp = await add_security_key(client, auth(token), SoftKey())
    assert resp.status_code == 200, resp.text

    async def no_kdf(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("the KDF ran")

    monkeypatch.setattr(helpers, "derive", no_kdf)
    for password in (MASTER_PASSWORD, WRONG_MASTER_PASSWORD):
        resp = await client.post(
            "/extension/unlock", json={"master_password": password}
        )
        assert resp.status_code == 409, resp.text
        assert resp.json()["code"] == "use_handoff"
    assert sessions().extension_sessions() == []

    resp = await client.post(
        "/extension/sessions", json={"browser": "Chrome"}, headers=auth(token)
    )
    assert resp.status_code == 200, resp.text
    resp = await post(client, resp.json()["session_token"], "session")
    assert resp.status_code == 200


async def test_extension_unlock_runs_its_kdf_outside_the_write_lock(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await populated(client)
    waits = FirstDerivationWaits(monkeypatch)
    pending = asyncio.create_task(
        client.post("/extension/unlock", json={"master_password": MASTER_PASSWORD})
    )
    await waits.entered.wait()
    # While the KDF runs, a write goes through: the unlock holds no lock.
    resp = await client.post(
        "/passwords/create", json=entry("During KDF"), headers=auth(token)
    )
    assert resp.status_code == 200, resp.text
    waits.release.set()
    resp = await pending
    assert resp.json()["valid"] is True


async def test_an_extension_unlock_overtaken_by_a_rotation_opens_no_session(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await populated(client)
    waits = FirstDerivationWaits(monkeypatch)
    stale = asyncio.create_task(
        client.post("/extension/unlock", json={"master_password": MASTER_PASSWORD})
    )
    await waits.entered.wait()
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    waits.release.set()
    resp = await stale
    assert resp.json()["valid"] is False
    assert sessions().extension_sessions() == []


# --- the handoff and the settings list ------------------------------------


async def test_connect_list_and_disconnect(client: httpx.AsyncClient) -> None:
    token = await populated(client)
    created = []
    for browser in ("Chrome", "Firefox"):
        resp = await client.post(
            "/extension/sessions", json={"browser": browser}, headers=auth(token)
        )
        assert resp.status_code == 200, resp.text
        created.append(resp.json())
    resp = await client.get("/extension/sessions", headers=auth(token))
    assert resp.status_code == 200
    listed = resp.json()
    assert [s["browser"] for s in listed] == ["Firefox", "Chrome"]
    assert set(listed[0]) == {"id", "browser", "created", "last_used"}
    for item in created:
        assert item["session_token"] not in resp.text
    resp = await client.delete(
        f"/extension/sessions/{created[0]['id']}", headers=auth(token)
    )
    assert resp.status_code == 200
    assert (await post(client, created[0]["session_token"], "session")).status_code == (
        401
    )
    assert (await post(client, created[1]["session_token"], "session")).status_code == (
        200
    )
    resp = await client.delete(
        f"/extension/sessions/{created[0]['id']}", headers=auth(token)
    )
    assert resp.status_code == 404
    resp = await client.delete(
        f"/extension/sessions/{created[1]['session_token']}", headers=auth(token)
    )
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"browser": "Netscape"},
        {"browser": "Chrome", "scope": "full"},
        {"browser": ["Chrome"]},
    ],
)
async def test_connect_refuses_unknown_browsers_and_fields(
    client: httpx.AsyncClient, body: dict
) -> None:
    token = await populated(client)
    resp = await client.post("/extension/sessions", json=body, headers=auth(token))
    assert resp.status_code == 422
    assert sessions().extension_sessions() == []


# --- matches and search ----------------------------------------------------


async def test_matches_list_active_logins_saved_for_the_page(
    client: httpx.AsyncClient,
) -> None:
    await populated(client)
    extension = await extension_unlock(client)
    resp = await post(
        client, extension, "matches", {"origin": "https://github.com/session"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["truncated"] is False
    assert [login["name"] for login in body["logins"]] == [
        "Zebra GitHub",
        "GitHub",
        "GitHub (work)",
    ]
    first = body["logins"][1]
    assert set(first) == {"id", "name", "username", "host", "favorite", "has_totp"}
    assert first["host"] == "github.com"
    assert first["has_totp"] is True
    assert body["logins"][0]["favorite"] is True
    for canary in (
        "gh-Secret-1",
        TOTP_SECRET,
        NOTE_BODY,
        DESCRIPTION,
        FIELD_VALUE,
        "Trashed",
        "Notes on",
    ):
        assert canary not in resp.text


@pytest.mark.parametrize(
    ("origin", "subdomains", "expected"),
    [
        ("http://github.com", False, []),
        ("https://github.com:8443", False, []),
        ("https://github.com.evil.test", True, []),
        ("http://intranet.test", False, ["Insecure"]),
        ("https://intranet.test", False, []),
        ("https://login.example.com", False, []),
        ("https://login.example.com", True, ["Subdomain"]),
        ("https://gitlab.com", False, ["GitLab"]),
    ],
)
async def test_matching_rules_apply_to_the_vault(
    client: httpx.AsyncClient, origin: str, subdomains: bool, expected: list[str]
) -> None:
    await populated(client)
    extension = await extension_unlock(client)
    resp = await post(
        client, extension, "matches", {"origin": origin, "subdomains": subdomains}
    )
    assert resp.status_code == 200, resp.text
    assert [login["name"] for login in resp.json()["logins"]] == expected
    if expected == ["Insecure"]:
        assert resp.json()["logins"][0]["host"] == "http://intranet.test"


@pytest.mark.parametrize(
    "origin",
    ["file:///etc/passwd", "about:blank", "javascript:alert(1)", "chrome://settings"],
)
async def test_pages_without_an_origin_are_refused(
    client: httpx.AsyncClient, origin: str
) -> None:
    await populated(client)
    extension = await extension_unlock(client)
    resp = await post(client, extension, "matches", {"origin": origin})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"origin": GITHUB, "extra": 1},
        {"origin": GITHUB, "subdomains": "yes"},
        {"origin": 42},
        {"origin": ""},
        {"origin": "https://x.test/" + "a" * 3000},
    ],
)
async def test_match_bodies_are_strict(client: httpx.AsyncClient, body: dict) -> None:
    await populated(client)
    extension = await extension_unlock(client)
    resp = await post(client, extension, "matches", body)
    assert resp.status_code == 422, resp.text


async def test_search_covers_names_usernames_and_hosts_of_logins_only(
    client: httpx.AsyncClient,
) -> None:
    await populated(client)
    extension = await extension_unlock(client)

    async def names(query: str) -> list[str]:
        resp = await post(client, extension, "search", {"query": query})
        assert resp.status_code == 200, resp.text
        return [login["name"] for login in resp.json()["logins"]]

    assert await names("gitlab") == ["GitLab"]
    assert await names("WORK@") == ["GitHub (work)"]
    assert await names("intranet") == ["Insecure"]
    assert await names("notes on") == []
    assert await names("trashed") == []
    assert await names("canary") == []
    assert await names("") == [
        "Zebra GitHub",
        "GitHub",
        "GitHub (work)",
        "GitLab",
        "Insecure",
        "No URL",
        "Subdomain",
    ]
    resp = await post(client, extension, "search", {"query": "x" * 201})
    assert resp.status_code == 422


async def test_listings_stop_at_fifty_and_say_so(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    for index in range(55):
        resp = await client.post(
            "/passwords/create",
            json=entry(f"site {index:02}", url=GITHUB),
            headers=auth(token),
        )
        assert resp.status_code == 200
    extension = await extension_unlock(client)
    for path, body in (("matches", {"origin": GITHUB}), ("search", {"query": ""})):
        resp = await post(client, extension, path, body)
        assert len(resp.json()["logins"]) == 50
        assert resp.json()["truncated"] is True


async def test_damaged_rows_are_skipped_in_listings_and_refused_by_id(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    await db_execute(
        "UPDATE entries SET document = x'02' || randomblob(60) WHERE id = :id",
        id=ids["GitHub"],
    )
    extension = await extension_unlock(client)
    resp = await post(client, extension, "matches", {"origin": GITHUB})
    assert [login["name"] for login in resp.json()["logins"]] == [
        "Zebra GitHub",
        "GitHub (work)",
    ]
    for path in ("credential", "totp"):
        resp = await post(
            client, extension, path, {"id": ids["GitHub"], "origin": GITHUB}
        )
        assert resp.status_code == 500
        assert resp.json()["code"] == "vault_damaged"
        assert f"#{ids['GitHub']}" in resp.json()["detail"]
        assert "gh-Secret" not in resp.text


# --- credentials and 2FA codes ---------------------------------------------


async def test_a_matching_login_returns_only_its_username_and_password(
    client: httpx.AsyncClient,
) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    resp = await post(
        client,
        extension,
        "credential",
        {"id": ids["GitHub"], "origin": "https://github.com"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"username": "moth@example.com", "password": "gh-Secret-1"}
    resp = await post(
        client, extension, "credential", {"id": ids["GitLab"], "origin": GITHUB}
    )
    assert resp.status_code == 409
    resp = await post(
        client,
        extension,
        "credential",
        {"id": ids["GitLab"], "origin": "https://gitlab.com"},
    )
    assert resp.json() == {"username": "moth", "password": "gl-Secret-4c"}
    assert "gl-Secret-4b" not in resp.text


@pytest.mark.parametrize("path", ["credential", "totp"])
async def test_a_login_for_another_site_needs_the_users_confirmation(
    client: httpx.AsyncClient, path: str
) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    for origin, name in (
        ("https://gitlab.com", "GitHub"),
        ("http://github.com", "GitHub"),
        ("https://github.com.evil.test", "GitHub"),
        ("https://github.com", "No URL"),
        ("https://login.example.com", "Subdomain"),
    ):
        body = {"id": ids[name], "origin": origin}
        resp = await post(client, extension, path, body)
        assert resp.status_code in (409, 404), (origin, resp.text)
        if resp.status_code == 409:
            assert resp.json()["code"] == "origin_mismatch"
            assert "Secret" not in resp.text
    body = {"id": ids["Subdomain"], "origin": "https://login.example.com"}
    resp = await post(client, extension, "credential", {**body, "subdomains": True})
    assert resp.status_code == 200
    resp = await post(
        client, extension, "credential", {**body, "confirmed_mismatch": True}
    )
    assert resp.status_code == 200
    assert resp.json()["password"] == "sub-Secret-6"


@pytest.mark.parametrize("path", ["credential", "totp"])
async def test_notes_trashed_and_unknown_ids_are_not_found(
    client: httpx.AsyncClient, path: str
) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    for entry_id in (
        ids["Notes on GitHub"],
        ids["Trashed GitHub"],
        max(ids.values()) + 1,
        2**62,
    ):
        resp = await post(
            client,
            extension,
            path,
            {"id": entry_id, "origin": GITHUB, "confirmed_mismatch": True},
        )
        assert resp.status_code == 404, resp.text
        assert NOTE_BODY not in resp.text
        assert "trash-Secret" not in resp.text
    for bad in (0, -1, 2**63, "1", 1.5, None, True):
        resp = await post(client, extension, path, {"id": bad, "origin": GITHUB})
        assert resp.status_code == 422, (bad, resp.text)


async def test_totp_returns_a_code_and_never_the_secret(
    client: httpx.AsyncClient,
) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    resp = await post(
        client, extension, "totp", {"id": ids["GitHub"], "origin": GITHUB}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"code", "expires_in"}
    assert body["code"] == helpers.generate_totp(TOTP_SECRET) or body["code"].isdigit()
    assert len(body["code"]) == 6
    assert 1 <= body["expires_in"] <= 30
    assert TOTP_SECRET not in resp.text
    assert TOTP_SECRET.lower() not in resp.text.lower()
    resp = await post(
        client, extension, "totp", {"id": ids["GitHub (work)"], "origin": GITHUB}
    )
    assert resp.status_code == 404


async def test_totp_code_and_lifetime_come_from_one_clock_reading(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two readings straddling a window boundary reported the old code with the
    # full lifetime of the next window.
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    readings = iter([1_800_000_029.9999, 1_800_000_030.0001])
    monkeypatch.setattr(
        crud.extension, "time", type("Clock", (), {"time": lambda: next(readings)})
    )
    monkeypatch.setattr(helpers, "time", crud.extension.time)
    resp = await post(
        client, extension, "totp", {"id": ids["GitHub"], "origin": GITHUB}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["code"] == helpers.generate_totp(TOTP_SECRET, now=1_800_000_029)
    assert body["expires_in"] == 1


async def test_an_unusable_stored_totp_secret_is_a_clear_error(
    client: httpx.AsyncClient,
) -> None:
    token = await populated(client)
    await plant_entry("Odd 2FA", url=GITHUB, totp_secret="not base32 at all!")
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    resp = await post(
        client, extension, "totp", {"id": ids["Odd 2FA"], "origin": GITHUB}
    )
    assert resp.status_code == 400
    assert "not base32" not in resp.text


async def test_no_extension_response_carries_more_than_a_fill_needs(
    client: httpx.AsyncClient,
) -> None:
    """A canary scan over every extension route: notes, history, descriptions,
    custom fields, 2FA secrets and other entries' passwords never appear."""
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    bodies = []
    for path, body in (
        ("matches", {"origin": GITHUB}),
        ("matches", {"origin": GITHUB, "subdomains": True}),
        ("search", {"query": ""}),
        ("search", {"query": "github"}),
        ("credential", {"id": ids["GitHub"], "origin": GITHUB}),
        ("totp", {"id": ids["GitHub"], "origin": GITHUB}),
        ("session", None),
    ):
        resp = await post(client, extension, path, body)
        assert resp.status_code == 200, resp.text
        bodies.append(resp.text)
    text = "\n".join(bodies)
    for canary in (
        TOTP_SECRET,
        NOTE_BODY,
        DESCRIPTION,
        FIELD_VALUE,
        "gh-Work-2",
        "gl-Secret",
        "http-Secret",
        "trash-Secret",
        "Trashed GitHub",
        "Notes on GitHub",
        await stored_vault_key(),
        extension,
    ):
        assert canary not in text, canary


# --- transactions, logs and speed -------------------------------------------


async def test_extension_routes_hold_no_write_lock(client: httpx.AsyncClient) -> None:
    token = await populated(client)
    ids = await ids_by_name(client, token)
    extension = await extension_unlock(client)
    connected = (
        await client.post(
            "/extension/sessions", json={"browser": "Edge"}, headers=auth(token)
        )
    ).json()
    before = await db_snapshot()
    with write_lock_held():
        started = time.monotonic()
        responses = await asyncio.gather(
            post(client, extension, "matches", {"origin": GITHUB}),
            post(client, extension, "search", {"query": "git"}),
            post(
                client, extension, "credential", {"id": ids["GitHub"], "origin": GITHUB}
            ),
            post(client, extension, "totp", {"id": ids["GitHub"], "origin": GITHUB}),
            post(client, extension, "session"),
            client.post("/extension/unlock", json={"master_password": MASTER_PASSWORD}),
            client.post(
                "/extension/sessions", json={"browser": "Chrome"}, headers=auth(token)
            ),
            client.get("/extension/sessions", headers=auth(token)),
            client.delete(
                f"/extension/sessions/{connected['id']}", headers=auth(token)
            ),
        )
        elapsed = time.monotonic() - started
    assert [r.status_code for r in responses] == [200] * len(responses), [
        r.text for r in responses
    ]
    assert elapsed < 2
    assert await db_snapshot() == before


async def test_extension_traffic_logs_no_names_hosts_tokens_or_secrets(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    token = await populated(client)
    ids = await ids_by_name(client, token)
    await db_execute(
        "UPDATE entries SET document = x'02' || randomblob(60) WHERE id = :id",
        id=ids["GitLab"],
    )
    caplog.clear()
    extension = await extension_unlock(client)
    connected = (
        await client.post(
            "/extension/sessions", json={"browser": "Chrome"}, headers=auth(token)
        )
    ).json()
    for path, body in (
        ("matches", {"origin": "https://github.com/secret-path?q=canary"}),
        ("search", {"query": "GitHub (work)"}),
        ("credential", {"id": ids["GitHub"], "origin": GITHUB}),
        ("credential", {"id": ids["GitLab"], "origin": "https://gitlab.com"}),
        ("totp", {"id": ids["GitHub"], "origin": GITHUB}),
        ("matches", {"origin": "javascript:alert('host-canary')"}),
    ):
        await post(client, extension, path, body)
    await client.post(
        "/extension/unlock", json={"master_password": WRONG_MASTER_PASSWORD}
    )
    await post(client, extension, "lock")
    logged = "\n".join(caplog.handler.format(r) for r in caplog.records)
    for secret in (
        extension,
        connected["session_token"],
        MASTER_PASSWORD,
        WRONG_MASTER_PASSWORD,
        "gh-Secret-1",
        TOTP_SECRET,
        "GitHub",
        "github.com",
        "gitlab.com",
        "secret-path",
        "host-canary",
        "moth@example.com",
        await stored_vault_key(),
    ):
        assert secret not in logged, secret


def _plant_many(count: int, key: helpers.VaultKey) -> None:
    rows = []
    for index in range(count):
        document = {
            "name": f"login {index:05}",
            "kind": "login",
            "username": f"user{index}@example.com",
            "value": f"pw-{index}",
            "url": f"https://site{index % 500}.example.com/login",
            "totp_secret": None,
            "description": None,
            "tags": [],
            "custom_fields": [],
            "folder": None,
            "favorite": index % 50 == 0,
            "history": [],
        }
        uid = os.urandom(16)
        rows.append(
            (
                uid,
                key.name_index(document["name"]),
                key.seal_entry(uid, json.dumps(document).encode()),
            )
        )
    with sqlite3.connect(data_dir() / "vault.db") as connection:
        connection.executemany(
            "INSERT INTO entries (uid, name_index, document, backed_up) "
            "VALUES (?, ?, ?, 0)",
            rows,
        )


async def test_matches_for_five_thousand_entries_are_fast(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    _plant_many(5000, await vault_key())
    extension = await extension_unlock(client)
    timings = []
    for _ in range(5):
        started = time.perf_counter()
        resp = await post(
            client, extension, "matches", {"origin": "https://site7.example.com"}
        )
        timings.append(time.perf_counter() - started)
        assert resp.status_code == 200
        assert len(resp.json()["logins"]) == 10
    assert min(timings) < 0.150, timings


async def test_unlock_needs_a_master_password_set(client: httpx.AsyncClient) -> None:
    resp = await client.post("/extension/sessions", json={"browser": "Chrome"})
    assert resp.status_code == 401
    await create_vault(client)
    await unlock(client)
