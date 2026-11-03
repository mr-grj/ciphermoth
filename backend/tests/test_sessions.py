import asyncio
import base64
import math
import threading
import time
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import crud.master_password
import helpers
from api.retired_clients import UPGRADE_REQUIRED
from crud.engine import Database, create_engine
from crud.master_password import MasterPasswordCRUD
from crud.password import PasswordCRUD
from errors import SessionRequired
from helpers import VaultKey
from main import app, get_application
from settings import get_api_settings
from storage import VAULT_FILE
from tests.integrity import hkdf
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    api_server,
    auth,
    create_vault,
    data_dir,
    db_execute,
    entry,
    fresh_vault_sessions,
    read_current_vault,
    retired_key_header,
    stored_vault_key,
    unlock,
)
from vault_sessions import (
    EXPIRY_TOLERANCE_MS,
    MAX_LIFETIME_MS,
    TOKEN_BYTES,
    Instant,
    VaultSessions,
)

ROTATE = {
    "master_password": MASTER_PASSWORD,
    "new_master_password": NEW_MASTER_PASSWORD,
}
KEY_TEXT = base64.urlsafe_b64encode(b"k" * 32).decode()
KEY = VaultKey(b"k" * 32)
IDLE_MS = 120_000


class FakeClock:
    def __init__(self) -> None:
        self.monotonic = 1_000.0
        self.wall = 1_800_000_000.0

    def __call__(self) -> Instant:
        return Instant(self.monotonic, self.wall)

    def advance(self, ms: float, *, monotonic: bool = True, wall: bool = True) -> None:
        if monotonic:
            self.monotonic += ms / 1000
        if wall:
            self.wall += ms / 1000


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> VaultSessions:
    return VaultSessions(idle_timeout_ms=IDLE_MS, tolerance_ms=0, clock=clock)


@pytest.fixture
def app_clock() -> Iterator[FakeClock]:
    fake = FakeClock()
    app.state.vault_sessions = fresh_vault_sessions(fake)
    yield fake


def sessions() -> VaultSessions:
    return app.state.vault_sessions


def test_tokens_are_random_urlsafe_and_independent_of_the_key(
    store: VaultSessions,
) -> None:
    tokens = [store.open(KEY) for _ in range(200)]
    assert len(set(tokens)) == len(tokens)
    for token in tokens:
        assert len(token) == math.ceil(TOKEN_BYTES * 4 / 3) == 43
        assert set(token) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        assert KEY_TEXT[:8] not in token
    symbols = Counter("".join(tokens))
    assert len(symbols) == 64
    assert max(symbols.values()) < 3 * min(symbols.values())


def test_the_store_keeps_only_token_digests_and_never_prints_keys(
    store: VaultSessions,
) -> None:
    token = store.open(KEY)
    held = repr(store.__dict__) + repr(list(store._sessions.values()))
    assert token not in held
    assert KEY_TEXT not in held
    assert KEY.check.hex() not in held


def test_a_session_resolves_to_its_key_until_it_is_idle_too_long(
    store: VaultSessions, clock: FakeClock
) -> None:
    token = store.open(KEY)
    for _ in range(5):
        clock.advance(IDLE_MS - 1)
        assert store.resolve(token) == KEY
    clock.advance(IDLE_MS + 1)
    with pytest.raises(SessionRequired):
        store.resolve(token)
    with pytest.raises(SessionRequired):
        store.resolve(token)
    assert len(store) == 0


def test_idle_time_counts_while_the_machine_sleeps_or_the_clock_is_set_back(
    store: VaultSessions, clock: FakeClock
) -> None:
    asleep = store.open(KEY)
    rewound = store.open(KEY)
    clock.advance(IDLE_MS + 1, monotonic=False)
    with pytest.raises(SessionRequired):
        store.resolve(asleep)

    clock.wall -= 3600
    clock.monotonic += (IDLE_MS + 1) / 1000
    with pytest.raises(SessionRequired):
        store.resolve(rewound)


def test_sessions_end_after_their_absolute_lifetime_even_when_busy(
    store: VaultSessions, clock: FakeClock
) -> None:
    token = store.open(KEY)
    used = 0
    while used + IDLE_MS // 2 < MAX_LIFETIME_MS:
        clock.advance(IDLE_MS // 2)
        used += IDLE_MS // 2
        assert store.resolve(token) == KEY
    clock.advance(IDLE_MS // 2)
    with pytest.raises(SessionRequired):
        store.resolve(token)


def test_a_new_idle_timeout_applies_to_open_sessions(
    store: VaultSessions, clock: FakeClock
) -> None:
    token = store.open(KEY)
    store.set_idle_timeout(10_000)
    clock.advance(10_001)
    with pytest.raises(SessionRequired):
        store.resolve(token)


@pytest.mark.parametrize(
    "token",
    [None, "", "short", "A" * 42, "A" * 44, "A" * 42 + "=", "A" * 42 + "/", "é" * 43],
)
def test_malformed_tokens_are_refused(store: VaultSessions, token: str | None) -> None:
    store.open(KEY)
    with pytest.raises(SessionRequired):
        store.resolve(token)
    assert store.revoke(token) is False


def test_revoking_ends_one_session_and_revoke_all_ends_every_one(
    store: VaultSessions,
) -> None:
    first, second, third = (store.open(KEY) for _ in range(3))
    assert store.revoke(first) is True
    assert store.revoke(first) is False
    with pytest.raises(SessionRequired):
        store.resolve(first)
    assert store.resolve(second) == KEY
    assert store.revoke_all() == 2
    for token in (second, third):
        with pytest.raises(SessionRequired):
            store.resolve(token)


def test_the_store_is_bounded_and_evicts_the_least_recently_used(
    clock: FakeClock,
) -> None:
    store = VaultSessions(
        idle_timeout_ms=IDLE_MS, tolerance_ms=0, max_sessions=3, clock=clock
    )
    first, second, third = (store.open(KEY) for _ in range(3))
    store.resolve(first)
    fourth = store.open(KEY)
    assert len(store) == 3
    with pytest.raises(SessionRequired):
        store.resolve(second)
    for token in (first, third, fourth):
        assert store.resolve(token) == KEY


def test_expired_sessions_are_dropped_before_live_ones_are_evicted(
    clock: FakeClock,
) -> None:
    store = VaultSessions(
        idle_timeout_ms=IDLE_MS, tolerance_ms=0, max_sessions=2, clock=clock
    )
    stale = store.open(KEY)
    clock.advance(IDLE_MS // 2)
    live = store.open(KEY)
    clock.advance(IDLE_MS // 2 + 1)
    store.open(KEY)
    assert store.resolve(live) == KEY
    with pytest.raises(SessionRequired):
        store.resolve(stale)
    clock.advance(IDLE_MS + 1)
    assert store.drop_expired() == 2
    assert len(store) == 0


def test_a_single_session_store_replaces_the_previous_unlock(clock: FakeClock) -> None:
    desktop = VaultSessions(
        idle_timeout_ms=IDLE_MS, tolerance_ms=0, max_sessions=1, clock=clock
    )
    first = desktop.open(KEY)
    second = desktop.open(KEY)
    with pytest.raises(SessionRequired):
        desktop.resolve(first)
    assert desktop.resolve(second) == KEY


def test_the_configured_timeout_is_enforced_within_the_tolerance(
    clock: FakeClock,
) -> None:
    store = VaultSessions(idle_timeout_ms=30_000, tolerance_ms=5_000, clock=clock)
    early, late = store.open(KEY), store.open(KEY)
    clock.advance(34_999)
    assert store.resolve(early, refresh=False) == KEY
    assert store.info(early).expires_in_ms == 0
    clock.advance(2)
    for token in (early, late):
        with pytest.raises(SessionRequired):
            store.resolve(token)


def test_the_default_tolerance_is_at_most_five_seconds(clock: FakeClock) -> None:
    store = VaultSessions(idle_timeout_ms=30_000, clock=clock)
    token = store.open(KEY)
    clock.advance(35_001)
    with pytest.raises(SessionRequired):
        store.resolve(token)


def test_reading_a_session_is_not_activity(
    store: VaultSessions, clock: FakeClock
) -> None:
    token = store.open(KEY)
    for _ in range(4):
        clock.advance(IDLE_MS // 4 - 1)
        assert store.resolve(token, refresh=False) == KEY
        store.info(token)
    clock.advance(5)
    with pytest.raises(SessionRequired):
        store.info(token)


def test_an_expired_session_is_deleted_and_cannot_be_revived(
    store: VaultSessions, clock: FakeClock
) -> None:
    token = store.open(KEY)
    clock.advance(IDLE_MS + 1)
    store.set_idle_timeout(IDLE_MS * 10)
    for attempt in (store.info, store.resolve, store.resolve):
        with pytest.raises(SessionRequired):
            attempt(token)
    assert store.revoke(token) is False
    assert len(store) == 0


def test_a_new_timeout_applies_to_open_sessions_from_their_last_activity(
    store: VaultSessions, clock: FakeClock
) -> None:
    idle, active = store.open(KEY), store.open(KEY)
    clock.advance(20_000)
    store.resolve(active)
    store.set_idle_timeout(15_000)
    with pytest.raises(SessionRequired):
        store.resolve(idle)
    assert store.info(active).expires_in_ms == 15_000
    store.set_idle_timeout(60_000)
    clock.advance(40_000)
    assert store.resolve(active) == KEY


@pytest.mark.parametrize("offset_ms", [-1, 0, 1])
def test_concurrent_requests_at_the_deadline_agree(
    store: VaultSessions, clock: FakeClock, offset_ms: int
) -> None:
    token = store.open(KEY)
    clock.advance(IDLE_MS + offset_ms)

    def attempt(_: int) -> VaultKey | str:
        try:
            return store.resolve(token)
        except SessionRequired:
            return "ended"

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = set(pool.map(attempt, range(64)))
    assert outcomes == ({KEY} if offset_ms < 0 else {"ended"})


async def test_unlock_returns_a_session_and_never_the_vault_key(
    client: httpx.AsyncClient,
) -> None:
    created = await client.post(
        "/master_password/create", json={"master_password": MASTER_PASSWORD}
    )
    unlocked = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    vault_key = await stored_vault_key()
    raw_key = base64.urlsafe_b64decode(vault_key)
    for resp in (created, unlocked):
        assert resp.status_code == 200
        body = resp.json()
        assert set(body) >= {"session_token", "idle_timeout_ms"}
        assert "key_derivation" not in body
        assert vault_key not in resp.text
        assert vault_key.rstrip("=") not in resp.text
        assert raw_key.hex() not in resp.text
        assert resp.headers["cache-control"] == "no-store"
    assert unlocked.json()["idle_timeout_ms"] == 120_000
    assert len(sessions()) == 2


async def test_a_wrong_password_opens_no_session(client: httpx.AsyncClient) -> None:
    await create_vault(client)
    before = len(sessions())
    resp = await client.post(
        "/master_password/unlock", json={"master_password": WRONG_MASTER_PASSWORD}
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False
    assert len(sessions()) == before


async def test_unlock_without_a_vault_is_not_found(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 404
    assert len(sessions()) == 0


async def test_session_status_reports_the_server_side_timeout(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    app_clock.advance(30_000)
    resp = await client.get("/master_password/session", headers=auth(token))
    assert resp.json() == {"idle_timeout_ms": 120_000, "expires_in_ms": 90_000}
    app_clock.advance(10_000)
    resp = await client.get("/master_password/session", headers=auth(token))
    assert resp.json() == {"idle_timeout_ms": 120_000, "expires_in_ms": 80_000}
    resp = await client.post("/master_password/session", headers=auth(token))
    assert resp.json() == {"idle_timeout_ms": 120_000, "expires_in_ms": 120_000}


async def test_idle_sessions_expire_on_the_server(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    busy = await unlock(client)
    for _ in range(3):
        app_clock.advance(100_000)
        assert (await client.get("/passwords", headers=auth(busy))).status_code == 200
    resp = await client.get("/master_password/session", headers=auth(token))
    assert resp.status_code == 401
    resp = await client.get("/passwords", headers=auth(token))
    assert resp.status_code == 401
    assert resp.json()["code"] == "invalid_session"
    assert resp.headers["www-authenticate"] == "CipherMoth-Session"
    assert (await client.get("/passwords", headers=auth(busy))).status_code == 200


async def test_status_checks_and_public_polling_do_not_keep_a_session_alive(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    for path in ("/master_password/session", "/meta", "/master_password/status"):
        app_clock.advance(30_000)
        assert (await client.get(path, headers=auth(token))).status_code == 200
    app_clock.advance(30_000 + EXPIRY_TOLERANCE_MS + 1)
    resp = await client.get("/master_password/session", headers=auth(token))
    assert resp.status_code == 401
    resp = await client.post("/master_password/session", headers=auth(token))
    assert resp.status_code == 401


async def test_activity_keeps_a_session_open_until_its_absolute_limit(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    settings = (await client.get("/settings", headers=auth(token))).json()
    resp = await client.patch(
        "/settings", json={**settings, "inactivity_ms": 3_600_000}, headers=auth(token)
    )
    assert resp.status_code == 200
    elapsed = 0
    while elapsed + 3_000_000 < MAX_LIFETIME_MS:
        app_clock.advance(3_000_000)
        elapsed += 3_000_000
        resp = await client.post("/master_password/session", headers=auth(token))
        assert resp.status_code == 200
    app_clock.advance(MAX_LIFETIME_MS - elapsed)
    resp = await client.post("/master_password/session", headers=auth(token))
    assert resp.status_code == 401


async def test_raising_the_timeout_does_not_revive_an_expired_session(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    stale = await create_vault(client)
    app_clock.advance(100_000)
    active = await unlock(client)
    app_clock.advance(30_000)
    settings = (await client.get("/settings", headers=auth(active))).json()
    resp = await client.patch(
        "/settings", json={**settings, "inactivity_ms": 3_600_000}, headers=auth(active)
    )
    assert resp.status_code == 200
    assert (await client.get("/passwords", headers=auth(stale))).status_code == 401


async def test_concurrent_requests_near_the_deadline_agree(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    app_clock.advance(120_000 + EXPIRY_TOLERANCE_MS - 1)
    responses = await asyncio.gather(
        *(client.get("/passwords", headers=auth(token)) for _ in range(10))
    )
    assert {r.status_code for r in responses} == {200}
    app_clock.advance(120_000 + EXPIRY_TOLERANCE_MS)
    responses = await asyncio.gather(
        *(client.get("/passwords", headers=auth(token)) for _ in range(10))
    )
    assert {r.status_code for r in responses} == {401}


async def test_the_inactivity_setting_is_enforced_by_the_server(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    settings = (await client.get("/settings", headers=auth(token))).json()
    resp = await client.patch(
        "/settings",
        json={**settings, "inactivity_ms": 30_000, "warn_before_ms": 10_000},
        headers=auth(token),
    )
    assert resp.status_code == 200
    status = await client.get("/master_password/session", headers=auth(token))
    assert status.json() == {"idle_timeout_ms": 30_000, "expires_in_ms": 30_000}

    app_clock.advance(30_000 + EXPIRY_TOLERANCE_MS - 1)
    assert (await client.get("/settings", headers=auth(token))).status_code == 200
    app_clock.advance(30_000 + EXPIRY_TOLERANCE_MS + 1)
    assert (await client.get("/passwords", headers=auth(token))).status_code == 401

    app.state.vault_sessions = fresh_vault_sessions(app_clock)
    fresh = await unlock(client)
    status = await client.get("/master_password/session", headers=auth(fresh))
    assert status.json()["idle_timeout_ms"] == 30_000


async def test_the_warning_must_come_before_the_lock(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    settings = (await client.get("/settings", headers=auth(token))).json()
    for warn in (60_000, 90_000):
        resp = await client.patch(
            "/settings",
            json={**settings, "inactivity_ms": 60_000, "warn_before_ms": warn},
            headers=auth(token),
        )
        assert resp.status_code == 422
    assert (await client.get("/settings", headers=auth(token))).json() == settings


async def test_a_settings_change_that_fails_to_commit_keeps_the_old_timeout(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await create_vault(client)
    settings = (await client.get("/settings", headers=auth(token))).json()

    async def failing_commit(self) -> None:
        raise RuntimeError("commit failed")

    monkeypatch.setattr("sqlalchemy.ext.asyncio.AsyncSession.commit", failing_commit)
    resp = await client.patch(
        "/settings", json={**settings, "inactivity_ms": 3_600_000}, headers=auth(token)
    )
    monkeypatch.undo()
    assert resp.status_code == 500
    assert sessions().idle_timeout_ms == 120_000


async def test_lock_ends_only_that_session_and_is_idempotent(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    other = await unlock(client)
    for _ in range(2):
        resp = await client.post("/master_password/lock", headers=auth(token))
        assert resp.status_code == 200
        assert resp.json() == {"locked": True}
    for headers in ([], auth("garbage"), auth("A" * 43)):
        assert (await client.post("/master_password/lock", headers=headers)).is_success

    for path in ("/passwords", "/settings", "/master_password/session"):
        resp = await client.get(path, headers=auth(token))
        assert resp.status_code == 401, path
    assert (await client.get("/passwords", headers=auth(other))).status_code == 200


async def test_independent_sessions_work_concurrently(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    tokens = await asyncio.gather(*(unlock(client) for _ in range(4)))
    assert len(set(tokens)) == 4
    for i, token in enumerate(tokens):
        resp = await client.post(
            "/passwords/create", json=entry(f"from-{i}"), headers=auth(token)
        )
        assert resp.status_code == 200
    responses = await asyncio.gather(
        *(client.get("/passwords", headers=auth(t)) for t in tokens * 5)
    )
    assert {r.status_code for r in responses} == {200}
    assert {len(r.json()) for r in responses} == {4}


async def test_rotation_ends_every_session(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    others = [await unlock(client) for _ in range(3)]
    resp = await client.patch(
        "/master_password/update", json=ROTATE, headers=auth(others[0])
    )
    assert resp.status_code == 200, resp.text
    assert len(sessions()) == 0

    for stale in (token, *others):
        resp = await client.get("/passwords", headers=auth(stale))
        assert resp.status_code == 401
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.json()["valid"] is False
    fresh = await unlock(client, NEW_MASTER_PASSWORD)
    assert (await client.get("/passwords", headers=auth(fresh))).status_code == 200


@pytest.mark.parametrize("failure", ["wrong password", "commit"])
async def test_a_rotation_that_does_not_happen_keeps_every_session(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    token = await create_vault(client)
    other = await unlock(client)
    body = ROTATE
    if failure == "wrong password":
        body = {**ROTATE, "master_password": WRONG_MASTER_PASSWORD}
    else:

        async def failing_commit(self) -> None:
            raise RuntimeError("commit failed")

        monkeypatch.setattr(
            "sqlalchemy.ext.asyncio.AsyncSession.commit", failing_commit
        )
    resp = await client.patch("/master_password/update", json=body, headers=auth(token))
    monkeypatch.undo()

    assert resp.status_code in (403, 500)
    for live in (token, other):
        assert (await client.get("/passwords", headers=auth(live))).status_code == 200


async def test_a_session_whose_key_was_changed_elsewhere_is_ended(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    other_process = get_application(database=Database(data_dir()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=other_process),
        base_url="http://testserver/api",
    ) as elsewhere:
        remote = await unlock(elsewhere)
        resp = await elsewhere.patch(
            "/master_password/update", json=ROTATE, headers=auth(remote)
        )
        assert resp.status_code == 200
        await other_process.state.database.dispose()

    assert len(sessions()) == 1
    resp = await client.get("/passwords", headers=auth(token))
    assert resp.status_code == 401
    assert len(sessions()) == 0


async def test_a_session_does_not_survive_a_vault_recreated_from_scratch(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    await db_execute("DELETE FROM vault")
    resp = await client.get("/passwords", headers=auth(token))
    assert resp.status_code == 403
    await create_vault(client, NEW_MASTER_PASSWORD)
    resp = await client.get("/passwords", headers=auth(token))
    assert resp.status_code == 401


async def test_sessions_belong_to_one_app_instance(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    other_process = get_application(database=Database(data_dir()))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=other_process),
            base_url="http://testserver/api",
        ) as elsewhere:
            resp = await elsewhere.get("/passwords", headers=auth(token))
            assert resp.status_code == 401
            mine = await unlock(elsewhere)
        assert (await client.get("/passwords", headers=auth(mine))).status_code == 401
    finally:
        await other_process.state.database.dispose()


async def test_a_client_cannot_choose_its_session_token(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    chosen = "A" * 43
    resp = await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(chosen),
    )
    issued = resp.json()["session_token"]
    assert issued != chosen
    assert (await client.get("/passwords", headers=auth(chosen))).status_code == 401
    assert (await client.get("/passwords", headers=auth(issued))).status_code == 200


async def test_a_reverse_proxy_may_keep_its_own_authorization_header(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    proxy = [(b"authorization", b"Basic bW90aDpwcm94eS1wYXNz")]
    resp = await client.get("/passwords", headers=proxy + auth(token))
    assert resp.status_code == 200
    resp = await client.get("/passwords", headers=proxy)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] != "Basic"


async def test_a_session_token_and_a_vault_key_together_are_refused(
    client: httpx.AsyncClient, app_clock: FakeClock
) -> None:
    token = await create_vault(client)
    key = await stored_vault_key()
    app_clock.advance(IDLE_MS - 10_000)
    for headers in (
        auth(token) + retired_key_header(key),
        retired_key_header(key) + auth(token),
    ):
        resp = await client.post(
            "/passwords/create", json=entry("both"), headers=headers
        )
        assert resp.status_code == 403
        assert resp.json() == {"detail": UPGRADE_REQUIRED, "code": "invalid_key"}
    assert await db_execute("SELECT id FROM entries") == []
    assert sessions().info(token).expires_in_ms == 10_000
    assert (await client.get("/passwords", headers=auth(token))).status_code == 200


async def test_a_write_in_flight_during_rotation_is_reencrypted(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await create_vault(client)
    gate = asyncio.Event()
    original = PasswordCRUD.create_password

    async def slow_create(self, password, key_derivation):
        result = await original(self, password, key_derivation)
        await gate.wait()
        return result

    monkeypatch.setattr(PasswordCRUD, "create_password", slow_create)
    create = asyncio.create_task(
        client.post("/passwords/create", json=entry("racer"), headers=auth(token))
    )
    await asyncio.sleep(0.3)
    rotate = asyncio.create_task(
        client.patch("/master_password/update", json=ROTATE, headers=auth(token))
    )
    await asyncio.sleep(1.5)
    gate.set()
    create_resp, rotate_resp = await asyncio.gather(create, rotate)

    assert create_resp.status_code == 200, create_resp.text
    assert rotate_resp.status_code == 200, rotate_resp.text
    fresh = await unlock(client, NEW_MASTER_PASSWORD)
    resp = await client.get("/passwords/racer", headers=auth(fresh))
    assert resp.json()["password_value"] == "s3cret-Value!"


async def test_a_request_queued_behind_rotation_is_refused(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await create_vault(client)
    other = await unlock(client)
    gate = asyncio.Event()
    original = MasterPasswordCRUD.update_master_password

    async def slow_rotation(self, *args, **kwargs):
        result = await original(self, *args, **kwargs)
        await gate.wait()
        return result

    monkeypatch.setattr(MasterPasswordCRUD, "update_master_password", slow_rotation)
    rotate = asyncio.create_task(
        client.patch("/master_password/update", json=ROTATE, headers=auth(token))
    )
    await asyncio.sleep(1.5)
    late = asyncio.create_task(
        client.post("/passwords/create", json=entry("late"), headers=auth(other))
    )
    stale_unlock = asyncio.create_task(
        client.post(
            "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
        )
    )
    await asyncio.sleep(1.0)
    gate.set()
    rotate_resp, late_resp, unlock_resp = await asyncio.gather(
        rotate, late, stale_unlock
    )

    assert rotate_resp.status_code == 200, rotate_resp.text
    assert late_resp.status_code == 401, late_resp.text
    if unlock_resp.json()["valid"]:
        stale = unlock_resp.json()["session_token"]
        assert (await client.get("/passwords", headers=auth(stale))).status_code == 401
    assert len(sessions()) == 0
    assert await db_execute("SELECT id FROM entries") == []


async def test_requests_after_a_lock_are_refused_while_earlier_ones_finish(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await create_vault(client)
    gate = asyncio.Event()
    original = PasswordCRUD.create_password

    async def slow_create(self, password, key):
        await gate.wait()
        return await original(self, password, key)

    monkeypatch.setattr(PasswordCRUD, "create_password", slow_create)
    in_flight = asyncio.create_task(
        client.post("/passwords/create", json=entry("before"), headers=auth(token))
    )
    await asyncio.sleep(0.3)
    assert (await client.post("/master_password/lock", headers=auth(token))).is_success
    after = await client.post(
        "/passwords/create", json=entry("after"), headers=auth(token)
    )
    gate.set()

    assert after.status_code == 401
    assert (await in_flight).status_code == 200
    names = [e.name for e in (await read_current_vault()).entries]
    assert names == ["before"]


async def test_unlock_does_not_block_other_requests(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await create_vault(client)
    entered = threading.Event()
    release = threading.Event()
    original = helpers.argon2id

    def paused_argon2id(
        password: str,
        salt: bytes,
        params: helpers.KdfParams = helpers.DEFAULT_KDF,
    ) -> bytes:
        entered.set()
        release.wait(timeout=1)
        return original(password, salt, params)

    monkeypatch.setattr(helpers, "argon2id", paused_argon2id)
    unlocking = asyncio.create_task(unlock(client))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        response = await client.get("/meta")
        assert response.status_code == 200
        assert not unlocking.done()
    finally:
        release.set()
    await unlocking


async def test_unlocks_waiting_for_the_kdf_hold_no_database_connection(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    engine = create_engine(
        data_dir() / VAULT_FILE,
        pool_size=1,
        max_overflow=0,
        pool_timeout=10,
    )
    one_connection = get_application(database=Database(data_dir(), engine=engine))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=one_connection),
            base_url="http://testserver/api",
            timeout=60,
        ) as narrow:
            unlocks = [asyncio.create_task(unlock(narrow)) for _ in range(3)]
            await asyncio.sleep(0.05)
            started = time.monotonic()
            resp = await narrow.get("/master_password/status")
            waited = time.monotonic() - started
            unlocking = not all(task.done() for task in unlocks)
            await asyncio.gather(*unlocks)
    finally:
        await engine.dispose()

    assert resp.json() == {
        "initialized": True,
        "security_key_required": False,
        "recovery_code": False,
    }
    assert unlocking
    assert waited < 0.15


async def test_argon2id_derivations_never_overlap(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await create_vault(client)
    running = 0
    peak = 0
    lock = threading.Lock()
    original = helpers.Argon2id

    class Counted:
        def __init__(self, **kwargs: Any) -> None:
            self._kdf = original(**kwargs)

        def derive(self, data: bytes) -> bytes:
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            try:
                time.sleep(0.05)
                return self._kdf.derive(data)
            finally:
                with lock:
                    running -= 1

    monkeypatch.setattr(helpers, "Argon2id", Counted)
    derive_on_loop = asyncio.to_thread(helpers.argon2id, MASTER_PASSWORD, b"s" * 16)
    tokens, _ = await asyncio.wait_for(
        asyncio.gather(
            asyncio.gather(*(unlock(client) for _ in range(6))), derive_on_loop
        ),
        timeout=120,
    )
    assert len(set(tokens)) == 6
    assert peak == 1


async def test_sessions_are_bounded(client: httpx.AsyncClient) -> None:
    first = await create_vault(client)
    for _ in range(32):
        await unlock(client)
    assert len(sessions()) == 32
    assert (await client.get("/passwords", headers=auth(first))).status_code == 401


async def test_neither_tokens_nor_keys_are_stored_in_the_database(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    other = await unlock(client)
    vault_key = await stored_vault_key()
    raw_key = base64.urlsafe_b64decode(vault_key)
    rows = []
    for table in ("vault", "entries", "attachments", "settings"):
        rows += await db_execute(f"SELECT * FROM {table}")
    dump = repr(rows).encode()
    blobs = b"".join(
        bytes(value) for row in rows for value in row if isinstance(value, bytes)
    )
    for secret in (token, other, vault_key):
        assert secret.encode() not in dump
        assert secret.encode() not in blobs
    assert raw_key not in blobs
    for label in ("record-encryption", "name-index"):
        assert hkdf(raw_key, f"ciphermoth/v2/{label}") not in blobs


def _fail_commit_number(monkeypatch: pytest.MonkeyPatch, failing: int) -> None:
    original = AsyncSession.commit
    calls = 0

    async def commit(self) -> None:
        nonlocal calls
        calls += 1
        if calls == failing:
            raise RuntimeError("commit failed")
        await original(self)

    monkeypatch.setattr(AsyncSession, "commit", commit)


async def test_unlock_that_fails_to_commit_leaves_no_session(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await create_vault(client)
    before = len(sessions())

    _fail_commit_number(monkeypatch, 2)
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    monkeypatch.undo()
    assert resp.status_code == 500
    assert "session_token" not in resp.text
    assert len(sessions()) == before


@pytest.mark.parametrize("failing", [1, 2])
async def test_creation_that_fails_to_commit_leaves_no_session(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, failing: int
) -> None:
    _fail_commit_number(monkeypatch, failing)
    resp = await client.post(
        "/master_password/create", json={"master_password": MASTER_PASSWORD}
    )
    monkeypatch.undo()
    assert resp.status_code == 500
    assert len(sessions()) == 0
    assert await db_execute("SELECT id FROM vault") == []


async def test_browsers_may_send_the_session_header(client: httpx.AsyncClient) -> None:
    resp = await client.options(
        "/passwords",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-ciphermoth-session",
        },
    )
    assert resp.status_code == 200
    allowed = resp.headers["access-control-allow-headers"].lower()
    assert "x-ciphermoth-session" in allowed
    assert "authorization" not in allowed
    assert resp.headers.get("access-control-allow-credentials") is None


async def test_the_retired_key_route_answers_without_deriving_a_key(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await create_vault(client)
    key = await stored_vault_key()
    before = len(sessions())

    async def never(*args: Any) -> Any:
        raise AssertionError("the retired route must not check the password")

    monkeypatch.setattr(MasterPasswordCRUD, "unlock", never)
    monkeypatch.setattr(crud.master_password, "open_vault", never)
    monkeypatch.setattr(helpers, "derive", never)
    for body in (
        {"master_password": MASTER_PASSWORD},
        {"master_password": WRONG_MASTER_PASSWORD},
        {},
    ):
        resp = await client.post("/master_password/check", json=body)
        assert resp.status_code == 410
        assert resp.json() == {"detail": UPGRADE_REQUIRED, "code": "upgrade_required"}
        assert key not in resp.text
        assert resp.headers["cache-control"] == "no-store"
    assert len(sessions()) == before


async def test_the_retired_key_header_is_refused_on_public_routes_too(
    client: httpx.AsyncClient,
) -> None:
    key_header = retired_key_header("K" * 43 + "=")
    resp = await client.post(
        "/master_password/create",
        json={"master_password": MASTER_PASSWORD},
        headers=key_header,
    )
    assert resp.status_code == 403
    assert await db_execute("SELECT id FROM vault") == []

    await create_vault(client)
    before = len(sessions())
    for method, path, body in (
        ("POST", "/master_password/unlock", {"master_password": MASTER_PASSWORD}),
        ("POST", "/master_password/lock", None),
        ("GET", "/master_password/status", None),
        ("GET", "/meta", None),
        ("GET", "/health", None),
    ):
        resp = await client.request(method, path, json=body, headers=key_header)
        assert resp.status_code == 403, path
        assert resp.json() == {"detail": UPGRADE_REQUIRED, "code": "invalid_key"}
    assert len(sessions()) == before


async def test_the_server_no_longer_advertises_the_vault_key_protocol(
    client: httpx.AsyncClient,
) -> None:
    features = (await client.get("/meta")).json()["features"]
    assert features == [
        "bulk-entry-actions",
        "entry-names-with-slash",
        "recovery-code",
        "security-keys",
        "vault-sessions",
    ]
    paths = app.openapi()["paths"]
    assert "/api/master_password/check" not in paths
    assert "key-derivation" not in str(app.openapi()).lower()


async def test_a_leftover_legacy_setting_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value in ("true", "false", ""):
        monkeypatch.setenv("CIPHERMOTH_LEGACY_KEY_AUTH", value)
        settings = get_api_settings().__class__()
        assert not hasattr(settings, "legacy_key_auth")
        server = get_application(vault_sessions=fresh_vault_sessions())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server), base_url="http://testserver/api"
        ) as other:
            resp = await other.post(
                "/master_password/check", json={"master_password": MASTER_PASSWORD}
            )
            assert resp.status_code == 410
            resp = await other.get("/passwords", headers=retired_key_header("K"))
            assert resp.status_code == 403


async def test_old_browser_tabs_can_read_the_refusal(client: httpx.AsyncClient) -> None:
    origin = [(b"origin", b"http://localhost:3000")]
    resp = await client.options(
        "/passwords",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-ciphermoth-key-derivation",
        },
    )
    assert resp.status_code == 200
    resp = await client.get(
        "/passwords", headers=origin + retired_key_header("K" * 43 + "=")
    )
    assert resp.status_code == 403
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert resp.json()["code"] == "invalid_key"
    assert resp.headers["x-frame-options"] == "DENY"


async def test_a_restarted_server_has_no_sessions(tmp_path: Path) -> None:
    with api_server(tmp_path / "first.log", tmp_path / "vault") as server:
        resp = httpx.post(
            f"{server.base_url}/master_password/create",
            json={"master_password": MASTER_PASSWORD},
        )
        token = resp.json()["session_token"]
        resp = httpx.get(f"{server.base_url}/passwords", headers=dict(auth(token)))
        assert resp.status_code == 200
    with api_server(tmp_path / "second.log", tmp_path / "vault") as server:
        resp = httpx.get(f"{server.base_url}/passwords", headers=dict(auth(token)))
        assert resp.status_code == 401
        assert resp.json()["code"] == "invalid_session"
        resp = httpx.post(
            f"{server.base_url}/master_password/unlock",
            json={"master_password": MASTER_PASSWORD},
        )
        fresh = resp.json()["session_token"]
        resp = httpx.get(f"{server.base_url}/passwords", headers=dict(auth(fresh)))
        assert resp.status_code == 200
    for log in ("first.log", "second.log"):
        text = (tmp_path / log).read_text(errors="replace")
        assert token not in text
        assert fresh not in text


def test_app_factory_keeps_an_empty_injected_session_store():
    from main import get_application
    from vault_sessions import VaultSessions

    sessions = VaultSessions(idle_timeout_ms=30_000, max_sessions=1)
    assert get_application(vault_sessions=sessions).state.vault_sessions is sessions
