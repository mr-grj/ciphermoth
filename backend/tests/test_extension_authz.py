"""
The second authorization matrix: browser extension sessions. An extension
token opens exactly the routes in ``EXTENSION_ROUTES`` and nothing else; those
routes open for nothing but an extension token. The route list itself is
checked against the app in test_authz.test_every_api_route_is_classified.
"""

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
    forged_tokens,
    retired_key_header,
    stored_vault_key,
)
from tests.test_authz import (
    EXTENSION_IDS,
    EXTENSION_ROUTES,
    PROTECTED_ROUTES,
    REACHED,
    ROUTE_IDS,
    _alpha,
    _as_key_headers,
    _assert_rejected_without_side_effects,
    seed,
)


def _scope_refusal(resp: httpx.Response) -> None:
    assert resp.status_code == 403, resp.text
    assert resp.json()["code"] == "extension_scope"


async def _seed(client: httpx.AsyncClient, headers: Headers) -> dict:
    ctx = await seed(client, headers)
    resp = await client.patch(
        "/passwords/update",
        json={
            "password": _alpha(),
            "new_password": entry(
                "alpha",
                username="moth@example.com",
                url="https://x.test/login",
                totp_secret="JBSWY3DPEHPK3PXP",
            ),
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return ctx


@pytest.mark.parametrize("route", list(PROTECTED_ROUTES), ids=ROUTE_IDS)
async def test_extension_tokens_never_open_a_full_route(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    spec = PROTECTED_ROUTES[route]
    extension = ctx["extension_token"]

    before = await db_snapshot()
    sessions_before = app.state.vault_sessions.extension_sessions()
    for headers in (
        auth(extension),
        auth(extension) + [(b"x-ciphermoth-entry", b"alpha")],
    ):
        _scope_refusal(await spec(client, headers, ctx))
    assert await db_snapshot() == before
    # Refused, not refreshed: the extension session's last use did not move.
    assert app.state.vault_sessions.extension_sessions() == sessions_before

    resp = await spec(client, auth(token), ctx)
    assert resp.status_code == REACHED.get(route, 200), resp.text


@pytest.mark.parametrize("route", list(EXTENSION_ROUTES), ids=EXTENSION_IDS)
async def test_full_tokens_never_open_an_extension_route(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    spec = EXTENSION_ROUTES[route]

    before = await db_snapshot()
    _scope_refusal(await spec(client, auth(token), ctx))
    assert await db_snapshot() == before

    resp = await spec(client, auth(ctx["extension_token"]), ctx)
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("route", list(EXTENSION_ROUTES), ids=EXTENSION_IDS)
async def test_forged_and_ended_extension_tokens_are_rejected(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    spec = EXTENSION_ROUTES[route]
    extension = ctx["extension_token"]
    key = await stored_vault_key()

    locked = await client.post(
        "/extension/sessions", json={"browser": "Edge"}, headers=auth(token)
    )
    locked_token = locked.json()["session_token"]
    resp = await client.post("/extension/lock", headers=auth(locked_token))
    assert resp.status_code == 200
    disconnected = await client.post(
        "/extension/sessions", json={"browser": "Brave"}, headers=auth(token)
    )
    resp = await client.delete(
        f"/extension/sessions/{disconnected.json()['id']}", headers=auth(token)
    )
    assert resp.status_code == 200

    credentials = {
        **await forged_tokens(client, extension, key),
        "locked extension session": auth(locked_token),
        "disconnected extension session": auth(disconnected.json()["session_token"]),
        "extension handle as token": auth(ctx["extension_id"]),
        **_as_key_headers({"vault key": key}),
        "extension token and key header": auth(extension) + retired_key_header(key),
    }
    await _assert_rejected_without_side_effects(client, spec, ctx, credentials)

    resp = await spec(client, auth(extension), ctx)
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("route", list(EXTENSION_ROUTES), ids=EXTENSION_IDS)
async def test_extension_sessions_from_before_a_rotation_are_rejected(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    await _assert_rejected_without_side_effects(
        client,
        EXTENSION_ROUTES[route],
        ctx,
        {"extension session": auth(ctx["extension_token"])},
    )


@pytest.mark.parametrize("route", list(EXTENSION_ROUTES), ids=EXTENSION_IDS)
async def test_uninitialized_vault_rejects_extension_routes(
    client: httpx.AsyncClient, route: tuple[str, str]
) -> None:
    await _assert_rejected_without_side_effects(
        client,
        EXTENSION_ROUTES[route],
        {"alpha_id": 1},
        {"random token": auth("A" * 43), "missing": []},
        expect_code=False,
    )


async def test_lock_routes_end_only_their_own_kind_of_session(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    extension = ctx["extension_token"]

    assert (
        await client.post("/master_password/lock", headers=auth(extension))
    ).status_code == 200
    assert (
        await client.post("/extension/lock", headers=auth(token))
    ).status_code == 200
    assert (await client.get("/passwords", headers=auth(token))).status_code == 200
    resp = await client.post("/extension/session", headers=auth(extension))
    assert resp.status_code == 200, resp.text

    await client.post("/extension/lock", headers=auth(extension))
    resp = await client.post("/extension/session", headers=auth(extension))
    assert resp.status_code == 401
    assert resp.json()["code"] == "invalid_session"


async def test_an_extension_token_cannot_mint_another(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    ctx = await _seed(client, auth(token))
    resp = await client.post(
        "/extension/sessions",
        json={"browser": "Chrome"},
        headers=auth(ctx["extension_token"]),
    )
    _scope_refusal(resp)
    assert len(app.state.vault_sessions.extension_sessions()) == 1


async def test_the_unlock_route_takes_no_security_key_and_no_extra_fields(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    for body in (
        {"master_password": MASTER_PASSWORD, "security_key": None},
        {"master_password": MASTER_PASSWORD, "browser": "Netscape"},
        {"master_password": MASTER_PASSWORD, "scope": "full"},
    ):
        resp = await client.post("/extension/unlock", json=body)
        assert resp.status_code == 422, body
        assert MASTER_PASSWORD not in resp.text
