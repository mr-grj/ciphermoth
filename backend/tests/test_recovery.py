"""
The recovery code: creating, replacing and removing it, resetting a forgotten
master password with it (with and without security keys), and what someone who
can write the vault file can and cannot do to it.
"""

import re

import httpx
import pytest

import helpers
from device_unlock import DEVICE_UNLOCK_FILE
from tests.authenticator import SoftKey, b64url
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    add_security_key,
    auth,
    confirmation,
    create_recovery_code,
    create_vault,
    data_dir,
    db_execute,
    db_snapshot,
    entry,
    raw_vault_key,
    security_key_answer,
    unlock,
    unlock_with_key,
)

pytestmark = pytest.mark.asyncio

RESET_PASSWORD = "Moth-Recovered-Vault-2028#"
CODE = re.compile(r"^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$")


async def _seeded_vault(client: httpx.AsyncClient) -> str:
    token = await create_vault(client)
    for item in (entry("GitHub", "gh-Secret-1"), entry("Bank", "bank-Secret-2")):
        resp = await client.post("/passwords/create", json=item, headers=auth(token))
        assert resp.status_code == 200, resp.text
    resp = await client.post(
        "/passwords/GitHub/attachments",
        files={"file": ("note.txt", b"attachment bytes", "text/plain")},
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert (
        await client.delete("/passwords/Bank", headers=auth(token))
    ).status_code == 200
    return token


async def _recover(
    client: httpx.AsyncClient,
    code: str,
    password: str = RESET_PASSWORD,
    keep_security_keys: bool = True,
) -> httpx.Response:
    return await client.post(
        "/master_password/recover",
        json={
            "recovery_code": code,
            "new_master_password": password,
            "keep_security_keys": keep_security_keys,
        },
    )


async def _assert_contents(client: httpx.AsyncClient, token: str) -> None:
    resp = await client.get("/passwords/GitHub", headers=auth(token))
    assert resp.json()["password_value"] == "gh-Secret-1"
    attachments = (
        await client.get("/passwords/GitHub/attachments", headers=auth(token))
    ).json()
    resp = await client.get(
        f"/passwords/GitHub/attachments/{attachments[0]['id']}", headers=auth(token)
    )
    assert resp.content == b"attachment bytes"
    trash = (await client.get("/passwords/trash", headers=auth(token))).json()
    assert [t["password_name"] for t in trash] == ["Bank"]


async def test_a_recovery_code_is_shown_once_and_never_stored(
    client: httpx.AsyncClient,
) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    assert CODE.match(code)

    status = (await client.get("/security", headers=auth(token))).json()
    assert status["recovery_code"] is True
    assert status["recovery_code_created"] is not None
    assert (await client.get("/master_password/status")).json()["recovery_code"]

    snapshot = repr(await db_snapshot()).encode()
    canonical = code.replace("-", "")
    for form in (code, canonical, canonical.lower()):
        assert form.encode() not in snapshot
    for path in data_dir().rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert canonical.encode() not in content, path


async def test_creating_one_needs_the_master_password(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    resp = await client.post(
        "/security/recovery-code",
        json={"master_password": "Not-The-Vault-Password-1"},
        headers=auth(token),
    )
    assert resp.status_code == 403
    assert (await client.get("/security", headers=auth(token))).json()[
        "recovery_code"
    ] is False


async def test_the_code_resets_a_forgotten_master_password(
    client: httpx.AsyncClient,
) -> None:
    token = await _seeded_vault(client)
    other = await unlock(client)
    code = await create_recovery_code(client, auth(token))
    old_raw = await raw_vault_key()

    resp = await _recover(client, code)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["security_key_required"] is False
    assert CODE.match(body["recovery_code"]) and body["recovery_code"] != code
    new_token = body["session_token"]

    await _assert_contents(client, new_token)
    # Every other session ended; the vault was re-keyed.
    for stale in (token, other):
        assert (await client.get("/passwords", headers=auth(stale))).status_code == 401
    assert await raw_vault_key(RESET_PASSWORD) != old_raw
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.json()["valid"] is False
    await unlock(client, RESET_PASSWORD)

    # The used code is spent; the new one works.
    assert (await _recover(client, code, NEW_MASTER_PASSWORD)).status_code == 403
    resp = await _recover(client, body["recovery_code"], NEW_MASTER_PASSWORD)
    assert resp.status_code == 200
    await _assert_contents(client, resp.json()["session_token"])


@pytest.mark.parametrize(
    "typed",
    [
        lambda c: c.lower(),
        lambda c: c.replace("-", ""),
        lambda c: " ".join(c.split("-")),
        lambda c: f"  {c}\n",
    ],
)
async def test_the_code_forgives_how_it_was_typed(
    client: httpx.AsyncClient, typed
) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    assert (await _recover(client, typed(code))).status_code == 200


async def test_look_alike_letters_are_read_as_digits() -> None:
    code = "0" * 4 + "-" + "1" * 4 + "-" + "-".join(["ABCD"] * 6)
    assert helpers.canonical_recovery_code(code.replace("0", "O").replace("1", "l"))
    assert helpers.canonical_recovery_code(code) == helpers.canonical_recovery_code(
        code.replace("0", "o").replace("1", "I")
    )
    assert helpers.canonical_recovery_code("ABCD-" * 7 + "ABCU") is None
    assert helpers.canonical_recovery_code("ABCD-" * 7) is None


@pytest.mark.parametrize(
    "code",
    [
        "0000-0000-0000-0000-0000-0000-0000-0000",
        "not a code",
        "",
        "Ü" * 32,
    ],
)
async def test_wrong_codes_change_nothing(client: httpx.AsyncClient, code: str) -> None:
    token = await _seeded_vault(client)
    await create_recovery_code(client, auth(token))
    before = await db_snapshot()
    resp = await _recover(client, code)
    assert resp.status_code in (403, 422), resp.text
    assert await db_snapshot() == before
    assert (await client.get("/passwords", headers=auth(token))).status_code == 200


async def test_the_new_password_must_be_strong(client: httpx.AsyncClient) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    assert (await _recover(client, code, "short")).status_code == 422
    assert (await _recover(client, code)).status_code == 200


async def test_without_a_code_there_is_no_recovery(client: httpx.AsyncClient) -> None:
    await _seeded_vault(client)
    resp = await _recover(client, helpers.new_recovery_code())
    assert resp.status_code == 400
    assert "no recovery code" in resp.json()["detail"]


async def test_replacing_and_removing_the_code(client: httpx.AsyncClient) -> None:
    token = await _seeded_vault(client)
    first = await create_recovery_code(client, auth(token))
    second = await create_recovery_code(client, auth(token))
    assert (await _recover(client, first)).status_code == 403

    resp = await client.post(
        "/security/recovery-code/remove",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["recovery_code"] is False
    assert (await _recover(client, second)).status_code == 400


async def test_a_master_password_change_keeps_the_code(
    client: httpx.AsyncClient,
) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    resp = await _recover(client, code)
    assert resp.status_code == 200, resp.text
    await _assert_contents(client, resp.json()["session_token"])


async def test_recovery_turns_biometric_unlock_off(client: httpx.AsyncClient) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    resp = await client.post(
        "/master_password/device-unlock/enroll",
        json={
            "master_password": MASTER_PASSWORD,
            "credential_id": "touch-id",
            "kind": "passkey",
            "material": "c2FsdA",
            "secret": b64url(b"\x05" * 32),
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert (data_dir() / DEVICE_UNLOCK_FILE).exists()
    assert (await _recover(client, code)).status_code == 200
    assert not (data_dir() / DEVICE_UNLOCK_FILE).exists()


async def test_recovery_keeps_security_keys_working(client: httpx.AsyncClient) -> None:
    token = await _seeded_vault(client)
    key = SoftKey()
    assert (await add_security_key(client, auth(token), key)).status_code == 200
    code = await create_recovery_code(client, auth(token), key)

    resp = await _recover(client, code)
    assert resp.status_code == 200, resp.text
    assert resp.json()["security_key_required"] is True
    await _assert_contents(client, resp.json()["session_token"])

    resp = await client.post(
        "/master_password/unlock", json={"master_password": RESET_PASSWORD}
    )
    assert resp.status_code == 400
    resp = await unlock_with_key(client, key, RESET_PASSWORD)
    assert resp.status_code == 200, resp.text
    security = (
        await client.get("/security", headers=auth(resp.json()["session_token"]))
    ).json()
    assert [k["name"] for k in security["security_keys"]] == ["YubiKey"]


async def test_recovery_after_losing_every_key(client: httpx.AsyncClient) -> None:
    token = await _seeded_vault(client)
    key = SoftKey()
    assert (await add_security_key(client, auth(token), key)).status_code == 200
    code = await create_recovery_code(client, auth(token), key)

    resp = await _recover(client, code, keep_security_keys=False)
    assert resp.status_code == 200, resp.text
    assert resp.json()["security_key_required"] is False
    assert await db_execute("SELECT count(*) FROM security_keys") == [(0,)]
    new_token = await unlock(client, RESET_PASSWORD)
    await _assert_contents(client, new_token)


async def test_the_code_needs_no_security_key_but_changing_it_does(
    client: httpx.AsyncClient,
) -> None:
    token = await _seeded_vault(client)
    key = SoftKey()
    assert (await add_security_key(client, auth(token), key)).status_code == 200
    resp = await client.post(
        "/security/recovery-code",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(token),
    )
    assert resp.status_code == 400
    resp = await client.post(
        "/security/recovery-code",
        json=await confirmation(client, auth(token), key),
        headers=auth(token),
    )
    assert resp.status_code == 200


async def test_a_planted_recovery_key_is_never_sealed_to(
    client: httpx.AsyncClient,
) -> None:
    """Someone who can write the file but does not know the master password
    replaces the recovery public key with their own, hoping the next master
    password change seals the new vault key to it. The binding refuses."""
    token = await _seeded_vault(client)
    await create_recovery_code(client, auth(token))
    _, theirs = await helpers.create_recovery(b"\x01" * 32)
    await db_execute(
        "UPDATE recovery SET public_key = :key, salt = :salt",
        key=theirs.public_key,
        salt=theirs.salt,
    )
    before = await db_snapshot()
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 400
    assert "recovery code record" in resp.json()["detail"]
    assert await db_snapshot() == before


async def test_a_recovery_record_for_another_vault_key_opens_nothing(
    client: httpx.AsyncClient,
) -> None:
    """A recovery row copied from another vault (or left by an older key) whose
    code the attacker knows: it opens a key, but not this vault's."""
    token = await _seeded_vault(client)
    await create_recovery_code(client, auth(token))
    code, theirs = await helpers.create_recovery(b"\x02" * 32)
    await db_execute(
        "UPDATE recovery SET salt = :salt, public_key = :public_key, "
        "sealed_key = :sealed_key, binding = :binding",
        salt=theirs.salt,
        public_key=theirs.public_key,
        sealed_key=theirs.sealed_key,
        binding=theirs.binding,
    )
    before = await db_snapshot()
    resp = await _recover(client, code)
    assert resp.status_code == 400
    assert await db_snapshot() == before


async def test_a_damaged_sealed_key_is_damage_not_a_wrong_code(
    client: httpx.AsyncClient,
) -> None:
    token = await _seeded_vault(client)
    code = await create_recovery_code(client, auth(token))
    rows = await db_execute("SELECT sealed_key FROM recovery")
    sealed = bytearray(rows[0][0])
    sealed[-1] ^= 1
    await db_execute("UPDATE recovery SET sealed_key = :s", s=bytes(sealed))
    resp = await _recover(client, code)
    assert resp.status_code == 400
    assert "does not verify" in resp.json()["detail"]


def test_recovery_and_security_routes_are_rate_limited() -> None:
    """The test environment raises every limit (CIPHERMOTH_RATE_LIMIT); this
    checks each route still declares one."""
    from api.rate_limit import limiter

    limited = set(limiter._route_limits)
    for route in (
        "master_password.recover",
        "master_password.unlock_challenge",
        "master_password.unlock",
        "security.add_security_key",
        "security.remove_security_key",
        "security.create_recovery_code",
        "security.remove_recovery_code",
    ):
        assert f"api.endpoints.{route}" in limited, route


async def test_security_key_answers_never_reach_the_logs(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    token = await create_vault(client)
    key = SoftKey()
    assert (await add_security_key(client, auth(token), key)).status_code == 200
    code = await create_recovery_code(client, auth(token), key)
    answer = await security_key_answer(client, key)
    await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
    )
    await _recover(client, code)
    logged = caplog.text
    for secret in (answer["prf_output"], answer["signature"], code, MASTER_PASSWORD):
        assert secret not in logged
