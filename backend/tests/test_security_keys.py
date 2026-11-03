"""
Security keys as a second factor: registration, unlock, every confirmation, and
the ways an answer can be wrong, replayed, misdirected or planted.
"""

import hashlib
import io
import os

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import helpers
from tests.authenticator import SoftKey, b64url, unb64url
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    add_security_key,
    auth,
    confirmation,
    create_vault,
    db_execute,
    db_snapshot,
    entry,
    security_key_answer,
    unlock,
    unlock_with_key,
)

pytestmark = pytest.mark.asyncio


async def _vault_with_key(
    client: httpx.AsyncClient, key: SoftKey | None = None
) -> tuple[str, SoftKey]:
    token = await create_vault(client)
    resp = await client.post(
        "/passwords/create", json=entry("GitHub", "gh-Secret-1"), headers=auth(token)
    )
    assert resp.status_code == 200, resp.text
    key = key or SoftKey()
    resp = await add_security_key(client, auth(token), key)
    assert resp.status_code == 200, resp.text
    return token, key


async def _vault_row() -> dict:
    rows = await db_execute(
        "SELECT kdf_memory_kib, kdf_iterations, kdf_lanes, kdf_salt, password_check,"
        " factor_key_escrow FROM vault"
    )
    memory, iterations, lanes, salt, check, escrow = rows[0]
    return {
        "params": helpers.KdfParams(memory, iterations, lanes),
        "salt": salt,
        "password_check": check,
        "escrow": escrow,
    }


def _hkdf(key: bytes, label: str) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, label.encode()).derive(key)


async def test_the_first_key_turns_the_second_factor_on(
    client: httpx.AsyncClient,
) -> None:
    token, key = await _vault_with_key(client)

    status = (await client.get("/master_password/status")).json()
    assert status == {
        "initialized": True,
        "security_key_required": True,
        "recovery_code": False,
    }
    security = (await client.get("/security", headers=auth(token))).json()
    assert security["security_key_required"] is True
    assert [k["name"] for k in security["security_keys"]] == ["YubiKey"]
    assert security["security_keys"][0]["rp_id"] == "localhost"

    # The session that turned it on keeps working: the vault key did not change.
    resp = await client.get("/passwords/GitHub", headers=auth(token))
    assert resp.status_code == 200
    assert resp.json()["password_value"] == "gh-Secret-1"


async def test_the_master_password_alone_no_longer_unlocks(
    client: httpx.AsyncClient,
) -> None:
    await _vault_with_key(client)
    resp = await client.post(
        "/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    assert resp.status_code == 400
    assert "security key" in resp.json()["detail"]

    resp = await unlock_with_key(client, key=SoftKey())
    assert resp.status_code == 403
    assert "not registered" in resp.json()["detail"]


async def test_password_and_key_unlock_the_vault(client: httpx.AsyncClient) -> None:
    _, key = await _vault_with_key(client)
    resp = await unlock_with_key(client, key)
    assert resp.status_code == 200, resp.text
    token = resp.json()["session_token"]
    resp = await client.get("/passwords/GitHub", headers=auth(token))
    assert resp.json()["password_value"] == "gh-Secret-1"

    security = (await client.get("/security", headers=auth(token))).json()
    assert security["security_keys"][0]["last_used"] is not None


async def test_a_wrong_password_with_the_right_key_is_a_wrong_password(
    client: httpx.AsyncClient,
) -> None:
    _, key = await _vault_with_key(client)
    resp = await unlock_with_key(client, key, WRONG_MASTER_PASSWORD)
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": False,
        "session_token": None,
        "idle_timeout_ms": None,
    }
    assert (await unlock_with_key(client, key)).status_code == 200


async def test_the_vault_file_alone_cannot_even_test_a_password(
    client: httpx.AsyncClient,
) -> None:
    """With a second factor the commitment covers password and factor key, so
    a copy of the file gives no way to confirm a password guess."""
    await _vault_with_key(client)
    row = await _vault_row()
    derived = helpers.argon2id(MASTER_PASSWORD, row["salt"], row["params"])
    assert row["password_check"] != _hkdf(derived, "ciphermoth/v2/password-commitment")
    material = helpers.KeyMaterial(
        params=row["params"],
        salt=row["salt"],
        password_check=row["password_check"],
        wrapped_key=b"",
        key_check=b"",
        second_factor=True,
    )
    # Every factor key but the real one fails the commitment.
    for _ in range(3):
        assert (
            helpers.open_key_material(derived, material, helpers.new_factor_key())
            is None
        )


async def test_answers_are_single_use(client: httpx.AsyncClient) -> None:
    _, key = await _vault_with_key(client)
    answer = await security_key_answer(client, key)
    body = {"master_password": MASTER_PASSWORD, "security_key": answer}
    assert (await client.post("/master_password/unlock", json=body)).status_code == 200
    resp = await client.post("/master_password/unlock", json=body)
    assert resp.status_code == 403
    assert "expired or was already used" in resp.json()["detail"]


async def test_a_challenge_is_only_good_for_its_purpose_and_session(
    client: httpx.AsyncClient,
) -> None:
    token, key = await _vault_with_key(client)
    other = (await unlock_with_key(client, key)).json()["session_token"]

    # A session's confirmation challenge cannot unlock.
    answer = await security_key_answer(client, key, auth(token))
    resp = await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
    )
    assert resp.status_code == 403

    # An unlock challenge cannot confirm a change.
    answer = await security_key_answer(client, key)
    resp = await client.post(
        "/security/recovery-code",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
        headers=auth(token),
    )
    assert resp.status_code == 403

    # Another session's challenge cannot confirm this session's change.
    answer = await security_key_answer(client, key, auth(other))
    resp = await client.post(
        "/security/recovery-code",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
        headers=auth(token),
    )
    assert resp.status_code == 403
    assert (await client.get("/security", headers=auth(token))).json()[
        "recovery_code"
    ] is False


async def test_a_challenge_the_server_never_issued_is_refused(
    client: httpx.AsyncClient,
) -> None:
    _, key = await _vault_with_key(client)
    descriptor = (await client.post("/master_password/unlock/challenge")).json()[
        "keys"
    ][0]
    answer = key.answer(b64url(b"\x01" * 32), descriptor["prf_salt"])
    resp = await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("label", "options"),
    [
        ("another site", {"origin": "https://evil.test"}),
        ("a look-alike subdomain", {"origin": "https://localhost.evil.test"}),
        ("plain http elsewhere", {"origin": "http://intranet.test"}),
        ("another relying party", {"rp_id": "evil.test"}),
        ("a registration instead", {"kind": "webauthn.create"}),
    ],
)
async def test_answers_for_another_site_are_refused(
    client: httpx.AsyncClient, label: str, options: dict
) -> None:
    _, key = await _vault_with_key(client)
    answer = await security_key_answer(client, key, **options)
    resp = await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
    )
    assert resp.status_code == 403, label
    assert "did not verify" in resp.json()["detail"], label


async def test_the_key_must_have_been_touched(client: httpx.AsyncClient) -> None:
    _, key = await _vault_with_key(client)
    key.user_present = False
    resp = await unlock_with_key(client, key)
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "part", ["signature", "authenticator_data", "client_data_json"]
)
async def test_altered_answers_are_refused(
    client: httpx.AsyncClient, part: str
) -> None:
    _, key = await _vault_with_key(client)
    answer = await security_key_answer(client, key)
    raw = bytearray(unb64url(answer[part]))
    raw[-2] ^= 0x01
    answer[part] = b64url(bytes(raw))
    resp = await client.post(
        "/master_password/unlock",
        json={"master_password": MASTER_PASSWORD, "security_key": answer},
    )
    assert resp.status_code == 403


async def test_a_counter_that_goes_backwards_is_refused(
    client: httpx.AsyncClient,
) -> None:
    _, key = await _vault_with_key(client)
    assert (await unlock_with_key(client, key)).status_code == 200
    key.counter -= 2  # a clone that started from an older state
    resp = await unlock_with_key(client, key)
    assert resp.status_code == 403
    assert "cloned" in resp.json()["detail"]


async def test_the_key_must_have_verified_its_user(client: httpx.AsyncClient) -> None:
    """Every answer must carry the key's user verification (its PIN): without it
    the key would produce another PRF secret, and a stolen key would need no PIN."""
    _, key = await _vault_with_key(client)
    key.user_verified = False
    resp = await unlock_with_key(client, key)
    assert resp.status_code == 403
    assert "did not verify" in resp.json()["detail"]


async def test_a_different_secret_from_the_key_opens_nothing(
    client: httpx.AsyncClient,
) -> None:
    """The signature verifies but the PRF output is not the one the factor key
    was wrapped under (a reset key, another verification mode)."""
    _, key = await _vault_with_key(client)
    key._cred_random_uv = os.urandom(32)
    resp = await unlock_with_key(client, key)
    assert resp.status_code == 403
    assert "secret does not open this vault" in resp.json()["detail"]


async def test_registration_needs_user_verification(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    resp = await add_security_key(client, auth(token), SoftKey(user_verified=False))
    assert resp.status_code == 400


@pytest.mark.parametrize("column", ["public_key", "prf_salt", "rp_id", "credential_id"])
async def test_a_planted_key_row_opens_nothing(
    client: httpx.AsyncClient, column: str
) -> None:
    """Someone who can write the file swaps one identifying value of a key row:
    either the signature or the factor key's associated data stops verifying."""
    _, key = await _vault_with_key(client)
    attacker = SoftKey()
    other = SoftKey()
    await _vault_row()
    if column == "public_key":
        value = attacker.cose_public_key()
        attacker.credential_id = key.credential_id
        attacker.counter = key.counter
        planted = attacker
    elif column == "prf_salt":
        value = b"\x07" * 32
        planted = key
    elif column == "rp_id":
        value = "evil.test"
        planted = SoftKey(rp_id="evil.test", origin="https://evil.test")
        planted._private, planted._cred_random = key._private, key._cred_random
        planted.credential_id, planted.counter = key.credential_id, key.counter
    else:
        value = other.credential_id
        planted = key
        key.credential_id = other.credential_id
    await db_execute(f"UPDATE security_keys SET {column} = :value", value=value)
    before = await db_snapshot()
    resp = await unlock_with_key(client, planted)
    assert resp.status_code == 403, resp.text
    after = await db_snapshot()
    assert after["vault"] == before["vault"]


async def test_a_second_key_needs_the_first_and_either_unlocks(
    client: httpx.AsyncClient,
) -> None:
    token, first = await _vault_with_key(client)
    second = SoftKey()

    resp = await add_security_key(client, auth(token), second, name="Backup")
    assert resp.status_code == 400
    assert "security key" in resp.json()["detail"]

    resp = await add_security_key(
        client, auth(token), second, name="Backup", confirm_with=first
    )
    assert resp.status_code == 200, resp.text
    assert [k["name"] for k in resp.json()["security_keys"]] == ["YubiKey", "Backup"]

    for key in (first, second):
        assert (await unlock_with_key(client, key)).status_code == 200

    options = (await client.post("/security/keys/options", headers=auth(token))).json()
    assert set(options["exclude_credentials"]) == {first.id, second.id}


async def test_the_same_key_cannot_be_registered_twice(
    client: httpx.AsyncClient,
) -> None:
    token, key = await _vault_with_key(client)
    resp = await add_security_key(client, auth(token), key, confirm_with=key)
    assert resp.status_code == 400
    assert "already registered" in resp.json()["detail"]


async def test_registration_must_come_from_the_key_that_answers(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    options = (await client.post("/security/keys/options", headers=auth(token))).json()
    new, impostor = SoftKey(), SoftKey()
    resp = await client.post(
        "/security/keys",
        json={
            "name": "Mixed",
            "confirmation": {"master_password": MASTER_PASSWORD},
            "registration": new.register(options["challenge"]),
            "assertion": impostor.answer(
                options["secret_challenge"], options["prf_salt"]
            ),
        },
        headers=auth(token),
    )
    assert resp.status_code == 400
    assert (await client.get("/master_password/status")).json()[
        "security_key_required"
    ] is False


async def test_registration_challenges_are_bound_to_their_role(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    options = (await client.post("/security/keys/options", headers=auth(token))).json()
    key = SoftKey()
    resp = await client.post(
        "/security/keys",
        json={
            "name": "Swapped",
            "confirmation": {"master_password": MASTER_PASSWORD},
            # The two challenges swapped: each is refused for the other role.
            "registration": key.register(options["secret_challenge"]),
            "assertion": key.answer(options["challenge"], options["prf_salt"]),
        },
        headers=auth(token),
    )
    assert resp.status_code == 400


async def test_registration_from_another_site_is_refused(
    client: httpx.AsyncClient,
) -> None:
    token = await create_vault(client)
    options = (await client.post("/security/keys/options", headers=auth(token))).json()
    key = SoftKey()
    resp = await client.post(
        "/security/keys",
        json={
            "name": "Phished",
            "confirmation": {"master_password": MASTER_PASSWORD},
            # The browser was on evil.test, but the key was asked for localhost.
            "registration": key.register(
                options["challenge"], origin="https://evil.test"
            ),
            "assertion": key.answer(options["secret_challenge"], options["prf_salt"]),
        },
        headers=auth(token),
    )
    assert resp.status_code == 400


async def test_registering_needs_the_master_password(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    before = await db_snapshot()
    resp = await add_security_key(
        client, auth(token), SoftKey(), master_password=WRONG_MASTER_PASSWORD
    )
    assert resp.status_code == 403
    assert await db_snapshot() == before


async def test_key_names_are_encrypted(client: httpx.AsyncClient) -> None:
    token = await create_vault(client)
    resp = await add_security_key(
        client, auth(token), SoftKey(), name="Grandma's drawer key"
    )
    assert resp.status_code == 200
    rows = await db_execute("SELECT name FROM security_keys")
    assert b"Grandma" not in rows[0][0]


async def test_removing_keys_and_turning_the_second_factor_off(
    client: httpx.AsyncClient,
) -> None:
    token, first = await _vault_with_key(client)
    second = SoftKey()
    resp = await add_security_key(
        client, auth(token), second, name="Backup", confirm_with=first
    )
    first_id, second_id = (k["id"] for k in resp.json()["security_keys"])

    # A lost key is removed with the other one.
    resp = await client.post(
        f"/security/keys/{first_id}/remove",
        json=await confirmation(client, auth(token), second),
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["security_key_required"] is True
    assert (await unlock_with_key(client, first)).status_code == 403

    # Removing the last key needs that key, and turns the factor off.
    resp = await client.post(
        f"/security/keys/{second_id}/remove",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(token),
    )
    assert resp.status_code == 400
    resp = await client.post(
        f"/security/keys/{second_id}/remove",
        json=await confirmation(client, auth(token), second),
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["security_key_required"] is False
    row = await _vault_row()
    assert row["escrow"] is None
    derived = helpers.argon2id(MASTER_PASSWORD, row["salt"], row["params"])
    assert row["password_check"] == _hkdf(derived, "ciphermoth/v2/password-commitment")
    new_token = await unlock(client)
    resp = await client.get("/passwords/GitHub", headers=auth(new_token))
    assert resp.json()["password_value"] == "gh-Secret-1"


async def test_a_master_password_change_keeps_the_keys(
    client: httpx.AsyncClient,
) -> None:
    token, key = await _vault_with_key(client)
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )
    assert resp.status_code == 400

    answer = await security_key_answer(client, key, auth(token))
    resp = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
            "security_key": answer,
        },
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text

    assert (await unlock_with_key(client, key, MASTER_PASSWORD)).json()[
        "valid"
    ] is False
    resp = await unlock_with_key(client, key, NEW_MASTER_PASSWORD)
    new_token = resp.json()["session_token"]
    resp = await client.get("/passwords/GitHub", headers=auth(new_token))
    assert resp.json()["password_value"] == "gh-Secret-1"
    security = (await client.get("/security", headers=auth(new_token))).json()
    assert [k["name"] for k in security["security_keys"]] == ["YubiKey"]


async def test_backups_need_the_key_but_restore_with_the_password(
    client: httpx.AsyncClient,
) -> None:
    token, key = await _vault_with_key(client)
    resp = await client.post(
        "/passwords/backup",
        json={"master_password": MASTER_PASSWORD},
        headers=auth(token),
    )
    assert resp.status_code == 400
    resp = await client.post(
        "/passwords/backup",
        json=await confirmation(client, auth(token), key),
        headers=auth(token),
    )
    assert resp.status_code == 200, resp.text
    backup = resp.content

    await db_execute("DELETE FROM attachments")
    await db_execute("DELETE FROM entries")
    await db_execute("DELETE FROM security_keys")
    await db_execute("DELETE FROM vault")
    fresh = await create_vault(client, NEW_MASTER_PASSWORD)
    resp = await client.post(
        "/passwords/import",
        data={"master_password": MASTER_PASSWORD, "on_conflict": "skip"},
        files={
            "file": ("vault.cmbackup", io.BytesIO(backup), "application/octet-stream")
        },
        headers=auth(fresh),
    )
    assert resp.status_code == 200, resp.text
    resp = await client.get("/passwords/GitHub", headers=auth(fresh))
    assert resp.json()["password_value"] == "gh-Secret-1"


async def test_biometric_enrollment_needs_the_key(client: httpx.AsyncClient) -> None:
    token, key = await _vault_with_key(client)
    body = {
        "master_password": MASTER_PASSWORD,
        "credential_id": "touch-id",
        "kind": "passkey",
        "material": "c2FsdA",
        "secret": b64url(b"\x05" * 32),
    }
    resp = await client.post(
        "/master_password/device-unlock/enroll", json=body, headers=auth(token)
    )
    assert resp.status_code == 400
    body["security_key"] = await security_key_answer(client, key, auth(token))
    resp = await client.post(
        "/master_password/device-unlock/enroll", json=body, headers=auth(token)
    )
    assert resp.status_code == 200, resp.text

    # Touch ID still opens the vault on its own: the user chose to keep it.
    resp = await client.post(
        "/master_password/device-unlock/unlock",
        json={"credential_id": "touch-id", "secret": body["secret"]},
    )
    assert resp.json()["valid"] is True


async def test_status_tells_nothing_about_keys_before_unlock(
    client: httpx.AsyncClient,
) -> None:
    await _vault_with_key(client)
    challenge = (await client.post("/master_password/unlock/challenge")).json()
    assert set(challenge) == {"challenge", "timeout_ms", "keys"}
    assert set(challenge["keys"][0]) == {"credential_id", "rp_id", "prf_salt"}
    resp = await client.get("/security")
    assert resp.status_code == 401


async def test_a_vault_without_keys_has_no_unlock_challenge(
    client: httpx.AsyncClient,
) -> None:
    await create_vault(client)
    resp = await client.post("/master_password/unlock/challenge")
    assert resp.status_code == 400


async def test_challenges_are_bounded_and_expire() -> None:
    from webauthn import MAX_PENDING_CHALLENGES, Challenges, VerificationFailed

    now = [0.0]
    challenges = Challenges(clock=lambda: now[0])
    first = challenges.issue("unlock")
    for _ in range(MAX_PENDING_CHALLENGES):
        challenges.issue("unlock")
    with pytest.raises(VerificationFailed):
        challenges.consume(first, "unlock")
    late = challenges.issue("unlock")
    now[0] += 301
    with pytest.raises(VerificationFailed):
        challenges.consume(late, "unlock")
    fresh = challenges.issue("confirm", b"session", b"data")
    with pytest.raises(VerificationFailed):
        challenges.consume(fresh, "confirm", b"other session")
    with pytest.raises(VerificationFailed):
        challenges.consume(fresh, "confirm", b"session")  # used up by the failure
    ok = challenges.issue("confirm", b"session", b"data")
    assert challenges.consume(ok, "confirm", b"session") == b"data"


async def test_the_session_binding_is_not_the_token() -> None:
    from webauthn import session_binding

    token = "a" * 43
    assert session_binding(token) != hashlib.sha256(token.encode()).digest()
    assert session_binding(token) == session_binding(token)
