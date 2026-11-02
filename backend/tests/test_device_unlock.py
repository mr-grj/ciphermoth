"""Biometric unlock: what an enrollment can open, and everything that ends it."""

import base64
import json
import os
import stat
import struct

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import api.endpoints.deps as deps
from device_unlock import DEVICE_UNLOCK_FILE, DeviceUnlockStore
from tests.support import (
    MASTER_PASSWORD,
    NEW_MASTER_PASSWORD,
    auth,
    create_vault,
    data_dir,
    entry,
    raw_vault_key,
    stored_vault_key,
    unlock,
)

STATUS = "/master_password/device-unlock"
UNLOCK = f"{STATUS}/unlock"
ENROLL = f"{STATUS}/enroll"
DEVICE = "device-one"
DAY = 86_400


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


SECRET_BYTES = bytes(range(32))
SECRET = encode(SECRET_BYTES)
OTHER_SECRET = encode(bytes(range(1, 33)))


def enrollment(**overrides: object) -> dict:
    return {
        "master_password": MASTER_PASSWORD,
        "credential_id": DEVICE,
        "kind": "secure-enclave",
        "material": "b3BhcXVl",
        **overrides,
    } | ({"secret": SECRET} if "secret" not in overrides else {})


def store_file():
    return data_dir() / DEVICE_UNLOCK_FILE


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    current = Clock()
    monkeypatch.setattr(
        deps,
        "DeviceUnlockStore",
        lambda folder: DeviceUnlockStore(folder, clock=current),
    )
    return current


async def enrolled_vault(client: httpx.AsyncClient) -> str:
    token = await create_vault(client)
    response = await client.post(ENROLL, json=enrollment(), headers=auth(token))
    assert response.status_code == 200, response.text
    return token


async def test_an_enrolled_device_opens_a_working_session(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await enrolled_vault(client)
    created = await client.post(
        "/passwords/create", json=entry("alpha"), headers=auth(token)
    )
    assert created.status_code == 200, created.text

    response = await client.post(
        UNLOCK, json={"credential_id": DEVICE, "secret": SECRET}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["idle_timeout_ms"] > 0
    listed = await client.get("/passwords", headers=auth(body["session_token"]))
    assert [row["password_name"] for row in listed.json()] == ["alpha"]


async def test_status_tells_a_locked_client_only_what_its_authenticator_needs(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)

    status = (await client.get(STATUS)).json()

    assert status == {
        "enrollments": [
            {"credential_id": DEVICE, "kind": "secure-enclave", "material": "b3BhcXVl"}
        ],
        "password_required": False,
        "password_interval_days": 14,
    }


async def test_enrolling_needs_a_session_and_the_master_password(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await create_vault(client)

    assert (await client.post(ENROLL, json=enrollment())).status_code == 401
    wrong = await client.post(
        ENROLL,
        json=enrollment(master_password="Not-The-Master-Password-1"),
        headers=auth(token),
    )

    assert wrong.status_code == 403
    assert not store_file().exists()


@pytest.mark.parametrize(
    "secret",
    [encode(b"short"), encode(bytes(33)), "not base64!", ""],
    ids=["short", "long", "alphabet", "empty"],
)
async def test_a_secret_must_be_a_32_byte_key(
    client: httpx.AsyncClient, clock: Clock, secret: str
) -> None:
    token = await create_vault(client)

    response = await client.post(
        ENROLL, json=enrollment(secret=secret), headers=auth(token)
    )

    assert response.status_code == 422
    assert secret == "" or secret not in response.text


async def test_the_wrong_secret_opens_nothing_and_does_not_end_the_enrollment(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)

    wrong = await client.post(
        UNLOCK, json={"credential_id": DEVICE, "secret": OTHER_SECRET}
    )
    unknown = await client.post(
        UNLOCK, json={"credential_id": "nobody", "secret": SECRET}
    )

    assert wrong.json() == {
        "valid": False,
        "session_token": None,
        "idle_timeout_ms": None,
        "password_required": False,
    }
    assert unknown.json()["valid"] is False
    again = await client.post(UNLOCK, json={"credential_id": DEVICE, "secret": SECRET})
    assert again.json()["valid"] is True


async def test_the_password_reminder_comes_due_and_a_password_unlock_clears_it(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)
    credentials = {"credential_id": DEVICE, "secret": SECRET}

    clock.now += 14 * DAY - 1
    assert (await client.post(UNLOCK, json=credentials)).json()["valid"] is True

    clock.now += 1
    due = (await client.post(UNLOCK, json=credentials)).json()
    assert due["valid"] is False
    assert due["password_required"] is True
    assert due["session_token"] is None
    assert (await client.get(STATUS)).json()["password_required"] is True

    await unlock(client)

    assert (await client.get(STATUS)).json()["password_required"] is False
    assert (await client.post(UNLOCK, json=credentials)).json()["valid"] is True


async def test_a_wrong_password_does_not_clear_the_reminder(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)
    clock.now += 14 * DAY

    response = await client.post(
        "/master_password/unlock", json={"master_password": "Not-The-Password-12"}
    )

    assert response.json()["valid"] is False
    assert (await client.get(STATUS)).json()["password_required"] is True


async def test_moving_the_clock_back_cannot_postpone_the_reminder(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)

    clock.now -= DAY

    response = await client.post(
        UNLOCK, json={"credential_id": DEVICE, "secret": SECRET}
    )
    assert response.json()["password_required"] is True


async def test_the_reminder_interval_can_be_chosen_from_the_offered_ones(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await enrolled_vault(client)

    changed = await client.patch(
        STATUS, json={"password_interval_days": 7}, headers=auth(token)
    )
    refused = await client.patch(
        STATUS, json={"password_interval_days": 3650}, headers=auth(token)
    )

    assert changed.json()["password_interval_days"] == 7
    assert refused.status_code == 422
    clock.now += 7 * DAY
    assert (await client.get(STATUS)).json()["password_required"] is True


async def test_changing_the_master_password_ends_every_enrollment(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await enrolled_vault(client)
    saved = store_file().read_bytes()

    response = await client.patch(
        "/master_password/update",
        json={
            "master_password": MASTER_PASSWORD,
            "new_master_password": NEW_MASTER_PASSWORD,
        },
        headers=auth(token),
    )

    assert response.status_code == 200, response.text
    assert not store_file().exists()
    credentials = {"credential_id": DEVICE, "secret": SECRET}
    assert (await client.post(UNLOCK, json=credentials)).json()["valid"] is False

    # A file put back later still holds the old vault key, which opens nothing now.
    store_file().write_bytes(saved)
    stale = await client.post(UNLOCK, json=credentials)
    assert stale.json()["valid"] is False
    assert stale.json()["password_required"] is True
    assert not store_file().exists()


async def test_forgetting_a_device_ends_its_unlock_only(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await enrolled_vault(client)
    other = await client.post(
        ENROLL,
        json=enrollment(credential_id="device-two", secret=OTHER_SECRET),
        headers=auth(token),
    )
    assert other.status_code == 200, other.text

    await client.delete(f"{STATUS}/{DEVICE}", headers=auth(token))

    removed = await client.post(
        UNLOCK, json={"credential_id": DEVICE, "secret": SECRET}
    )
    kept = await client.post(
        UNLOCK, json={"credential_id": "device-two", "secret": OTHER_SECRET}
    )
    assert removed.json()["valid"] is False
    assert kept.json()["valid"] is True


async def test_forgetting_the_last_device_removes_the_file(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await enrolled_vault(client)

    await client.delete(f"{STATUS}/{DEVICE}", headers=auth(token))

    assert not store_file().exists()


async def test_enrollments_are_bounded(client: httpx.AsyncClient, clock: Clock) -> None:
    token = await create_vault(client)
    for number in range(8):
        response = await client.post(
            ENROLL,
            json=enrollment(credential_id=f"device-{number}"),
            headers=auth(token),
        )
        assert response.status_code == 200, response.text

    refused = await client.post(
        ENROLL, json=enrollment(credential_id="device-9"), headers=auth(token)
    )
    replaced = await client.post(
        ENROLL, json=enrollment(credential_id="device-0"), headers=auth(token)
    )

    assert refused.status_code == 400
    assert replaced.status_code == 200, replaced.text


async def test_the_file_is_private_and_holds_no_key_or_password(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    await enrolled_vault(client)
    raw = await raw_vault_key()
    content = store_file().read_bytes()

    assert stat.S_IMODE(os.stat(store_file()).st_mode) == 0o600
    for forbidden in (
        raw,
        base64.b64encode(raw),
        (await stored_vault_key()).encode(),
        SECRET.encode(),
        SECRET_BYTES,
        MASTER_PASSWORD.encode(),
    ):
        assert forbidden not in content


async def test_responses_never_carry_the_wrapped_key(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    token = await create_vault(client)

    enrolled = await client.post(ENROLL, json=enrollment(), headers=auth(token))
    status = await client.get(STATUS)

    wrapped = json.loads(store_file().read_bytes())["enrollments"][0]["wrapped_key"]
    assert wrapped not in enrolled.text
    assert wrapped not in status.text


async def test_the_wrapping_matches_its_specification(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    """Reference construction from the primitives (docs/VAULT_FORMAT.md section 3)."""
    await enrolled_vault(client)
    stored = json.loads(store_file().read_bytes())["enrollments"][0]["wrapped_key"]
    sealed = base64.urlsafe_b64decode(stored + "=" * (-len(stored) % 4))
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ciphermoth/v2/device-unlock",
    ).derive(SECRET_BYTES)
    role, credential = b"device-unlock", DEVICE.encode()
    associated_data = (
        b"\x02ciphermoth/v2"
        + struct.pack(">I", len(role))
        + role
        + struct.pack(">I", len(credential))
        + credential
    )

    assert sealed[:1] == b"\x02"
    assert (
        AESGCM(wrapping_key).decrypt(sealed[1:13], sealed[13:], associated_data)
        == await raw_vault_key()
    )


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[]", b'{"version": 99}', b'{"enrollments": [{"kind": "x"}]}'],
    ids=["garbage", "list", "newer", "malformed"],
)
async def test_a_damaged_file_never_blocks_the_master_password(
    client: httpx.AsyncClient, clock: Clock, content: bytes
) -> None:
    await enrolled_vault(client)
    store_file().write_bytes(content)

    assert (await client.get(STATUS)).json()["enrollments"] == []
    refused = await client.post(
        UNLOCK, json={"credential_id": DEVICE, "secret": SECRET}
    )
    assert refused.json()["valid"] is False
    assert await unlock(client)


async def test_a_new_vault_inherits_no_enrollment(
    client: httpx.AsyncClient, clock: Clock
) -> None:
    store_file().write_text(
        json.dumps(
            {
                "enrollments": [
                    {
                        "credential_id": DEVICE,
                        "kind": "passkey",
                        "material": "c2FsdA",
                        "wrapped_key": "AAAA",
                    }
                ],
                "last_password_at": clock.now,
            }
        )
    )

    assert (await client.get(STATUS)).json()["enrollments"] == []
    await create_vault(client)

    assert not store_file().exists()
