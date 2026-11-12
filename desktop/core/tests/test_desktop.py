import base64
import json
import os
import stat
from urllib.parse import quote

import pytest
from core_client import CANCEL, ERROR, REQUEST, SHUTDOWN, Core, frame, multipart

PASSWORD = "Desktop-Canary-Master-2026!"
SECRET = "Desktop-secret-canary-9A!"


@pytest.fixture
def core(tmp_path):
    instance = Core(tmp_path / "data", tmp_path / "core.log")
    yield instance
    instance.kill()


def api(core, method, path, payload=None, token=None):
    headers = [["content-type", "application/json"]]
    if token:
        headers.append(["x-ciphermoth-session", token])
    reply = core.call(
        method,
        "/api" + path,
        json.dumps(payload).encode() if payload is not None else b"",
        headers,
    )
    assert reply.kind == 2, reply
    return reply.header["status"], json.loads(reply.body) if reply.body else None


def create(core):
    status, data = api(
        core, "POST", "/master_password/create", {"master_password": PASSWORD}
    )
    assert status == 200, data
    assert "key_derivation" not in data
    assert len(data["session_token"]) == 43
    return data["session_token"]


def entry(core, token, name="Desktop entry", **extra):
    payload = {"password_name": name, "password_value": SECRET, **extra}
    status, data = api(core, "POST", "/passwords/create", payload, token)
    assert status == 200, data
    return payload


def native(core, operation, path, token, **fields):
    request_id = core.next_id
    core.next_id += 1
    core.send(
        frame(
            REQUEST,
            request_id,
            {"native": operation, "file": str(path), "session": token},
            json.dumps(fields).encode(),
        )
    )
    reply = core.wait(request_id, timeout=120)
    assert reply.kind == 2, reply
    return reply.header["status"], json.loads(reply.body)


def test_fresh_create_unlock_lock(core):
    assert api(core, "GET", "/master_password/status") == (
        200,
        {"initialized": False, "security_key_required": False, "recovery_code": False},
    )
    token = create(core)
    assert api(core, "GET", "/passwords", token=token)[0] == 200
    assert (
        api(
            core,
            "POST",
            "/master_password/unlock",
            {"master_password": "Wrong-password-1!"},
        )[1]["valid"]
        is False
    )
    assert api(core, "POST", "/master_password/lock", token=token)[0] == 200
    assert api(core, "GET", "/passwords", token=token)[0] == 401
    assert (
        api(core, "POST", "/master_password/unlock", {"master_password": PASSWORD})[1][
            "valid"
        ]
        is True
    )


def test_a_biometric_unlock_gets_the_same_native_deadline_as_a_password(core):
    token = create(core)
    secret = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    credential = {"credential_id": "this-mac", "secret": secret}
    enrolled = api(
        core,
        "POST",
        "/master_password/device-unlock/enroll",
        {
            **credential,
            "master_password": PASSWORD,
            "kind": "secure-enclave",
            "material": "b3BhcXVl",
        },
        token=token,
    )
    assert enrolled[0] == 200, enrolled

    reply = core.call(
        "POST",
        "/api/master_password/device-unlock/unlock",
        headers=[["content-type", "application/json"]],
        body=json.dumps(credential).encode(),
    )

    assert json.loads(reply.body)["valid"] is True
    assert 0 < reply.header["session"]["expires_in_ms"] <= 120_000


def test_native_session_deadline_is_authoritative_and_contains_no_token(core):
    import time

    token = create(core)
    headers = [["x-ciphermoth-session", token]]
    first = core.call("GET", "/api/master_password/session", headers=headers)
    time.sleep(0.05)
    second = core.call("GET", "/api/master_password/session", headers=headers)
    assert set(first.header["session"]) == {"expires_in_ms"}
    assert (
        second.header["session"]["expires_in_ms"]
        < first.header["session"]["expires_in_ms"]
    )
    assert token not in json.dumps(second.header)
    api(core, "POST", "/master_password/lock", token=token)
    ended = core.call("GET", "/api/master_password/session", headers=headers)
    assert ended.header["session"] == {"expires_in_ms": 0}


def test_persistence_permissions_and_no_plaintext(core, tmp_path):
    token = create(core)
    entry(core, token)
    core.close_stdin()
    assert core.exit_code() == 0
    raw = (tmp_path / "data/vault.db").read_bytes()
    for canary in (SECRET, PASSWORD, "Desktop entry"):
        assert canary.encode() not in raw
        assert canary.encode() not in (tmp_path / "core.log").read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "data").stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "data/vault.db").stat().st_mode) == 0o600
    again = Core(tmp_path / "data", tmp_path / "again.log")
    try:
        assert api(again, "GET", "/passwords", token=token)[0] == 401
        token = api(
            again, "POST", "/master_password/unlock", {"master_password": PASSWORD}
        )[1]["session_token"]
        assert (
            api(again, "GET", "/passwords", token=token)[1][0]["password_value"]
            == SECRET
        )
    finally:
        again.kill()


def test_entries_history_notes_totp_trash(core):
    token = create(core)
    old = entry(
        core, token, totp_secret="JBSWY3DPEHPK3PXP", folder="Work", tags=["test"]
    )
    new = {**old, "password_value": "Changed-secret-2026!"}
    assert (
        api(
            core,
            "PATCH",
            "/passwords/update",
            {"password": old, "new_password": new},
            token,
        )[0]
        == 200
    )
    rows = api(core, "GET", "/passwords", token=token)[1]
    assert rows[0]["password_history"][0]["value"] == SECRET
    entry(
        core, token, name="Private note", kind="note", password_value="Secret note body"
    )
    path = "/passwords/" + quote("Desktop entry")
    assert api(core, "DELETE", path, token=token)[0] == 200
    assert len(api(core, "GET", "/passwords/trash", token=token)[1]) == 1
    assert api(core, "POST", path + "/restore", token=token)[0] == 200


def test_attachment_binary(core):
    token = create(core)
    entry(core, token, name="binary")
    data = bytes(range(256)) * 4096
    body, content_type = multipart("file", "secret.bin", data)
    response = core.call(
        "POST",
        "/api/passwords/binary/attachments",
        body,
        [["content-type", content_type], ["x-ciphermoth-session", token]],
    )
    assert response.header["status"] == 200, response
    attachment = json.loads(response.body)
    response = core.call(
        "GET",
        f"/api/passwords/binary/attachments/{attachment['id']}",
        headers=[["x-ciphermoth-session", token]],
    )
    assert response.body == data


def test_rotation_revokes_old_session(core):
    token = create(core)
    entry(core, token)
    new = "Rotated-Desktop-2027!"
    assert (
        api(
            core,
            "PATCH",
            "/master_password/update",
            {"master_password": PASSWORD, "new_master_password": new},
            token,
        )[0]
        == 200
    )
    assert api(core, "GET", "/passwords", token=token)[0] == 401
    assert (
        api(core, "POST", "/master_password/unlock", {"master_password": PASSWORD})[1][
            "valid"
        ]
        is False
    )
    assert (
        api(core, "POST", "/master_password/unlock", {"master_password": new})[1][
            "valid"
        ]
        is True
    )


def test_large_backup_roundtrip(core, tmp_path):
    token = create(core)
    entry(core, token, name="large")
    data = os.urandom(5 * 1024 * 1024)
    for i in range(5):
        body, ct = multipart("file", f"{i}.bin", data)
        result = core.call(
            "POST",
            "/api/passwords/large/attachments",
            body,
            [["content-type", ct], ["x-ciphermoth-session", token]],
        )
        assert result.header["status"] == 200
    backup = tmp_path / "large.cmbackup"
    assert (
        native(core, "backup_export", backup, token, master_password=PASSWORD)[0] == 200
    )
    assert backup.stat().st_size > 24 * 1024 * 1024
    before = backup.read_bytes()
    assert (
        native(core, "backup_export", backup, token, master_password=PASSWORD)[0] == 400
    )
    assert backup.read_bytes() == before
    other = Core(tmp_path / "restored", tmp_path / "restore.log")
    try:
        dest = create(other)
        assert (
            native(
                other,
                "backup_import",
                backup,
                dest,
                master_password="wrong",
                on_conflict="skip",
            )[0]
            == 403
        )
        assert api(other, "GET", "/passwords", token=dest)[1] == []
        status, result = native(
            other,
            "backup_import",
            backup,
            dest,
            master_password=PASSWORD,
            on_conflict="skip",
        )
        assert status == 200, result
        assert result["attachments"] == 5
        attachments = api(other, "GET", "/passwords/large/attachments", token=dest)[1]
        for attachment in attachments:
            response = other.call(
                "GET",
                f"/api/passwords/large/attachments/{attachment['id']}",
                headers=[["x-ciphermoth-session", dest]],
            )
            assert response.body == data
    finally:
        other.kill()
    assert not list(tmp_path.glob(".ciphermoth-*.partial"))


@pytest.mark.parametrize(
    "header",
    [
        b"not json",
        b"[]",
        b'{"method":"GET","path":"relative"}',
        b'{"method":"TRACE","path":"/api/meta"}',
    ],
)
def test_malformed_frames(core, header):
    core.send(frame(REQUEST, 100, header))
    assert core.wait(100).kind == ERROR
    assert api(core, "GET", "/meta")[0] == 200


@pytest.mark.parametrize(
    "kind,body,header",
    [
        (99, b"", b"{}"),
        (REQUEST, b"x" * (24 * 1024 * 1024 + 1), b"{}"),
        (REQUEST, b"", b"x" * 65537),
    ],
    ids=["unknown-kind", "oversized-body", "oversized-header"],
)
def test_oversized_and_unknown_frames(core, kind, body, header):
    core.send(frame(kind, 100, header, body))
    assert core.wait(100).kind == ERROR
    assert api(core, "GET", "/meta")[0] == 200


def test_bad_magic_exits(core):
    core.send(frame(REQUEST, 100, {}, magic=b"XX"))
    assert core.exit_code() == 2


def test_shutdown(core):
    core.send(frame(SHUTDOWN, 0, {}))
    assert core.exit_code() == 0


def test_cancellation_leaves_vault_usable(core):
    token = create(core)
    request_id = core.submit(
        "POST",
        "/api/master_password/unlock",
        json.dumps({"master_password": PASSWORD}).encode(),
        [["content-type", "application/json"]],
    )
    core.send(frame(CANCEL, request_id, {}))
    assert core.wait(request_id).kind in (2, ERROR)
    assert api(core, "GET", "/passwords", token=token)[0] == 200


def test_core_has_no_listener(core):
    import psutil

    if os.name == "posix" and __import__("sys").platform.startswith("linux"):
        pytest.skip(
            "Linux dump protection blocks per-process fd inspection; "
            "namespace check in native harness"
        )
    assert not [
        c
        for c in psutil.Process(core.proc.pid).net_connections()
        if c.status == psutil.CONN_LISTEN
    ]


@pytest.mark.parametrize(
    "data", [b"not a database", b"SQLite format 3\x00" + b"x" * 500]
)
def test_damaged_vault_unchanged(tmp_path, data):
    folder = tmp_path / "damaged"
    folder.mkdir()
    vault = folder / "vault.db"
    vault.write_bytes(data)
    c = Core(folder, tmp_path / "damaged.log", wait_ready=False)
    try:
        assert c.exit_code() != 0
        assert vault.read_bytes() == data
    finally:
        c.kill()


def test_desktop_has_one_session(core):
    first = create(core)
    second = api(
        core, "POST", "/master_password/unlock", {"master_password": PASSWORD}
    )[1]["session_token"]
    assert api(core, "GET", "/passwords", token=first)[0] == 401
    assert api(core, "GET", "/passwords", token=second)[0] == 200


@pytest.mark.parametrize("version", [1, 999])
def test_unsupported_vault_is_not_modified(tmp_path, version):
    import sqlite3

    c = Core(tmp_path / "data", tmp_path / "initial.log")
    create(c)
    c.close_stdin()
    assert c.exit_code() == 0
    path = tmp_path / "data/vault.db"
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA user_version={version}")
    before = path.read_bytes()
    c = Core(tmp_path / "data", tmp_path / "refused.log", wait_ready=False)
    try:
        assert c.exit_code() != 0
        assert path.read_bytes() == before
    finally:
        c.kill()


def test_idle_expiry_is_enforced_over_desktop_transport(core):
    import time

    token = create(core)
    settings = api(core, "GET", "/settings", token=token)[1]
    settings.update(inactivity_ms=30_000, warn_before_ms=5_000)
    assert api(core, "PATCH", "/settings", settings, token)[0] == 200
    time.sleep(35.2)
    assert api(core, "GET", "/passwords", token=token)[0] == 401
