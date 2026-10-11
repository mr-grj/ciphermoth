import hashlib
import json
import os
import sys
import time
from pathlib import Path

import psutil
import pytest

from core_client import CANCEL, ERROR, RESPONSE, SHUTDOWN, Core, frame, multipart

MASTER = "Canary-Master-7Qx-ciphermoth"
ATTACHMENT_CANARY = b"CANARY-ATTACHMENT-91c4"
MIB = 1024 * 1024


def listening_now() -> set:
    return {
        (c.family, str(c.laddr))
        for c in psutil.net_connections(kind="inet")
        if c.status == psutil.CONN_LISTEN
    }


@pytest.fixture
def workspace(tmp_path: Path) -> dict:
    temp = tmp_path / "tmp"
    temp.mkdir()
    return {
        "listening_before": listening_now()
        if sys.platform.startswith("linux")
        else set(),
        "data": tmp_path / "data",
        "log": tmp_path / "core.log",
        "env": {"TMPDIR": str(temp), "TEMP": str(temp), "TMP": str(temp)},
        "temp": temp,
    }


@pytest.fixture
def core(workspace: dict):
    process = Core(workspace["data"], workspace["log"], workspace["env"])
    yield process
    process.kill()


def unlocked(core: Core) -> None:
    status, body = core.json("POST", "/spike/vault/create", {"master_password": MASTER})
    assert status == 200, body
    assert body == {"unlocked": True}


def test_ready_frame_announces_protocol_and_hardening(core: Core) -> None:
    ready = core.ready
    assert ready is not None
    assert ready.header["ready"] is True
    assert ready.header["protocol"] == 1
    assert ready.header["pid"] == core.proc.pid
    if sys.platform != "win32":
        assert "rlimit_core=0" in ready.header["hardening"]
    if sys.platform.startswith("linux"):
        assert "pr_set_pdeathsig=SIGKILL" in ready.header["hardening"]


def test_real_ciphermoth_app_answers_in_process(core: Core) -> None:
    reply = core.call("GET", "/api/meta")
    assert reply.kind == RESPONSE
    assert reply.header["status"] == 200
    assert json.loads(reply.body)["version"] == "1.4.7"
    headers = dict(reply.header["headers"])
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"


def test_real_app_error_mapping_and_body_limit(core: Core) -> None:
    missing = core.call("GET", "/api/does-not-exist")
    assert missing.header["status"] == 404
    oversized = core.call("POST", "/api/passwords/import", b"x" * (12 * MIB))
    assert oversized.header["status"] == 413
    assert "limit for this request is 11 MB" in json.loads(oversized.body)["detail"]


def test_vault_key_never_leaves_the_core(core: Core) -> None:
    unlocked(core)
    status, body = core.json("GET", "/spike/vault/status")
    assert body == {"exists": True, "unlocked": True}
    status, body = core.json("POST", "/spike/vault/lock")
    assert body == {"unlocked": False}
    status, body = core.json(
        "POST", "/spike/vault/unlock", {"master_password": "wrong password"}
    )
    assert status == 403
    status, body = core.json(
        "POST", "/spike/vault/unlock", {"master_password": f"  {MASTER}\n"}
    )
    assert (status, body) == (200, {"unlocked": True})


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        bytes(range(256)) * 64,
        frame(1, 9, {"method": "GET"}, b"CM" * 100),
        os.urandom(MIB),
    ],
    ids=["empty", "all-bytes", "frame-lookalike", "random-1mib"],
)
def test_binary_echo_is_byte_identical(core: Core, payload: bytes) -> None:
    reply = core.call(
        "POST", "/spike/echo", payload, [["content-type", "application/octet-stream"]]
    )
    assert reply.header["status"] == 200
    assert reply.body == payload
    assert (
        dict(reply.header["headers"])["x-sha256"] == hashlib.sha256(payload).hexdigest()
    )


def test_five_mib_attachment_round_trip(core: Core, workspace: dict) -> None:
    unlocked(core)
    data = ATTACHMENT_CANARY + os.urandom(5 * MIB - len(ATTACHMENT_CANARY))
    body, content_type = multipart("file", "canary.bin", data)
    started = time.perf_counter()
    upload = core.call(
        "POST", "/spike/attachments", body, [["content-type", content_type]]
    )
    upload_s = time.perf_counter() - started
    assert upload.header["status"] == 200, upload.body
    meta = json.loads(upload.body)
    assert meta["size"] == 5 * MIB
    assert meta["sha256"] == hashlib.sha256(data).hexdigest()
    started = time.perf_counter()
    download = core.call("GET", f"/spike/attachments/{meta['id']}")
    download_s = time.perf_counter() - started
    assert download.header["status"] == 200
    assert download.body == data
    print(
        f"\n5 MiB upload {upload_s * 1000:.1f} ms, download {download_s * 1000:.1f} ms"
    )
    too_big, content_type = multipart("file", "big.bin", os.urandom(5 * MIB + 1))
    rejected = core.call(
        "POST", "/spike/attachments", too_big, [["content-type", content_type]]
    )
    assert rejected.header["status"] == 400


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (b"{not json", "header is not JSON"),
        (b"\xff\xfe", "header is not JSON"),
        (b"[]", "header is not an object"),
        (json.dumps({"method": "TRACE", "path": "/api/meta"}).encode(), "method"),
        (json.dumps({"method": "GET", "path": "api/meta"}).encode(), "path"),
        (json.dumps({"method": "GET", "path": "/api/meta\r\nx"}).encode(), "path"),
        (json.dumps({"method": "GET", "path": "/api/méta"}).encode(), "path"),
        (
            json.dumps({"method": "GET", "path": "/", "headers": [["a"]]}).encode(),
            "header pair",
        ),
        (
            json.dumps(
                {"method": "GET", "path": "/", "headers": [["a", "b\r\nc"]]}
            ).encode(),
            "header pair",
        ),
        (
            json.dumps({"method": "GET", "path": "/", "headers": "x"}).encode(),
            "headers",
        ),
    ],
)
def test_malformed_requests_are_refused_and_the_core_keeps_serving(
    core: Core, header: bytes, reason: str
) -> None:
    core.send(frame(1, 41, header))
    reply = core.wait(41)
    assert reply.kind == ERROR
    assert reply.header == {"code": "bad_request", "message": reason}
    assert core.call("GET", "/spike/health").header["status"] == 200


def test_reserved_and_duplicate_ids(core: Core) -> None:
    core.send(frame(1, 0, {"method": "GET", "path": "/spike/health"}))
    assert core.wait(0).header["code"] == "bad_request"
    core.submit("GET", "/spike/sleep", query="ms=500", request_id=77)
    core.submit("GET", "/spike/health", request_id=77)
    first = core.wait(77)
    assert first.kind == ERROR and first.header["code"] == "duplicate_id"
    second = core.wait(77)
    assert second.kind == RESPONSE and json.loads(second.body) == {"slept_ms": 500}


def test_oversized_frames_are_discarded_without_losing_sync(core: Core) -> None:
    core.send(
        frame(1, 50, {"method": "POST", "path": "/spike/echo"}, b"z" * (24 * MIB + 1))
    )
    assert core.wait(50).header["code"] == "body_too_large"
    core.send(frame(1, 51, b" " * (64 * 1024 + 1)))
    assert core.wait(51).header["code"] == "header_too_large"
    core.send(frame(9, 52, {}))
    assert core.wait(52).header["code"] == "unknown_kind"
    assert core.call("GET", "/spike/health").header["status"] == 200


def test_huge_declared_length_does_not_allocate(workspace: dict) -> None:
    core = Core(workspace["data"], workspace["log"], workspace["env"])
    try:
        process = psutil.Process(core.proc.pid)
        before = process.memory_info().rss
        import struct

        core.send(struct.pack(">2sBBIII", b"CM", 1, 1, 60, 0, 0xFFFFFFFF) + b"x" * MIB)
        time.sleep(1)
        assert process.memory_info().rss - before < 32 * MIB
        core.close_stdin()
        assert core.exit_code() == 0
    finally:
        core.kill()


def test_bad_magic_is_a_fatal_desync(core: Core) -> None:
    core.send(frame(1, 60, {"method": "GET", "path": "/"}, magic=b"XX"))
    reply = core.next_frame()
    assert (
        reply is not None and reply.kind == ERROR and reply.header["code"] == "desync"
    )
    assert core.exit_code() == 2


def test_concurrent_requests_complete_out_of_order(core: Core) -> None:
    started = time.perf_counter()
    slow = [core.submit("GET", "/spike/sleep", query="ms=400") for _ in range(20)]
    fast = core.submit("GET", "/spike/health")
    assert core.wait(fast).header["status"] == 200
    fast_s = time.perf_counter() - started
    for request_id in slow:
        assert json.loads(core.wait(request_id).body) == {"slept_ms": 400}
    total_s = time.perf_counter() - started
    assert fast_s < 0.3
    assert total_s < 2.0


def test_listing_is_not_blocked_behind_a_large_upload(core: Core) -> None:
    unlocked(core)
    core.json("POST", "/spike/entries/seed", query="count=1000")
    body, content_type = multipart("file", "big.bin", os.urandom(5 * MIB))
    upload = core.submit(
        "POST", "/spike/attachments", body, [["content-type", content_type]]
    )
    started = time.perf_counter()
    listing = core.call("GET", "/spike/entries")
    listing_s = time.perf_counter() - started
    assert listing.header["status"] == 200
    assert len(json.loads(listing.body)) == 1000
    assert core.wait(upload).header["status"] == 200
    print(
        "\nlisting 1000 decrypted entries next to a 5 MiB upload: "
        f"{listing_s * 1000:.1f} ms"
    )
    assert listing_s < 0.5


def test_cancellation(core: Core) -> None:
    request_id = core.submit("GET", "/spike/sleep", query="ms=30000")
    time.sleep(0.2)
    started = time.perf_counter()
    core.send(frame(CANCEL, request_id, {}))
    reply = core.wait(request_id)
    assert reply.kind == ERROR and reply.header["code"] == "cancelled"
    assert time.perf_counter() - started < 0.5
    status, stats = core.json("GET", "/spike/stats")
    assert stats["cancelled"] == 1


def test_python_exception_returns_generic_500_and_logs_no_message(
    core: Core, workspace: dict
) -> None:
    reply = core.call("GET", "/spike/raise")
    assert reply.header["status"] == 500
    assert json.loads(reply.body) == {"detail": "An internal server error occurred."}
    assert b"CANARY-EXCEPTION" not in reply.body
    core.close_stdin()
    core.exit_code()
    log = workspace["log"].read_bytes()
    assert b"RuntimeError" in log
    assert b"CANARY-EXCEPTION" not in log


def test_stray_output_cannot_corrupt_the_protocol(core: Core, workspace: dict) -> None:
    reply = core.call("POST", "/spike/stray-output")
    assert json.loads(reply.body) == {"printed": True}
    assert core.call("GET", "/spike/health").header["status"] == 200
    core.close_stdin()
    core.exit_code()
    assert b"raw write to fd 1" in workspace["log"].read_bytes()


@pytest.mark.parametrize("mode", ["exit", "abort", "segv"])
def test_core_crash_is_visible_as_eof(core: Core, mode: str) -> None:
    if mode == "segv" and sys.platform == "win32":
        pytest.skip("ctypes turns an access violation into OSError on Windows")
    core.submit("POST", "/spike/crash", query=f"mode={mode}")
    assert core.next_frame(timeout=10) is None
    code = core.exit_code()
    assert code != 0


def test_stdin_eof_shuts_the_core_down(core: Core) -> None:
    core.submit("GET", "/spike/sleep", query="ms=60000")
    started = time.perf_counter()
    core.close_stdin()
    assert core.exit_code(timeout=5) == 0
    assert time.perf_counter() - started < 3


def test_shutdown_frame(core: Core) -> None:
    core.send(frame(SHUTDOWN, 0, {}))
    assert core.exit_code(timeout=5) == 0


def test_startup_failure_without_ready(workspace: dict) -> None:
    core = Core(
        workspace["data"],
        workspace["log"],
        {**workspace["env"], "CIPHERMOTH_SPIKE_FAIL_STARTUP": "1"},
        wait_ready=False,
    )
    try:
        assert core.next_frame(timeout=60) is None
        assert core.exit_code() == 1
        assert b"startup failed: RuntimeError" in workspace["log"].read_bytes()
    finally:
        core.kill()


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="POSIX permissions, not root"
)
def test_unwritable_data_dir_fails_before_ready(
    tmp_path: Path, workspace: dict
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    core = None
    try:
        core = Core(
            locked / "data", workspace["log"], workspace["env"], wait_ready=False
        )
        assert core.next_frame(timeout=60) is None
        assert core.exit_code() == 1
    finally:
        if core is not None:
            core.kill()
        locked.chmod(0o700)


def test_no_sockets_and_no_canary_on_disk(core: Core, workspace: dict) -> None:
    unlocked(core)
    body, content_type = multipart("file", "canary.bin", ATTACHMENT_CANARY * 50_000)
    assert (
        core.call(
            "POST", "/spike/attachments", body, [["content-type", content_type]]
        ).header["status"]
        == 200
    )
    try:
        connections = psutil.Process(core.proc.pid).net_connections(kind="all")
    except psutil.AccessDenied:
        assert sys.platform.startswith("linux")
        connections = []
        assert listening_now() <= workspace["listening_before"]
    assert [c for c in connections if c.status == psutil.CONN_LISTEN] == []
    assert [c for c in connections if c.family in (2, 10, 23)] == []
    core.close_stdin()
    core.exit_code()
    leaked = []
    for root in (workspace["data"], workspace["temp"], workspace["log"].parent):
        for path in root.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                if MASTER.encode() in content or ATTACHMENT_CANARY in content:
                    leaked.append(str(path))
    assert leaked == []
    assert list(workspace["temp"].iterdir()) == []
    if sys.platform != "win32":
        assert (workspace["data"] / "spike.db").stat().st_mode & 0o777 == 0o600
        assert workspace["data"].stat().st_mode & 0o777 == 0o700
