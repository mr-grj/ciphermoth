import json
import os
import queue
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE_DIR = HERE.parent
REPO = CORE_DIR.parents[2]

PREFIX = struct.Struct(">2sBBIII")
REQUEST, RESPONSE, CANCEL, READY, ERROR, SHUTDOWN = 1, 2, 3, 4, 5, 6


@dataclass
class Frame:
    kind: int
    request_id: int
    header: dict
    body: bytes


def core_command() -> list[str]:
    binary = os.environ.get("CORE_BIN")
    if binary:
        return [binary]
    return [sys.executable, str(CORE_DIR / "core_main.py")]


def core_env(data_dir: Path, extra: dict | None = None) -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "PATH",
            "HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "SYSTEMROOT",
            "WINDIR",
            "LOCALAPPDATA",
            "USERPROFILE",
        }
    }
    env["CIPHERMOTH_SPIKE_DATA_DIR"] = str(data_dir)
    env["CIPHERMOTH_SPIKE_TEST_HOOKS"] = "1"
    if not os.environ.get("CORE_BIN"):
        env["PYTHONPATH"] = os.pathsep.join([str(REPO / "backend"), str(CORE_DIR)])
    env.update(extra or {})
    return env


def frame(
    kind: int,
    request_id: int,
    header: dict | bytes,
    body: bytes = b"",
    magic=b"CM",
    version=1,
) -> bytes:
    header_bytes = header if isinstance(header, bytes) else json.dumps(header).encode()
    return (
        PREFIX.pack(magic, version, kind, request_id, len(header_bytes), len(body))
        + header_bytes
        + body
    )


def multipart(field: str, filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = "spikeboundary7c1e"
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + data
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, f"multipart/form-data; boundary={boundary}"


class Core:
    def __init__(
        self,
        data_dir: Path,
        log_path: Path,
        extra_env: dict | None = None,
        wait_ready: bool = True,
    ) -> None:
        self.log_path = log_path
        self.log_file = open(log_path, "wb")
        self.spawned_at = time.perf_counter()
        self.proc = subprocess.Popen(
            core_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log_file,
            env=core_env(data_dir, extra_env),
            cwd=str(data_dir.parent),
        )
        self.frames: queue.Queue[Frame | None] = queue.Queue()
        self.pending: dict[int, Frame] = {}
        self.next_id = 1
        self.write_lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        self.ready: Frame | None = None
        self.ready_after_s: float | None = None
        if wait_ready:
            self.ready = self.next_frame(timeout=60)
            self.ready_after_s = time.perf_counter() - self.spawned_at
            assert self.ready is not None and self.ready.kind == READY, self.ready

    def _read(self) -> None:
        stream = self.proc.stdout
        assert stream is not None
        while True:
            raw = stream.read(PREFIX.size)
            if len(raw) < PREFIX.size:
                self.frames.put(None)
                return
            magic, version, kind, request_id, header_len, body_len = PREFIX.unpack(raw)
            if magic != b"CM" or version != 1:
                self.frames.put(Frame(-1, 0, {"desync": raw.hex()}, b""))
                return
            header = stream.read(header_len)
            body = stream.read(body_len)
            self.frames.put(Frame(kind, request_id, json.loads(header), body))

    def next_frame(self, timeout: float = 30) -> Frame | None:
        return self.frames.get(timeout=timeout)

    def send(self, data: bytes) -> None:
        with self.write_lock:
            assert self.proc.stdin is not None
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def submit(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        headers: list | None = None,
        query: str = "",
        request_id: int | None = None,
    ) -> int:
        if request_id is None:
            request_id = self.next_id
            self.next_id += 1
        self.send(
            frame(
                REQUEST,
                request_id,
                {
                    "method": method,
                    "path": path,
                    "query": query,
                    "headers": headers or [],
                },
                body,
            )
        )
        return request_id

    def wait(self, request_id: int, timeout: float = 30) -> Frame:
        deadline = time.monotonic() + timeout
        while request_id not in self.pending:
            item = self.frames.get(timeout=max(0.01, deadline - time.monotonic()))
            if item is None:
                raise EOFError("core closed its output")
            self.pending[item.request_id] = item
        return self.pending.pop(request_id)

    def call(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        headers: list | None = None,
        query: str = "",
        timeout: float = 30,
    ) -> Frame:
        return self.wait(self.submit(method, path, body, headers, query), timeout)

    def json(
        self, method: str, path: str, payload: object | None = None, query: str = ""
    ) -> tuple[int, object]:
        body = json.dumps(payload).encode() if payload is not None else b""
        headers = [["content-type", "application/json"]] if payload is not None else []
        reply = self.call(method, path, body, headers, query)
        assert reply.kind == RESPONSE, reply
        return reply.header["status"], json.loads(reply.body) if reply.body else None

    def close_stdin(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()

    def exit_code(self, timeout: float = 10) -> int:
        try:
            return self.proc.wait(timeout)
        finally:
            self.log_file.close()

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        if not self.log_file.closed:
            self.log_file.close()
