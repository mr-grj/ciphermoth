import asyncio
import json
import logging
import os
import queue
import threading
from dataclasses import dataclass

from . import asgi_bridge
from . import framing as f

log = logging.getLogger("ciphermoth.core")

MAX_IN_FLIGHT = 64
MAX_PATH = 8192
MAX_HEADERS = 64
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
DROPPED_HEADERS = {"content-length", "transfer-encoding", "connection", "host"}


class ProtocolWriter:
    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.queue: queue.Queue[bytes | None] = queue.Queue()
        self.thread = threading.Thread(target=self._run, name="proto-out", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            data = self.queue.get()
            if data is None:
                return
            view = memoryview(data)
            try:
                while view:
                    written = os.write(self.fd, view)
                    view = view[written:]
            except OSError:
                os._exit(3)

    def send(self, kind: int, request_id: int, header: dict, body: bytes = b"") -> None:
        self.queue.put(f.encode(kind, request_id, header, body))

    def close(self, timeout: float = 2.0) -> None:
        self.queue.put(None)
        self.thread.join(timeout)


@dataclass(frozen=True)
class Incoming:
    kind: str
    prefix: f.Prefix | None = None
    header: bytes = b""
    body: bytes = b""
    reason: str = ""


def _read_exact(fd: int, size: int) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = os.read(fd, min(size - len(buffer), 1 << 20))
        if not chunk:
            return None
        buffer += chunk
    return bytes(buffer)


def _discard(fd: int, size: int) -> bool:
    while size:
        chunk = os.read(fd, min(size, f.DISCARD_CHUNK))
        if not chunk:
            return False
        size -= len(chunk)
    return True


def reader(fd: int, deliver) -> None:
    while True:
        raw = _read_exact(fd, f.PREFIX_SIZE)
        if raw is None:
            deliver(Incoming("eof"))
            return
        try:
            prefix = f.parse_prefix(raw)
        except f.Desync:
            deliver(Incoming("desync"))
            return
        reason = ""
        if prefix.kind not in f.KINDS:
            reason = "unknown_kind"
        elif prefix.header_len > f.MAX_HEADER_BYTES:
            reason = "header_too_large"
        elif prefix.body_len > f.MAX_BODY_BYTES:
            reason = "body_too_large"
        if reason:
            if not _discard(fd, prefix.header_len + prefix.body_len):
                deliver(Incoming("eof"))
                return
            deliver(Incoming("rejected", prefix, reason=reason))
            continue
        header = _read_exact(fd, prefix.header_len)
        body = _read_exact(fd, prefix.body_len) if header is not None else None
        if header is None or body is None:
            deliver(Incoming("eof"))
            return
        deliver(Incoming("frame", prefix, header, body))


class BadRequest(Exception):
    pass


def parse_request(header_bytes: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
    try:
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadRequest("header is not JSON") from exc
    if not isinstance(header, dict):
        raise BadRequest("header is not an object")
    method = header.get("method")
    path = header.get("path")
    query = header.get("query", "")
    headers = header.get("headers", [])
    if method not in METHODS:
        raise BadRequest("method")
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > MAX_PATH
        or not path.isascii()
        or any(ord(c) < 0x21 or ord(c) == 0x7F for c in path)
    ):
        raise BadRequest("path")
    if not isinstance(query, str) or not query.isascii() or len(query) > MAX_PATH:
        raise BadRequest("query")
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise BadRequest("headers")
    clean: list[tuple[str, str]] = []
    for pair in headers:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(part, str) and part.isascii() for part in pair)
            or any(ch in part for part in pair for ch in "\r\n\x00")
        ):
            raise BadRequest("header pair")
        if pair[0].lower() not in DROPPED_HEADERS:
            clean.append((pair[0], pair[1]))
    return method, path, query, clean


class CoreServer:
    def __init__(self, app, proto_in: int, proto_out: int) -> None:
        self.app = app
        self.proto_in = proto_in
        self.writer = ProtocolWriter(proto_out)
        self.in_flight: dict[int, asyncio.Task] = {}
        self.stopping = asyncio.Event()
        self.exit_code = 0
        self.incoming: asyncio.Queue[Incoming] = asyncio.Queue()

    def ready(self, info: dict) -> None:
        self.writer.send(
            f.READY, 0, {"ready": True, "protocol": f.PROTOCOL_VERSION, **info}
        )

    def error(self, request_id: int, code: str, message: str = "") -> None:
        self.writer.send(f.ERROR, request_id, {"code": code, "message": message})

    async def serve(self) -> int:
        loop = asyncio.get_running_loop()
        threading.Thread(
            target=reader,
            args=(
                self.proto_in,
                lambda item: loop.call_soon_threadsafe(self.incoming.put_nowait, item),
            ),
            name="proto-in",
            daemon=True,
        ).start()
        while True:
            item = await self.incoming.get()
            if item.kind == "eof":
                log.info("protocol input closed, shutting down")
                break
            if item.kind == "desync":
                log.error("protocol desync, shutting down")
                self.error(0, "desync", "bad magic or version")
                self.exit_code = 2
                break
            if item.kind == "rejected":
                assert item.prefix is not None
                self.error(item.prefix.request_id, item.reason)
                continue
            assert item.prefix is not None
            kind = item.prefix.kind
            if kind == f.REQUEST:
                self._start(item.prefix.request_id, item.header, item.body)
            elif kind == f.CANCEL:
                task = self.in_flight.get(item.prefix.request_id)
                if task is not None:
                    task.cancel()
            elif kind == f.SHUTDOWN:
                log.info("shutdown requested")
                break
            else:
                self.error(item.prefix.request_id, "unexpected_kind")
        await self._drain()
        self.writer.close()
        return self.exit_code

    def _start(self, request_id: int, header: bytes, body: bytes) -> None:
        if request_id == 0:
            self.error(0, "bad_request", "request id 0 is reserved")
            return
        if request_id in self.in_flight:
            self.error(request_id, "duplicate_id")
            return
        if len(self.in_flight) >= MAX_IN_FLIGHT:
            self.error(request_id, "busy")
            return
        try:
            request = parse_request(header)
        except BadRequest as exc:
            self.error(request_id, "bad_request", str(exc))
            return
        task = asyncio.create_task(self._handle(request_id, request, body))
        self.in_flight[request_id] = task
        task.add_done_callback(lambda _: self.in_flight.pop(request_id, None))

    async def _handle(self, request_id: int, request, body: bytes) -> None:
        method, path, query, headers = request
        try:
            status, response_headers, response_body = await asgi_bridge.call(
                self.app, method, path, query, headers, body, f.MAX_BODY_BYTES
            )
        except asyncio.CancelledError:
            self.error(request_id, "cancelled")
            return
        except asgi_bridge.ResponseTooLarge:
            self.error(request_id, "response_too_large")
            return
        except Exception as exc:
            log.error("unhandled %s in bridge", type(exc).__name__)
            self.error(request_id, "internal")
            return
        self.writer.send(
            f.RESPONSE,
            request_id,
            {"status": status, "headers": response_headers},
            response_body,
        )

    async def _drain(self) -> None:
        for task in list(self.in_flight.values()):
            task.cancel()
        if self.in_flight:
            await asyncio.wait(list(self.in_flight.values()), timeout=2)
