import json
import struct
from dataclasses import dataclass

MAGIC = b"CM"
PROTOCOL_VERSION = 1
PREFIX = struct.Struct(">2sBBIII")
PREFIX_SIZE = PREFIX.size

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 24 * 1024 * 1024
DISCARD_CHUNK = 64 * 1024

REQUEST = 1
RESPONSE = 2
CANCEL = 3
READY = 4
ERROR = 5
SHUTDOWN = 6

KINDS = {REQUEST, RESPONSE, CANCEL, READY, ERROR, SHUTDOWN}


class Desync(Exception):
    pass


@dataclass(frozen=True)
class Prefix:
    kind: int
    request_id: int
    header_len: int
    body_len: int


@dataclass(frozen=True)
class Frame:
    kind: int
    request_id: int
    header: dict
    body: bytes


def parse_prefix(raw: bytes) -> Prefix:
    magic, version, kind, request_id, header_len, body_len = PREFIX.unpack(raw)
    if magic != MAGIC or version != PROTOCOL_VERSION:
        raise Desync("bad magic or version")
    return Prefix(kind, request_id, header_len, body_len)


def encode(kind: int, request_id: int, header: dict, body: bytes = b"") -> bytes:
    header_bytes = json.dumps(header, separators=(",", ":")).encode()
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ValueError("header too large")
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("body too large")
    return (
        PREFIX.pack(
            MAGIC, PROTOCOL_VERSION, kind, request_id, len(header_bytes), len(body)
        )
        + header_bytes
        + body
    )
