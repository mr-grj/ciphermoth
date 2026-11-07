"""Hostile probes against the running QA app's browser-extension link, run by
extension.check_on (design 8.4 and decision 56). A same-user process that is
not the browser tries what it can: no or a foreign caller, malformed and
oversized frames, too many connections, a pairing that breaks its commitment
or uses a low-order key, an unknown pairing, and on a real paired channel:
reflection, replay from another connection, routes outside the four fill
routes, another site's login. It also checks that what the host relays holds
no readable secret, the link folder's permissions and that no log or report
holds the password or the pairing key.

macOS and Linux talk to the socket directly; Windows goes through the app's
own host (only it can reach the pipe the same way), so the probes that need a
raw endpoint run on Unix only.
"""

import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

import extension as ext
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

CHROME = f"chrome-extension://{ext.CHROMIUM_ID}/"
UNIX = sys.platform != "win32"


class Raw:
    """A same-user process on the app's socket (Unix)."""

    def __init__(self, path: Path, hello: bool = True):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(str(path))
        if hello:
            self.send({"t": "host", "caller": CHROME, "version": "1"})

    def send(self, message: dict) -> None:
        self.raw(json.dumps(message).encode(), framed=True)

    def raw(self, data: bytes, framed: bool = False) -> None:
        if framed:
            data = struct.pack("=I", len(data)) + data
        self.sock.sendall(data)

    def receive(self):
        try:
            head = self._exact(4)
            if head is None:
                return None
            body = self._exact(struct.unpack("=I", head)[0])
            return None if body is None else json.loads(body)
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            return None

    def _exact(self, n: int):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def close(self) -> None:
        self.sock.close()


class Through:
    """The same, through the app's installed host (Windows)."""

    def __init__(self, host: str, root: Path):
        self.host = ext.Host(host, root)

    def send(self, message: dict) -> None:
        self.host.send(message)

    def receive(self):
        prefix = self.host.process.stdout.read(4)
        if len(prefix) < 4:
            return None
        answer = json.loads(
            self.host.process.stdout.read(struct.unpack("=I", prefix)[0])
        )
        # The host reports the app closing the connection itself.
        return None if answer == {"t": "error", "code": "app_closed"} else answer

    def close(self) -> None:
        self.host.close()


def link(root: Path, host: str):
    return Raw(ext.socket_path(root)) if UNIX else Through(host, root)


def no_dialog(report_path: Path, seconds: float = 1.5) -> bool:
    time.sleep(seconds)
    try:
        return (
            json.loads(report_path.read_text(encoding="utf-8")).get("stage")
            != "extension_pairing"
        )
    except (OSError, ValueError):
        return True


def before_pairing(root: Path, report_path: Path, host: str) -> list[str]:
    done = []
    if UNIX:
        path = ext.socket_path(root)
        r = Raw(path, hello=False)
        r.send({"t": "pair_commit", "browser": "Chrome", "commit": ext.b64(bytes(32))})
        assert r.receive() == {"t": "refused", "code": "caller"}, "no host hello"
        r.close()
        r = Raw(path, hello=False)
        r.send(
            {
                "t": "host",
                "caller": "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
                "version": "1",
            }
        )
        assert r.receive() == {"t": "refused", "code": "caller"}, "foreign caller"
        r.close()
        r = Raw(path)
        r.raw(struct.pack("=I", 70_000) + b"{" * 64)
        assert r.receive() is None, "oversized frame"
        r.close()
        held = [Raw(path) for _ in range(8)]
        time.sleep(0.3)
        try:
            extra = Raw(path)
            extra.send(
                {
                    "t": "hello",
                    "id": ext.b64(os.urandom(16)),
                    "nonce": ext.b64(os.urandom(16)),
                }
            )
            closed = extra.receive() is None
            extra.close()
        except (BrokenPipeError, ConnectionResetError):
            closed = True
        assert closed, "a ninth connection was served"
        for r in held:
            r.close()
        time.sleep(0.3)
        done += ["no caller", "foreign caller", "oversized frame", "ninth connection"]

    r = link(root, host)
    r.send({"t": "pair_commit", "browser": "Netscape", "commit": ext.b64(bytes(32))})
    assert r.receive() == {"t": "refused", "code": "protocol"}, "unknown browser"
    r.close()

    r = link(root, host)
    real, nonce = X25519PrivateKey.generate(), os.urandom(16)
    r.send(
        {
            "t": "pair_commit",
            "browser": "Chrome",
            "commit": ext.b64(ext.commit(ext.public_of(real), nonce)),
        }
    )
    offer = r.receive()
    other = X25519PrivateKey.generate()
    r.send(
        {
            "t": "pair_reveal",
            "pub": ext.b64(ext.public_of(other)),
            "nonce": ext.b64(nonce),
        }
    )
    answer = r.receive()
    assert offer and offer["t"] == "pair_key", offer
    assert answer == {"t": "refused", "code": "protocol"}, answer
    assert no_dialog(report_path), "a broken commitment reached the dialog"
    r.close()

    r = link(root, host)
    weak, nonce = bytes(32), os.urandom(16)
    r.send(
        {
            "t": "pair_commit",
            "browser": "Chrome",
            "commit": ext.b64(ext.commit(weak, nonce)),
        }
    )
    r.receive()
    r.send({"t": "pair_reveal", "pub": ext.b64(weak), "nonce": ext.b64(nonce)})
    assert r.receive() == {"t": "refused", "code": "protocol"}, "low-order key"
    assert no_dialog(report_path), "a low-order key reached the dialog"
    r.close()

    r = link(root, host)
    r.send(
        {"t": "hello", "id": ext.b64(os.urandom(16)), "nonce": ext.b64(os.urandom(16))}
    )
    assert r.receive() == {"t": "refused", "code": "unknown_pairing"}, "unknown pairing"
    r.close()
    return done + [
        "unknown browser",
        "broken commitment",
        "low-order key",
        "unknown pairing",
    ]


class Session:
    def __init__(self, r, pairing_id: str, key: bytes):
        self.r = r
        m_x = os.urandom(16)
        r.send({"t": "hello", "id": pairing_id, "nonce": ext.b64(m_x)})
        hello = r.receive()
        assert hello and hello["t"] == "hello_ok", hello
        self.key = ext.connection_key(
            key, ext.unb64(pairing_id), m_x, ext.unb64(hello["nonce"])
        )
        self.sent = 0

    def frame(self, request: dict) -> dict:
        request = {"id": self.sent + 1, **request}
        sealed = ext.seal(self.key, ext.TO_APP, self.sent, json.dumps(request).encode())
        frame = {"t": "msg", "c": self.sent, "d": ext.b64(sealed)}
        self.sent += 1
        return frame

    def call(self, request: dict) -> dict:
        self.r.send(self.frame(request))
        answer = self.r.receive()
        assert answer and answer["t"] == "msg", answer
        return json.loads(
            ext.unseal(self.key, ext.TO_EXTENSION, answer["c"], ext.unb64(answer["d"]))
        )


def on_the_channel(root: Path, host: str, pairing_id: str, key: bytes) -> list[str]:
    r = link(root, host)
    s = Session(r, pairing_id, key)
    recorded = s.frame({"op": "status"})
    r.send(recorded)
    reply = r.receive()
    assert reply and reply["t"] == "msg", reply
    r.send(reply)  # the app's own answer, reflected
    assert r.receive() is None, "a reflected answer was read"
    r.close()

    r = link(root, host)
    Session(r, pairing_id, key)
    r.send(recorded)  # recorded on another connection
    assert r.receive() is None, "a replay from another connection was read"
    r.close()

    r = link(root, host)
    s = Session(r, pairing_id, key)
    for route in ("../sessions", "sessions", "credential/../../passwords", "MATCHES"):
        reply = s.call({"op": "api", "route": route, "body": {}})
        assert reply["ok"] is False and reply["code"] == "protocol", (route, reply)
    reply = s.call({"op": "api", "route": "search", "body": "x"})
    assert reply["ok"] is False and reply["code"] == "protocol", reply
    found = s.call(
        {"op": "api", "route": "matches", "body": {"origin": ext.LOGIN["origin"]}}
    )
    login = found["value"]["logins"][0]
    body = {
        "id": login["id"],
        "origin": "https://evil.example.test",
        "subdomains": False,
        "confirmed_mismatch": False,
    }
    reply = s.call({"op": "api", "route": "credential", "body": body})
    assert reply.get("status") == 409 and reply.get("code") == "origin_mismatch", reply
    body = {
        "id": 999_999,
        "origin": ext.LOGIN["origin"],
        "subdomains": False,
        "confirmed_mismatch": False,
    }
    reply = s.call({"op": "api", "route": "credential", "body": body})
    assert reply["ok"] is False and ext.LOGIN["password"] not in json.dumps(reply), (
        reply
    )
    r.close()
    return [
        "reflection",
        "replay across connections",
        "routes outside the fill routes",
        "another site's login",
        "unknown login",
    ]


def the_wire(root: Path, host: str, pairing_id: str, key: bytes) -> str:
    """What the host relays is ciphertext: read a password through it and
    search everything it wrote."""
    proc = subprocess.Popen(
        [host, CHROME, *(["--parent-window=0"] if not UNIX else [])],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env={**os.environ, "CIPHERMOTH_QA_ROOT": str(root)},
    )
    wire = b""

    def send(message: dict) -> None:
        body = json.dumps(message).encode()
        proc.stdin.write(struct.pack("=I", len(body)) + body)
        proc.stdin.flush()

    def receive() -> dict:
        nonlocal wire
        head = proc.stdout.read(4)
        body = proc.stdout.read(struct.unpack("=I", head)[0])
        wire += head + body
        return json.loads(body)

    m_x = os.urandom(16)
    send({"t": "hello", "id": pairing_id, "nonce": ext.b64(m_x)})
    conn = ext.connection_key(
        key, ext.unb64(pairing_id), m_x, ext.unb64(receive()["nonce"])
    )
    plain = []
    requests = [
        {
            "id": 1,
            "op": "api",
            "route": "matches",
            "body": {"origin": ext.LOGIN["origin"]},
        },
        None,
    ]
    for counter, request in enumerate(requests):
        if request is None:
            login_id = json.loads(plain[0])["value"]["logins"][0]["id"]
            body = {
                "id": login_id,
                "origin": ext.LOGIN["origin"],
                "subdomains": False,
                "confirmed_mismatch": False,
            }
            request = {"id": 2, "op": "api", "route": "credential", "body": body}
        sealed = ext.seal(conn, ext.TO_APP, counter, json.dumps(request).encode())
        send({"t": "msg", "c": counter, "d": ext.b64(sealed)})
        answer = receive()
        plain.append(
            ext.unseal(conn, ext.TO_EXTENSION, counter, ext.unb64(answer["d"])).decode()
        )
    proc.stdin.close()
    proc.wait(10)
    assert ext.LOGIN["password"] in plain[1], "the password did not arrive"
    for secret in (
        ext.LOGIN["password"],
        ext.LOGIN["username"],
        ext.LOGIN["name"],
        "session_token",
    ):
        assert secret.encode() not in wire, (
            f"{secret[:6]}... readable on the host's wire"
        )
    return "the host relays only ciphertext"


def files_and_logs(root: Path, key: bytes) -> list[str]:
    done = []
    if UNIX:
        folder = root / "browser-extension"

        def mode(path: Path) -> int:
            return stat.S_IMODE(path.stat().st_mode)

        assert mode(folder) == 0o700, oct(mode(folder))
        assert mode(folder / "config.json") == 0o600, oct(mode(folder / "config.json"))
        assert mode(folder / "launch.json") & 0o022 == 0, oct(
            mode(folder / "launch.json")
        )
        done.append("link folder 0700, config 0600")
    canaries = [ext.LOGIN["password"].encode(), ext.b64(key).encode()]
    for path in root.rglob("*"):
        relative = path.relative_to(root).parts
        if not path.is_file() or path.name == "config.json" or "data" in relative:
            continue
        if path.stat().st_size > 50_000_000:
            continue
        content = path.read_bytes()
        for canary in canaries:
            assert canary not in content, f"secret in {path.name}"
    return [*done, "no password or pairing key in logs and reports"]
