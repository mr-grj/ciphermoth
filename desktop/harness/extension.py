"""The browser side of the desktop-mode QA (design 8.4), run by native.py.

The QA app turns "Allow browser extensions" on and reports the stage
``extension``; this module then plays the browser: it checks the manifests the
app wrote for the (synthetic) browser profiles, the private endpoint, starts the
app's own installed native host the way Chrome does, pairs over native
messaging with a third implementation of the channel (checked against the
frozen vectors first), compares the six digits the app's dialog shows with its
own, and reads a login over the encrypted channel. At ``extension_off`` it
checks the manifests and the endpoint are gone and the host says the app is
not running.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST_NAME = "com.ciphermoth.desktop.qa"
CHROMIUM_ID = "emeejhcdcdnlhejcpeohdafdnkmbaddn"
LABEL = "ciphermoth/extension/v1"
TO_APP, TO_EXTENSION = 1, 2
LOGIN = {
    "name": "Extension QA login",
    "password": "Extension-QA-canary-2026!",
    "username": "qa@example.test",
    "origin": "https://login.example.test",
}
VECTORS = (
    Path(__file__).resolve().parents[2] / "testdata/vectors/extension-channel.json"
)


# --- the channel (docs/EXTENSION.md, testdata/vectors/extension-channel.json) --


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def lp(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def public_of(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def commit(public: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(lp(f"{LABEL}/commit".encode()) + public + nonce).digest()


def transcript(browser, ext_public, ext_nonce, app_public, app_nonce) -> bytes:
    return hashlib.sha256(
        lp(f"{LABEL}/pair".encode())
        + lp(browser.encode())
        + ext_public
        + ext_nonce
        + app_public
        + app_nonce
    ).digest()


def hkdf(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info.encode()).derive(ikm)


def finish(private: X25519PrivateKey, peer: bytes, salt: bytes) -> tuple[str, bytes]:
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer))
    assert shared != bytes(32)
    sas = int.from_bytes(hkdf(shared, salt, f"{LABEL}/sas", 4), "big") % 1_000_000
    return f"{sas:06d}", hkdf(shared, salt, f"{LABEL}/channel", 32)


def connection_key(pairing_key, pairing_id, ext_nonce, app_nonce) -> bytes:
    salt = hashlib.sha256(
        lp(f"{LABEL}/connection".encode()) + pairing_id + ext_nonce + app_nonce
    ).digest()
    return hkdf(pairing_key, salt, f"{LABEL}/connection", 32)


def seal(key: bytes, direction: int, counter: int, plaintext: bytes) -> bytes:
    nonce = bytes([direction, 0, 0, 0]) + struct.pack(">Q", counter)
    return AESGCM(key).encrypt(
        nonce, plaintext, bytes([direction]) + struct.pack(">Q", counter)
    )


def unseal(key: bytes, direction: int, counter: int, sealed: bytes) -> bytes:
    nonce = bytes([direction, 0, 0, 0]) + struct.pack(">Q", counter)
    return AESGCM(key).decrypt(
        nonce, sealed, bytes([direction]) + struct.pack(">Q", counter)
    )


def verify_vectors() -> None:
    """This implementation must agree with the frozen vectors before it is
    allowed to judge the app."""
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    for case in doc["cases"]:
        ext = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(case["extension_private_hex"])
        )
        app = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(case["app_private_hex"])
        )
        assert b64(public_of(ext)) == case["extension_public"]
        n_x, n_a = unb64(case["extension_nonce"]), unb64(case["app_nonce"])
        assert b64(commit(public_of(ext), n_x)) == case["commit"]
        salt = transcript(case["browser"], public_of(ext), n_x, public_of(app), n_a)
        sas, key = finish(ext, public_of(app), salt)
        assert (sas, key.hex()) == (case["sas"], case["pairing_key_hex"])
        conn = connection_key(
            key,
            unb64(case["pairing_id"]),
            unb64(case["hello_extension_nonce"]),
            unb64(case["hello_app_nonce"]),
        )
        assert conn.hex() == case["connection_key_hex"]
        for message in case["messages"]:
            sealed = seal(
                conn,
                message["direction"],
                message["counter"],
                message["plaintext"].encode(),
            )
            assert b64(sealed) == message["ciphertext"]


# --- what the app writes -----------------------------------------------------


def profiles(root: Path) -> dict[str, Path]:
    """Synthetic browser folders below the QA root (the QA app looks for
    browsers there, never in the runner's real profiles)."""
    home, local, roaming = root / "home", root / "local", root / "roaming"
    if sys.platform == "darwin":
        support = home / "Library/Application Support"
        return {"Chrome": support / "Google/Chrome", "Firefox": support / "Firefox"}
    if sys.platform == "win32":
        return {
            "Chrome": local / "Google/Chrome/User Data",
            "Firefox": roaming / "Mozilla/Firefox",
        }
    return {
        "Chrome": home / ".config/google-chrome",
        "Firefox": home / ".mozilla/firefox",
    }


def prepare(root: Path) -> None:
    for folder in profiles(root).values():
        folder.mkdir(parents=True, exist_ok=True)


def manifest_files(root: Path) -> dict[str, Path]:
    home = root / "home"
    if sys.platform == "darwin":
        support = home / "Library/Application Support"
        return {
            "Chrome": support / f"Google/Chrome/NativeMessagingHosts/{HOST_NAME}.json",
            "Brave": support
            / f"BraveSoftware/Brave-Browser/NativeMessagingHosts/{HOST_NAME}.json",
            "Firefox": support / f"Mozilla/NativeMessagingHosts/{HOST_NAME}.json",
        }
    if sys.platform == "win32":
        link = root / "browser-extension/native-messaging"
        return {
            "Chrome": link / f"{HOST_NAME}.chromium.json",
            "Firefox": link / f"{HOST_NAME}.firefox.json",
        }
    return {
        "Chrome": home / f".config/google-chrome/NativeMessagingHosts/{HOST_NAME}.json",
        "Brave": home
        / f".config/BraveSoftware/Brave-Browser/NativeMessagingHosts/{HOST_NAME}.json",
        "Firefox": home / f".mozilla/native-messaging-hosts/{HOST_NAME}.json",
    }


REGISTRY = {
    "Chrome": rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}",
    "Brave": rf"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{HOST_NAME}",
    "Firefox": rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}",
}


def registry_value(key: str) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            return winreg.QueryValueEx(handle, "")[0]
    except OSError:
        return None


def socket_path(root: Path) -> Path:
    path = root / "run/extension.sock"
    # The link moves longer paths to the per-user temporary folder; keep the
    # QA root short enough that the primary path is the one tested.
    assert len(os.fsencode(path)) < 100, f"QA root too long for a socket path: {path}"
    return path


def read_manifests(root: Path) -> dict[str, dict]:
    found = {}
    for browser, path in manifest_files(root).items():
        if sys.platform == "win32":
            value = registry_value(REGISTRY[browser])
            if value is None:
                continue
            assert Path(value) == path, (browser, value)
        if path.is_file():
            found[browser] = json.loads(path.read_text(encoding="utf-8"))
    return found


# --- the browser ---------------------------------------------------------------


class Host:
    """The app's installed native host, started as Chrome starts it."""

    def __init__(self, program: str, root: Path):
        args = [program, f"chrome-extension://{CHROMIUM_ID}/"]
        if sys.platform == "win32":
            args.append("--parent-window=0")
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={**os.environ, "CIPHERMOTH_QA_ROOT": str(root)},
        )

    def send(self, message: dict) -> None:
        body = json.dumps(message).encode()
        self.process.stdin.write(struct.pack("=I", len(body)) + body)
        self.process.stdin.flush()

    def receive(self) -> dict:
        prefix = self.process.stdout.read(4)
        assert len(prefix) == 4, "the host closed the connection"
        (length,) = struct.unpack("=I", prefix)
        assert 0 < length <= 64 * 1024
        return json.loads(self.process.stdout.read(length))

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()


def await_pairing_report(report_path: Path, seen: set, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = {}
        if report.get("stage") == "extension_pairing" and report.get("ack") not in seen:
            seen.add(report["ack"])
            return report
        time.sleep(0.05)
    raise TimeoutError("the app showed no pairing dialog")


def linux_strangers(path: Path) -> dict:
    """Another user cannot enter the folder; root can, and the app's peer check
    still drops it before reading anything."""
    probe = (
        "import socket,struct,sys\n"
        "s=socket.socket(socket.AF_UNIX)\n"
        "try:\n s.connect(sys.argv[1])\n"
        "except OSError as e:\n print('refused',e.errno);sys.exit(0)\n"
        'b=b\'{"t":"host","caller":"chrome-extension://%s/","version":"1"}\'%sys.argv[2].encode()\n'
        # Closed unread: an end of file, or a reset when our frame was still
        # unread in the app's buffer (Linux answers that close with RST).
        "try:\n"
        " s.sendall(struct.pack('=I',len(b))+b)\n"
        " s.settimeout(10)\n"
        " d=s.recv(4096)\n"
        "except (ConnectionResetError,BrokenPipeError):\n"
        " d=b''\n"
        "print('answer',len(d))\n"
    )
    results = {}
    for name, prefix in (
        ("other_user", ["sudo", "-n", "-u", "nobody"]),
        ("root", ["sudo", "-n"]),
    ):
        out = subprocess.run(
            # The system Python: another user may not reach the runner's venv.
            [*prefix, "/usr/bin/python3", "-I", "-c", probe, str(path), CHROMIUM_ID],
            capture_output=True,
            text=True,
            timeout=30,
        )
        results[name] = out.stdout.strip() or out.stderr.strip()
    assert results["other_user"].startswith("refused"), results
    # Root passes the folder permissions; the peer uid check closes it unread.
    assert results["root"] == "answer 0", results
    return results


def check_on(root: Path, report: dict, report_path: Path, app_executable: Path) -> dict:
    verify_vectors()
    result = {"vectors": True}
    assert report.get("browsers") == ["Chrome", "Firefox"], report.get("browsers")
    manifests = read_manifests(root)
    assert sorted(manifests) == ["Chrome", "Firefox"], sorted(manifests)
    assert manifests["Chrome"]["allowed_origins"] == [
        f"chrome-extension://{CHROMIUM_ID}/"
    ]
    assert manifests["Firefox"]["allowed_extensions"] == ["ciphermoth@mr-grj.github.io"]
    host = manifests["Chrome"]["path"]
    assert manifests["Firefox"]["path"] == host
    assert Path(host).is_file(), host
    # The host ships inside the installed app, next to its executable.
    assert Path(host).parent == app_executable.parent, (host, app_executable)
    result["host"] = host

    if sys.platform != "win32":
        path = socket_path(root)
        mode = path.stat().st_mode & 0o777
        folder = path.parent.stat().st_mode & 0o777
        assert (mode, folder) == (0o600, 0o700), (oct(mode), oct(folder))
        result["socket_modes"] = [oct(mode), oct(folder)]
        if sys.platform.startswith("linux"):
            result["strangers"] = linux_strangers(path)

    import extension_attacks as attacks

    hostile = attacks.before_pairing(root, report_path, host)

    seen: set = set()
    browser = Host(host, root)
    try:
        private = X25519PrivateKey.generate()
        n_x = os.urandom(16)
        browser.send(
            {
                "t": "pair_commit",
                "browser": "Chrome",
                "commit": b64(commit(public_of(private), n_x)),
            }
        )
        offer = browser.receive()
        assert offer["t"] == "pair_key", offer
        app_public, n_a = unb64(offer["pub"]), unb64(offer["nonce"])
        browser.send(
            {"t": "pair_reveal", "pub": b64(public_of(private)), "nonce": b64(n_x)}
        )
        sas, pairing_key = finish(
            private,
            app_public,
            transcript("Chrome", public_of(private), n_x, app_public, n_a),
        )
        shown = await_pairing_report(report_path, seen)
        assert shown["code"] == sas, (shown["code"], sas)
        assert shown["browser"] == "Chrome"
        (report_path.parent / (shown["ack"] + ".done")).touch()
        paired = browser.receive()
        assert paired["t"] == "paired", paired
        pairing_id = paired["id"]

        m_x = os.urandom(16)
        browser.send({"t": "hello", "id": pairing_id, "nonce": b64(m_x)})
        hello = browser.receive()
        assert hello["t"] == "hello_ok", hello
        key = connection_key(pairing_key, unb64(pairing_id), m_x, unb64(hello["nonce"]))
        counter = {"sent": 0, "received": 0}

        def call(request: dict) -> dict:
            request = {"id": counter["sent"] + 1, **request}
            sealed = seal(key, TO_APP, counter["sent"], json.dumps(request).encode())
            browser.send({"t": "msg", "c": counter["sent"], "d": b64(sealed)})
            counter["sent"] += 1
            answer = browser.receive()
            assert answer["t"] == "msg" and answer["c"] == counter["received"], answer
            plain = unseal(key, TO_EXTENSION, answer["c"], unb64(answer["d"]))
            counter["received"] += 1
            reply = json.loads(plain)
            assert reply["id"] == request["id"]
            return reply

        assert call({"op": "status"})["value"] == {"state": "unlocked"}
        found = call(
            {
                "op": "api",
                "route": "matches",
                "body": {"origin": LOGIN["origin"], "subdomains": False},
            }
        )
        logins = found["value"]["logins"]
        assert [login["name"] for login in logins] == [LOGIN["name"]], found
        assert logins[0]["username"] == LOGIN["username"]
        credential = call(
            {
                "op": "api",
                "route": "credential",
                "body": {
                    "id": logins[0]["id"],
                    "origin": LOGIN["origin"],
                    "subdomains": False,
                    "confirmed_mismatch": False,
                },
            }
        )
        assert credential["value"] == {
            "username": LOGIN["username"],
            "password": LOGIN["password"],
        }
        # Nothing but the four fill routes reaches the vault.
        refused = call({"op": "api", "route": "sessions", "body": {}})
        assert refused["ok"] is False and refused["code"] == "protocol", refused
        result["paired_and_filled"] = True
    finally:
        browser.close()
    hostile += attacks.on_the_channel(root, host, pairing_id, pairing_key)
    hostile.append(attacks.the_wire(root, host, pairing_id, pairing_key))
    hostile += attacks.files_and_logs(root, pairing_key)
    result["hostile_probes_refused"] = hostile
    return result


def check_off(root: Path) -> dict:
    assert read_manifests(root) == {}, "manifests left after turning extensions off"
    if sys.platform == "win32":
        assert all(registry_value(key) is None for key in REGISTRY.values())
    else:
        assert not socket_path(root).exists(), (
            "the socket survived turning extensions off"
        )
    return {"manifests_removed": True}


def check_not_running(host: str, root: Path) -> None:
    browser = Host(host, root)
    try:
        browser.send({"t": "hello", "id": b64(bytes(16)), "nonce": b64(bytes(16))})
        assert browser.receive() == {"t": "error", "code": "app_not_running"}
    finally:
        browser.close()
