"""Real installed-app updater acceptance on an isolated native host.

HTTPS has an ephemeral test CA trusted only by the QA process. The updater,
signature verifier, installer and production vault core are the real ones.
"""

import argparse
import base64
import copy
import datetime
import hashlib
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from artifacts import target
from native import gone


def certificate(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "CipherMoth disposable updater test")]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    (root / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    (root / "server.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (root / "tls.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(root / "tls.key", 0o600)


class Endpoint(http.server.BaseHTTPRequestHandler):
    mode = "good"
    manifest = None
    artifact = None
    bad_artifact = None
    signatures = {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/latest.json":
            if self.mode == "offline":
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            data = copy.deepcopy(self.manifest)
            entry = data["platforms"][target()]
            if self.mode in self.signatures:
                entry["signature"] = self.signatures[self.mode]
            if self.mode == "installer-failure":
                entry["signature"] = (
                    Path(str(self.bad_artifact) + ".sig").read_text().strip()
                )
            if self.mode == "missing-signature":
                del entry["signature"]
            if self.mode == "invalid-signature":
                lines = base64.b64decode(entry["signature"]).decode().splitlines()
                sig = bytearray(base64.b64decode(lines[1]))
                sig[-1] ^= 1
                lines[1] = base64.b64encode(sig).decode()
                entry["signature"] = base64.b64encode(
                    ("\n".join(lines) + "\n").encode()
                ).decode()
            if self.mode == "wrong-platform":
                entry["url"] = entry["url"].replace(target(), "wrong-aarch64")
            if self.mode == "wrong-source":
                entry["url"] = entry["url"].replace("github.com", "example.com")
            if self.mode == "downgrade":
                data["version"] = "2.9.0"
            if self.mode == "forged-version":
                data["version"] = "99.0.0"
            content = (
                b'{"invalid":'
                if self.mode == "invalid-manifest"
                else json.dumps(data).encode()
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        data = (
            self.bad_artifact if self.mode == "installer-failure" else self.artifact
        ).read_bytes()
        if self.mode == "modified":
            data = data[:-1] + bytes([data[-1] ^ 1])
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            if self.mode == "interrupted":
                self.wfile.write(data[:1024])
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
            elif self.mode == "cancel":
                for pos in range(0, len(data), 1024):
                    self.wfile.write(data[pos : pos + 1024])
                    self.wfile.flush()
                    time.sleep(0.05)
            else:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class Host:
    def __init__(self, root, executable, env):
        self.root = root
        self.executable = executable
        self.env = env
        self.seen = set()
        self.processes = []
        self.log = (root / "shell.log").open("wb")

    def launch(self):
        process = subprocess.Popen(
            [
                str(self.executable),
                "--qa-root",
                str(self.root),
                "--qa-update-endpoint",
                self.env["CIPHERMOTH_QA_UPDATE_ENDPOINT"],
                "--qa-update-ca",
                self.env["CIPHERMOTH_QA_UPDATE_CA"],
            ],
            env=self.env,
            stdout=self.log,
            stderr=self.log,
        )
        self.processes.append(process)
        return self.receive()

    def receive(self, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            path = self.root / "update-request.json"
            if path.exists():
                try:
                    report = json.loads(path.read_text())
                except (PermissionError, json.JSONDecodeError):
                    # Windows refuses to open a file while the app renames over
                    # it; the next poll reads the finished one.
                    time.sleep(0.05)
                    continue
                if report["id"] not in self.seen:
                    self.seen.add(report["id"])
                    self.report = report
                    assert report["result"].get("ok", True), report["result"]
                    return report
            time.sleep(0.1)
        raise TimeoutError("Installed update app did not report; see scoped shell.log")

    def send(self, action, wait=True, **fields):
        print(f"Update acceptance: {Endpoint.mode} / {action}", flush=True)
        response = self.root / f"update-{self.report['id']}.json"
        partial = response.with_suffix(".partial")
        partial.write_text(json.dumps({"action": action, **fields}))
        for _ in range(100):
            try:
                partial.replace(response)
                break
            except PermissionError:
                time.sleep(0.02)
        else:
            partial.replace(response)
        return self.receive() if wait else None

    def stop(self):
        pid = self.report["pid"]
        core = self.report["core"].get("info") or {}
        if psutil.pid_exists(pid):
            psutil.Process(pid).kill()
            gone(pid)
        if core.get("pid"):
            assert gone(core["pid"]), "Orphaned sidecar"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    certificate(root)
    native = target()
    suffix = (
        "app.tar.gz"
        if sys.platform == "darwin"
        else "exe"
        if sys.platform == "win32"
        else "AppImage"
    )
    newer = args.fixtures / "3.0.99" / f"CipherMoth_3.0.99_{native}.{suffix}"
    older = args.fixtures / "3.0.98" / f"CipherMoth_3.0.98_{native}.{suffix}"
    Endpoint.artifact = newer
    Endpoint.bad_artifact = args.fixtures / "installer-failure" / newer.name
    Endpoint.signatures = {
        mode: next((args.fixtures / mode).glob("*.sig")).read_text().strip()
        for mode in ("signed-wrong-platform", "signed-wrong-version")
    }
    Endpoint.manifest = {
        "version": "3.0.99",
        "notes": "Disposable native update acceptance",
        "platforms": {
            native: {
                "url": f"https://github.com/mr-grj/ciphermoth/releases/download/v3.0.99/{newer.name}",
                "signature": Path(str(newer) + ".sig").read_text().strip(),
            }
        },
    }
    server = http.server.ThreadingHTTPServer(("localhost", 0), Endpoint)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root / "server.pem", root / "tls.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    installed = root / "installed"
    installed.mkdir()
    if sys.platform == "darwin":
        app = installed / "CipherMoth Update QA.app"
        subprocess.run(
            ["ditto", str(args.fixtures / "3.0.98/CipherMoth Update QA.app"), str(app)],
            check=True,
        )
        executable = app / "Contents/MacOS/ciphermoth-desktop"
    elif sys.platform == "win32":
        subprocess.run([str(older), "/S", f"/D={installed}"], check=True)
        executable = installed / "ciphermoth-desktop.exe"
    else:
        executable = installed / "CipherMoth.AppImage"
        shutil.copy2(older, executable)
        executable.chmod(0o755)
    env = {
        **os.environ,
        "CIPHERMOTH_QA_ROOT": str(root),
        "CIPHERMOTH_QA_UPDATE_ENDPOINT": f"https://localhost:{server.server_port}/latest.json",
        "CIPHERMOTH_QA_UPDATE_CA": str(root / "ca.pem"),
    }
    host = Host(root, executable, env)
    checks = []
    try:
        assert host.launch()["version"] == "3.0.98"
        assert host.send("unlock")["result"]["fresh"]
        baseline = host.send("seed")["result"]["fingerprint"]
        checks.append(
            "Synthetic vault: notes, history, Trash, settings and binary attachments"
        )
        host.stop()
        host.launch()
        assert not host.send("unlock")["result"]["fresh"]
        host.send("verify", fingerprint=baseline)
        checks.append("Quit/reopen persistence before updating")
        host.send("check", available=True)
        for mode in (
            "missing-signature",
            "invalid-manifest",
            "wrong-platform",
            "signed-wrong-platform",
            "wrong-source",
            "forged-version",
            "offline",
        ):
            Endpoint.mode = mode
            host.send("check", reject=True)
            host.send("verify", fingerprint=baseline)
            checks.append(mode + " rejected; vault unchanged")
        Endpoint.mode = "downgrade"
        host.send("check", available=False)
        checks.append("Downgrade refused")
        for mode in (
            "invalid-signature",
            "signed-wrong-version",
            "modified",
            "interrupted",
            "cancel",
        ):
            Endpoint.mode = mode
            host.send("check", available=True)
            host.send("install", reject=True, cancel=mode == "cancel")
            host.send("verify", fingerprint=baseline)
            checks.append(mode + " refused; old app and vault usable")
        if Endpoint.bad_artifact.exists():
            Endpoint.mode = "installer-failure"
            host.send("check", available=True)
            old_pid = host.report["pid"]
            old_core = host.report["core"]["info"]["pid"]
            host.send("install", wait=False)
            report = host.receive()
            while report["pid"] == old_pid:
                report = host.receive()
            assert report["version"] == "3.0.98" and (root / "install-failed").is_file()
            assert gone(old_pid) and gone(old_core)
            host.send("unlock")
            host.send("verify", fingerprint=baseline)
            checks.append(
                "Real installer failure; old version restarts with unchanged vault"
            )
        Endpoint.mode = "good"
        status = host.send("check", available=True)["result"]["status"]
        assert status["canInstall"] and status["latest"] == "3.0.99"
        old_pid = host.report["pid"]
        old_core = host.report["core"]["info"]["pid"]
        host.send("install", wait=False)
        report = host.receive(timeout=180)
        # Navigation during locking can let the old renderer start its QA script.
        while report["version"] != "3.0.99":
            report = host.receive(timeout=180)
        assert gone(old_pid) and gone(old_core), "Orphan after update"
        host.send("unlock")
        host.send("verify", fingerprint=baseline, backup=True)
        (root / "transport.cmbackup").rename(root / "before-update.cmbackup")
        host.send("backup")
        host.send("check", available=False)
        checks.extend(
            [
                "Real signed update installed while unlocked; old processes reaped",
                "Relaunched version 3.0.99; original password unlocks unchanged vault",
                "Previous backup imports; new complete backup exports",
                "Same version reports no update",
            ]
        )
        host.stop()
        host.launch()
        host.send("unlock")
        host.send("verify", fingerprint=baseline)
        host.stop()
        result = {
            "target": native,
            "ok": True,
            "checks": checks,
            "fingerprint": baseline,
            "artifact_sha256": hashlib.sha256(newer.read_bytes()).hexdigest(),
            "scope": (
                "Installed QA bundles, real Tauri updater and production core; "
                "local verified HTTPS; OS internet reputation prompts not simulated"
            ),
        }
        (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    finally:
        if hasattr(host, "report"):
            host.stop()
        server.shutdown()
        host.log.close()


if __name__ == "__main__":
    main()
