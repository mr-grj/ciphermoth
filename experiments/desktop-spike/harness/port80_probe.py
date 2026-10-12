import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path

import psutil

CANARIES = {
    "master_password": b"Canary-Master-7Qx-ciphermoth",
    "attachment_canary": b"CANARY-ATTACHMENT-91c4",
}


def owners(port: int) -> list[dict]:
    found = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            try:
                name = psutil.Process(conn.pid).name() if conn.pid else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = None
            found.append({"laddr": str(conn.laddr), "pid": conn.pid, "name": name})
    return found


def sink(family: int, host: str, port: int, log: list, stop: threading.Event) -> str:
    server = socket.socket(family, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except OSError as exc:
        return f"{host}:{port} bind failed: {exc}"
    server.listen(16)
    server.settimeout(0.2)

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, addr = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(1.0)
            data = b""
            try:
                while len(data) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            conn.close()
            log.append(
                {
                    "listener": f"{host}:{port}",
                    "peer": str(addr),
                    "bytes": len(data),
                    "head": data[:200].decode("latin-1"),
                    "canaries": [k for k, v in CANARIES.items() if v in data],
                }
            )
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"{host}:{port} listening"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--duration", type=float, default=240)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()
    report = {
        "preexisting_listeners": owners(args.port),
        "sinks": [],
        "connections": [],
    }
    stop = threading.Event()
    report["sinks"].append(
        sink(socket.AF_INET, "127.0.0.1", args.port, report["connections"], stop)
    )
    report["sinks"].append(
        sink(socket.AF_INET6, "::1", args.port, report["connections"], stop)
    )
    if args.ready_file:
        args.ready_file.write_text("ready")
    deadline = time.time() + args.duration
    while time.time() < deadline and not (args.out.with_suffix(".stop")).exists():
        time.sleep(0.2)
    stop.set()
    time.sleep(0.5)
    args.out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
