import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

CORE_VERSION = "0.1.0-spike"
UNREACHABLE_DATABASE = "/nonexistent/ciphermoth-desktop-spike"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="ciphermoth-core")
    parser.add_argument("--check-vectors", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--version", action="store_true")
    return parser.parse_args()


async def _serve(
    proto_in: int, proto_out: int, data_dir: Path, applied: list[str], started: float
) -> int:
    import sqlite3

    import main as server_main

    from spike_core import asgi_bridge
    from spike_core.server import CoreServer
    from spike_core.spike_app import build_spike_app, open_state

    test_hooks = os.environ.get("CIPHERMOTH_SPIKE_TEST_HOOKS") == "1"
    if test_hooks and os.environ.get("CIPHERMOTH_SPIKE_FAIL_STARTUP") == "1":
        raise RuntimeError("synthetic startup failure")
    state = await open_state(data_dir)
    app = asgi_bridge.compose(server_main.app, build_spike_app(state, test_hooks))
    server = CoreServer(app, proto_in, proto_out)
    server.ready(
        {
            "core_version": CORE_VERSION,
            "pid": os.getpid(),
            "python": sys.version.split()[0],
            "frozen": bool(getattr(sys, "frozen", False)),
            "sqlite": sqlite3.sqlite_version,
            "startup_ms": round((time.monotonic() - started) * 1000, 1),
            "hardening": applied,
            "test_hooks": test_hooks,
        }
    )
    try:
        return await server.serve()
    finally:
        await state.engine.dispose()


def main(started: float) -> int:
    args = _arguments()
    if args.version:
        print(CORE_VERSION)
        return 0
    if args.check_vectors:
        from spike_core.vectors import run_all

        result = run_all(args.check_vectors)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if not result["failed"] else 1

    from spike_core.hardening import disable_crash_dumps, isolate_stdio, watch_parent

    proto_in, proto_out = isolate_stdio()
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    applied = disable_crash_dumps()
    os.environ["POSTGRES_HOST"] = UNREACHABLE_DATABASE
    data_dir = args.data_dir or Path(os.environ["CIPHERMOTH_SPIKE_DATA_DIR"])
    watch_parent(lambda: os._exit(4))
    try:
        code = asyncio.run(_serve(proto_in, proto_out, data_dir, applied, started))
    except Exception as exc:
        logging.getLogger("ciphermoth.core").error(
            "startup failed: %s", type(exc).__name__
        )
        code = 1
    logging.shutdown()
    return code
