import argparse
import base64
import json
import os
import platform
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

VERBOSE_KEYS = ("runs", "checks", "sockets", "lsof_inet", "core_stats")
CORE_NAMES = ("ciphermoth-core", "ciphermoth-core.exe")
WEBVIEW_NAMES = (
    "com.apple.WebKit",
    "WebKitWebProcess",
    "WebKitNetworkProcess",
    "msedgewebview2.exe",
)


MASTER = "Canary-Master-7Qx-ciphermoth"
ATTACHMENT_CANARY = b"CANARY-ATTACHMENT-91c4"
BUNDLE_ID = "com.ciphermoth.desktop-spike"


def core_processes() -> list[psutil.Process]:
    found = []
    for proc in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            if name in CORE_NAMES or name.startswith("ciphermoth-core"):
                found.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


BASELINE: set[int] = set()


def live(proc: psutil.Process) -> bool:
    try:
        return proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def listening_snapshot() -> set:
    try:
        return {
            (c.family, str(c.laddr))
            for c in psutil.net_connections(kind="inet")
            if c.status == psutil.CONN_LISTEN
        }
    except psutil.AccessDenied:
        return set()


def leftover_cores(before: list[int] | None = None, timeout: float = 5) -> list[int]:
    deadline = time.perf_counter() + timeout
    ignored = set(before or []) | BASELINE
    while True:
        alive = [p.pid for p in core_processes() if p.pid not in ignored and live(p)]
        if not alive or time.perf_counter() > deadline:
            return alive
        time.sleep(0.05)


def wait_gone(pid: int, timeout: float) -> float | None:
    started = time.perf_counter()
    while time.perf_counter() - started < timeout:
        if not psutil.pid_exists(pid):
            return time.perf_counter() - started
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return time.perf_counter() - started
        except psutil.NoSuchProcess:
            return time.perf_counter() - started
        time.sleep(0.02)
    return None


class Launch:
    def __init__(
        self, app: Path, scenario: str, workdir: Path, extra_env: dict | None = None
    ) -> None:
        self.workdir = workdir
        self.report_path = workdir / "report.json"
        (workdir / "tmp").mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update(
            {
                "CIPHERMOTH_SPIKE_SCENARIO": scenario,
                "CIPHERMOTH_SPIKE_REPORT": str(self.report_path),
                "CIPHERMOTH_SPIKE_DATA_DIR": str(workdir / "vault"),
                "CIPHERMOTH_SPIKE_TEST_HOOKS": "1",
                "TMPDIR": str(workdir / "tmp"),
                "TEMP": str(workdir / "tmp"),
                "TMP": str(workdir / "tmp"),
                "PYTHONPATH": str(workdir / "injected-pythonpath"),
                "PYTHONSTARTUP": str(workdir / "injected-startup.py"),
                "CIPHERMOTH_CANARY_ENV": "1",
            }
        )
        env.update(extra_env or {})
        self.out = open(workdir / "app.out", "wb")
        self.started = time.perf_counter()
        self.proc = subprocess.Popen(
            [str(app)],
            env=env,
            stdout=self.out,
            stderr=subprocess.STDOUT,
            cwd=str(workdir),
        )
        self.ps = psutil.Process(self.proc.pid)
        self.launch_time = self.ps.create_time()

    def report(self, timeout: float = 60) -> dict | None:
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            if self.report_path.exists():
                try:
                    return json.loads(self.report_path.read_text())
                except json.JSONDecodeError:
                    pass
            if self.proc.poll() is not None and not self.report_path.exists():
                return None
            time.sleep(0.02)
        return None

    def report_seen_after(self) -> float:
        return time.perf_counter() - self.started

    def tree(self) -> list[psutil.Process]:
        try:
            return [self.ps, *self.ps.children(recursive=True)]
        except psutil.NoSuchProcess:
            return []

    def webviews(self) -> list[psutil.Process]:
        if sys.platform != "darwin":
            return [
                p
                for p in self.tree()
                if any(safe_name(p).startswith(n) for n in WEBVIEW_NAMES)
            ]
        found = []
        for proc in psutil.process_iter(["name", "create_time"]):
            name = proc.info["name"] or ""
            if (
                name.startswith("com.apple.WebKit")
                and proc.info["create_time"] >= self.launch_time - 0.5
            ):
                found.append(proc)
        return found

    def core(self) -> psutil.Process | None:
        for proc in self.tree():
            try:
                if proc.name().startswith("ciphermoth-core"):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def wait_exit(self, timeout: float = 20) -> int | None:
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def cleanup(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        self.out.close()


def sockets(processes: list[psutil.Process], baseline: set) -> dict:
    listening, inet, uninspectable = [], [], []
    for proc in processes:
        try:
            for conn in proc.net_connections(kind="inet"):
                entry = {
                    "pid": proc.pid,
                    "name": safe_name(proc),
                    "status": conn.status,
                    "laddr": str(conn.laddr),
                    "raddr": str(conn.raddr),
                }
                inet.append(entry)
                if conn.status == psutil.CONN_LISTEN:
                    listening.append(entry)
        except psutil.AccessDenied:
            uninspectable.append(safe_name(proc))
        except psutil.NoSuchProcess:
            continue
    by_pid: dict[int, set[str]] = {}
    for entry in inet:
        by_pid.setdefault(entry["pid"], set()).add(entry["laddr"])
    for entry in inet:
        entry["self_pair"] = entry["raddr"] in by_pid[entry["pid"]]
    return {
        "listening": listening,
        "inet": inet,
        "core_external": [
            e
            for e in inet
            if e["name"].startswith("ciphermoth-core") and not e["self_pair"]
        ],
        "webview_connections": [
            e
            for e in inet
            if not e["name"].startswith("ciphermoth") and not e["self_pair"]
        ],
        "uninspectable": uninspectable,
        "namespace_new_listeners": sorted(map(str, listening_snapshot() - baseline)),
    }


def lsof_listen(pids: list[int]) -> str:
    if sys.platform == "win32" or not shutil.which("lsof"):
        return ""
    result = subprocess.run(
        ["lsof", "-nP", "-a", "-p", ",".join(map(str, pids)), "-i"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def memory(proc: psutil.Process | None) -> dict | None:
    if proc is None:
        return None
    try:
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = "?"
    try:
        info = proc.memory_full_info()
        return {
            "name": name,
            "rss_mb": round(info.rss / 2**20, 1),
            "uss_mb": round(getattr(info, "uss", 0) / 2**20, 1),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    try:
        return {"name": name, "rss_mb": round(proc.memory_info().rss / 2**20, 1)}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"name": name, "rss_mb": None}


def safe_name(proc: psutil.Process) -> str:
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "?"


def terminate_gracefully(launch: Launch) -> str:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(launch.proc.pid)], capture_output=True)
        return "taskkill (WM_CLOSE)"
    launch.proc.send_signal(signal.SIGTERM)
    return "SIGTERM"


def scenario_ipc(app: Path, root: Path) -> dict:
    launch = Launch(app, "ipc", root / "ipc")
    samples: list[float] = []
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            core = launch.core()
            if core is not None:
                try:
                    samples.append(core.memory_info().rss / 2**20)
                except psutil.NoSuchProcess:
                    pass
            time.sleep(0.05)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    try:
        code = launch.wait_exit(240)
        report = launch.report(timeout=5)
    finally:
        stop.set()
        launch.cleanup()
    leftovers = leftover_cores()
    result = report["result"] if report else None
    return {
        "ok": bool(result and result.get("ok")) and code == 0 and not leftovers,
        "exit_code": code,
        "checks": [
            {k: c.get(k) for k in ("name", "ok", "ms", "error")}
            for c in (result or {}).get("checks", [])
        ],
        "metrics": (result or {}).get("metrics"),
        "core_stats": (result or {}).get("core_stats"),
        "user_agent": (result or {}).get("user_agent"),
        "core_rss_peak_mb_sampled": round(max(samples), 1) if samples else None,
        "leftover_cores": leftovers,
    }


def scenario_exit(app: Path, root: Path, scenario: str) -> dict:
    launch = Launch(app, scenario, root / scenario)
    try:
        report = launch.report()
        core_pid = report["marks"]["core_ready"]["core_pid"] if report else None
        code = launch.wait_exit(20)
        gone = wait_gone(core_pid, 5) if core_pid else None
    finally:
        launch.cleanup()
    return {
        "ok": code == 0 and gone is not None,
        "exit_code": code,
        "core_pid": core_pid,
        "core_gone_after_s": gone,
        "marks": report["marks"] if report else None,
    }


def scenario_kill(app: Path, root: Path, mode: str) -> dict:
    baseline = listening_snapshot()
    launch = Launch(app, "idle", root / f"kill-{mode}")
    try:
        report = launch.report()
        if report is None:
            return {"ok": False, "error": "no ready report"}
        time.sleep(1.5)
        core_pid = report["marks"]["core_ready"]["core_pid"]
        tree = launch.tree() + launch.webviews()
        names = sorted({safe_name(p) for p in tree})
        net = sockets(tree, baseline)
        lsof = lsof_listen([p.pid for p in tree])
        idle = {
            "app": memory(launch.ps),
            "core": memory(psutil.Process(core_pid)),
            "webviews": [memory(p) for p in launch.webviews()],
        }
        if mode == "force":
            launch.proc.kill()
            how = "SIGKILL" if sys.platform != "win32" else "TerminateProcess"
        elif mode == "graceful":
            how = terminate_gracefully(launch)
        elif mode == "applequit":
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    'tell application id "com.ciphermoth.desktop-spike" to quit',
                ],
                capture_output=True,
                timeout=20,
            )
            how = "AppleScript quit"
        else:
            raise ValueError(mode)
        code = launch.wait_exit(20)
        gone = wait_gone(core_pid, 10)
    finally:
        launch.cleanup()
    return {
        "ok": gone is not None
        and gone <= 5
        and not net["listening"]
        and not net["core_external"]
        and not net["namespace_new_listeners"],
        "how": how,
        "exit_code": code,
        "core_pid": core_pid,
        "core_gone_after_s": None if gone is None else round(gone, 3),
        "sockets": net,
        "lsof_inet": lsof,
        "idle_memory": idle,
        "processes": names,
    }


def scenario_kill_core(app: Path, root: Path) -> dict:
    launch = Launch(app, "idle", root / "kill-core")
    try:
        report = launch.report()
        core_pid = report["marks"]["core_ready"]["core_pid"]
        psutil.Process(core_pid).kill()
        new_core = None
        started = time.perf_counter()
        while time.perf_counter() - started < 15:
            core = launch.core()
            if core is not None and core.pid != core_pid:
                new_core = core.pid
                break
            time.sleep(0.05)
        restarted_after = time.perf_counter() - started
        app_alive = launch.proc.poll() is None
        launch.proc.kill()
        launch.wait_exit(10)
        gone = wait_gone(new_core, 5) if new_core else None
    finally:
        launch.cleanup()
    return {
        "ok": bool(new_core) and app_alive and gone is not None,
        "old_core": core_pid,
        "new_core": new_core,
        "respawned_after_s": round(restarted_after, 3),
        "app_survived": app_alive,
        "new_core_gone_after_app_kill_s": gone,
    }


def scenario_startup_failure(app: Path, root: Path, variant: str) -> dict:
    target = app
    extra = {}
    if variant == "core-error":
        extra["CIPHERMOTH_SPIKE_FAIL_STARTUP"] = "1"
    elif variant == "missing-core":
        copy_root = root / "missing-core-bundle"
        if sys.platform == "darwin":
            bundle = app.parents[2]
            shutil.copytree(bundle, copy_root / bundle.name, symlinks=True)
            target = copy_root / bundle.name / "Contents" / "MacOS" / app.name
            shutil.rmtree(copy_root / bundle.name / "Contents" / "Resources" / "core")
        elif sys.platform == "win32":
            shutil.copytree(app.parent, copy_root, symlinks=True)
            target = copy_root / app.name
            shutil.rmtree(copy_root / "core")
        else:
            (copy_root / "bin").mkdir(parents=True)
            (copy_root / "lib" / "CipherMoth Spike").mkdir(parents=True)
            target = copy_root / "bin" / app.name
            shutil.copy2(app, target)
    launch = Launch(target, "idle", root / f"startup-{variant}", extra)
    try:
        report = launch.report(timeout=60)
        alive = launch.proc.poll() is None
        launch.proc.kill()
        launch.wait_exit(10)
    finally:
        launch.cleanup()
    failed = (report or {}).get("result", {}).get("failed")
    return {
        "ok": bool(failed) and alive and not leftover_cores(),
        "reason_shown": failed,
        "app_survived": alive,
    }


def scenario_symlinked_launch(app: Path, root: Path) -> dict:
    bundle = app.parents[2]
    link = root / "linked" / bundle.name
    link.parent.mkdir(parents=True)
    link.symlink_to(bundle)
    launch = Launch(link / "Contents" / "MacOS" / app.name, "idle", root / "symlinked")
    try:
        report = launch.report(timeout=60)
        alive = launch.proc.poll() is None
        launch.proc.kill()
        launch.wait_exit(10)
    finally:
        launch.cleanup()
    failed = (report or {}).get("result", {}).get("failed") or ""
    return {
        "ok": "cannot locate the bundled core" in failed
        and alive
        and not leftover_cores(),
        "reason_shown": failed,
        "app_survived": alive,
    }


def scenario_repeated(app: Path, root: Path, count: int) -> dict:
    runs = []
    for index in range(count):
        workdir = root / f"repeat-{index}"
        launch = Launch(app, "quit", workdir)
        try:
            report = launch.report()
            code = launch.wait_exit(20)
            wall = time.perf_counter() - launch.started
        finally:
            launch.cleanup()
        marks = (report or {}).get("marks", {})
        runs.append(
            {
                "exit_code": code,
                "core_ready_since_launch_ms": marks.get("core_ready", {}).get(
                    "since_launch_ms"
                ),
                "spawn_to_ready_ms": marks.get("core_ready", {}).get(
                    "spawn_to_ready_ms"
                ),
                "ui_ready_since_launch_ms": marks.get("ui_ready", {}).get(
                    "since_launch_ms"
                ),
                "wall_s": round(wall, 3),
            }
        )
    leftovers = leftover_cores()
    ready = [
        r["core_ready_since_launch_ms"]
        for r in runs
        if r["core_ready_since_launch_ms"] is not None
    ]
    ui = [
        r["ui_ready_since_launch_ms"]
        for r in runs
        if r["ui_ready_since_launch_ms"] is not None
    ]
    return {
        "ok": all(r["exit_code"] == 0 for r in runs)
        and not leftovers
        and len(ready) == count,
        "first_launch_core_ready_ms": ready[0] if ready else None,
        "warm_core_ready_ms_median": statistics.median(ready[1:])
        if len(ready) > 1
        else None,
        "warm_core_ready_ms_max": max(ready[1:]) if len(ready) > 1 else None,
        "first_launch_ui_ready_ms": ui[0] if ui else None,
        "warm_ui_ready_ms_median": statistics.median(ui[1:]) if len(ui) > 1 else None,
        "leftover_cores": leftovers,
        "runs": runs,
    }


def derive_vault_key(database: Path) -> str | None:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    if not database.exists():
        return None
    with sqlite3.connect(database) as conn:
        row = conn.execute("SELECT salt FROM spike_vault").fetchone()
    if row is None:
        return None
    kdf = Argon2id(salt=row[0], length=32, iterations=3, lanes=4, memory_cost=65536)
    return base64.urlsafe_b64encode(kdf.derive(MASTER.encode())).decode()


def platform_dirs() -> list[Path]:
    home = Path.home()
    if sys.platform == "darwin":
        library = home / "Library"
        return [
            library / "WebKit" / BUNDLE_ID,
            library / "Caches" / BUNDLE_ID,
            library / "Application Support" / BUNDLE_ID,
            library / "HTTPStorages",
            library / "Saved Application State" / f"{BUNDLE_ID}.savedState",
            library / "Logs" / "DiagnosticReports",
            Path(tempfile.gettempdir()),
        ]
    if sys.platform == "win32":
        local = Path(os.environ["LOCALAPPDATA"])
        return [
            local / BUNDLE_ID,
            local / "CrashDumps",
            local / "Temp",
            Path(tempfile.gettempdir()),
        ]
    return [
        home / ".local" / "share" / BUNDLE_ID,
        home / ".cache" / BUNDLE_ID,
        home / ".config" / BUNDLE_ID,
        Path("/var/crash"),
        Path(tempfile.gettempdir()),
    ]


def scan(roots: list[Path], needles: dict[str, bytes], since: float) -> dict:
    hits, scanned, skipped = [], 0, 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            try:
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or path.stat().st_mtime < since
                ):
                    continue
                if path.stat().st_size > 256 * 2**20:
                    skipped += 1
                    continue
                content = path.read_bytes()
            except OSError:
                skipped += 1
                continue
            scanned += 1
            for label, needle in needles.items():
                if needle in content:
                    hits.append({"file": str(path), "needle": label})
    return {"hits": hits, "scanned_files": scanned, "unreadable_or_large": skipped}


def scenario_canary(app: Path, root: Path) -> dict:
    since = time.time() - 1
    workdir = root / "canary"
    launch = Launch(app, "ipc", workdir)
    try:
        code = launch.wait_exit(240)
    finally:
        launch.cleanup()
    report = (
        json.loads(launch.report_path.read_text())
        if launch.report_path.exists()
        else {}
    )
    key = derive_vault_key(workdir / "vault" / "data" / "spike.db")
    if key is None:
        return {"ok": False, "error": "no vault salt to derive the key"}
    needles = {
        "master_password_utf8": MASTER.encode(),
        "master_password_utf16": MASTER.encode("utf-16-le"),
        "attachment_canary": ATTACHMENT_CANARY,
        "attachment_canary_utf16": ATTACHMENT_CANARY.decode().encode("utf-16-le"),
        "vault_key_base64": key.encode(),
        "vault_key_raw": base64.urlsafe_b64decode(key),
    }
    roots = [workdir, *platform_dirs()]
    found = scan(roots, needles, since)
    return {
        "ok": code == 0
        and bool(report.get("result", {}).get("ok"))
        and not found["hits"],
        "exit_code": code,
        "selftest_ok": report.get("result", {}).get("ok"),
        "roots": [str(r) for r in roots if r.exists()],
        **found,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--skip", nargs="*", default=[])
    args = parser.parse_args()
    app = args.app.resolve()
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix="cm-spike-")))
    before = [p.pid for p in core_processes()]
    BASELINE.update(before)
    plan = {
        "repeated_launches": lambda: scenario_repeated(app, root, args.repeat),
        "ipc_selftest": lambda: scenario_ipc(app, root),
        "normal_quit": lambda: scenario_exit(app, root, "quit"),
        "window_close": lambda: scenario_exit(app, root, "close"),
        "force_kill_shell": lambda: scenario_kill(app, root, "force"),
        "graceful_terminate_shell": lambda: scenario_kill(app, root, "graceful"),
        "core_killed_externally": lambda: scenario_kill_core(app, root),
        "canary_scan": lambda: scenario_canary(app, root),
        "startup_failure_core_error": lambda: scenario_startup_failure(
            app, root, "core-error"
        ),
        "startup_failure_missing_core": lambda: scenario_startup_failure(
            app, root, "missing-core"
        ),
    }
    if sys.platform == "darwin":
        plan["applescript_quit"] = lambda: scenario_kill(app, root, "applequit")
        plan["symlinked_launch_fails_closed"] = lambda: scenario_symlinked_launch(
            app, root
        )
    results = {
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "memory_gb": round(psutil.virtual_memory().total / 2**30, 1),
        },
        "app": str(app),
        "preexisting_cores": before,
        "scenarios": {},
    }
    for name, run in plan.items():
        if (args.only and name not in args.only) or name in args.skip:
            continue
        print(f"== {name}", flush=True)
        try:
            outcome = run()
        except Exception as exc:
            outcome = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        results["scenarios"][name] = outcome
        summary = {k: v for k, v in outcome.items() if k not in VERBOSE_KEYS}
        verdict = "PASS" if outcome.get("ok") else "FAIL"
        print(f"   {verdict} {json.dumps(summary)[:600]}", flush=True)
        if name == "ipc_selftest":
            for check in outcome.get("checks", []):
                mark = "ok " if check["ok"] else "BAD"
                error = check.get("error") or ""
                print(
                    f"      {mark} {check['name']} {check['ms']} ms {error}", flush=True
                )
    results["final_leftover_cores"] = leftover_cores(before)
    results["ok"] = (
        all(s.get("ok") for s in results["scenarios"].values())
        and not results["final_leftover_cores"]
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, default=str))
    shutil.rmtree(root, ignore_errors=True)
    print("ALL OK" if results["ok"] else "SOME FAILED")
    return 0 if results["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
