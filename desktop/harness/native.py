"""Exercise the QA .app in a native webview, its real UI, and process lifecycle.

Uses only synthetic data in a required absolute directory. No backend listener,
no browser substitution, no production self-test command.
"""

import argparse
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import extension
import psutil

# The desktop-mode stages (harness/extension.py) run on every platform.
EXTENSION_STAGES = ("extension", "extension_off", "extension_pairing")
EXTENSION = {"app": None, "host": None, "results": {}}


class MemorySampler:
    """RSS includes the process tree and newly started macOS WebKit XPCs.

    XPCs belong to launchd, so capture their PIDs separately and retain the
    attribution scope in the report. RSS can double-count shared pages.
    """

    def __init__(self, pid):
        self.pid = pid
        self.baseline = set(psutil.pids())
        self.stop = threading.Event()
        self.peak = 0
        self.webviews = set()
        self.samples = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.wait(0.1):
            try:
                processes = [psutil.Process(self.pid)]
                processes += processes[0].children(recursive=True)
                if __import__("sys").platform == "darwin":
                    for process in psutil.process_iter(["pid", "name"]):
                        if process.pid not in self.baseline and "com.apple.WebKit." in (
                            process.info["name"] or ""
                        ):
                            processes.append(process)
                            self.webviews.add(process.pid)
                rss = 0
                for process in {p.pid: p for p in processes}.values():
                    try:
                        rss += process.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self.peak = max(self.peak, rss)
                self.samples += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def finish(self):
        self.stop.set()
        self.thread.join(2)
        return {
            "peak_total_rss": self.peak,
            "samples": self.samples,
            "macos_new_webkit_pids": sorted(self.webviews),
            "scope": "process tree plus WebKit XPCs started during this isolated launch; RSS includes shared pages",
        }


def wait_report(path, process, timeout=240, dialogs=False, started=None):
    started = started or time.monotonic()
    interactive = None
    initial_core = None
    deadline = time.monotonic() + timeout
    stages = set()
    while time.monotonic() < deadline:
        if path.exists():
            report = json.loads(path.read_text(encoding="utf-8"))
            stage = report.get("stage")
            if stage == "interactive" and interactive is None:
                interactive = round(time.monotonic() - started, 3)
                initial_core = report.get("core")
            stage_key = report.get("ack", stage)
            if stage in ("extension", "extension_off") and stage_key not in stages:
                stages.add(stage_key)
                if stage == "extension":
                    on = extension.check_on(path.parent, report, path, EXTENSION["app"])
                    EXTENSION["host"] = on["host"]
                    EXTENSION["results"]["on"] = on
                else:
                    EXTENSION["results"]["off"] = extension.check_off(path.parent)
                    extension.check_not_running(EXTENSION["host"], path.parent)
                    EXTENSION["results"]["off"]["host_says_not_running"] = True
                (path.parent / (report["ack"] + ".done")).touch()
            if stage == "native_idle" and stage not in stages:
                stages.add(stage)
                pid = report["core"]["info"]["pid"]
                idle_deadline = time.monotonic() + 33
                while time.monotonic() < idle_deadline and psutil.pid_exists(pid):
                    try:
                        if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                            break
                    except psutil.NoSuchProcess:
                        break
                    time.sleep(0.1)
                else:
                    assert not psutil.pid_exists(pid), (
                        "idle lock depended on blocked JavaScript timers"
                    )
            if (
                stage
                and stage not in EXTENSION_STAGES
                and stage_key not in stages
                and __import__("sys").platform == "darwin"
            ):
                stages.add(stage_key)
                if stage == "clipboard_timeout":
                    assert (
                        subprocess.check_output(["pbpaste"]).decode()
                        == "Native-clipboard-canary"
                    )
                    subprocess.run(
                        ["osascript", "-e", 'tell application "Finder" to activate'],
                        check=True,
                    )
                    clipboard_deadline = time.monotonic() + 3
                    while (
                        time.monotonic() < clipboard_deadline
                        and subprocess.check_output(["pbpaste"]) != b""
                    ):
                        time.sleep(0.1)
                    assert subprocess.check_output(["pbpaste"]) == b"", (
                        "native clipboard did not clear in background"
                    )
                elif stage == "clipboard_replaced":
                    subprocess.run(["pbcopy"], input=b"User replacement", check=True)
                    time.sleep(1.3)
                    assert (
                        subprocess.check_output(["pbpaste"]) == b"User replacement"
                    ), "clipboard replacement erased"
                elif stage in ("backup_save", "backup_open"):
                    assert dialogs, "Build dialog QA only with --dialogs on macOS"
                    # The OS picker authorizes the path; it never enters JS.
                    destination = path.parent / "ciphermoth-backup.cmbackup"
                    script = """on run argv
tell application id "com.ciphermoth.desktop.qa" to activate
delay 1
tell application "System Events"
    tell process "ciphermoth-desktop"
        set frontmost to true
        keystroke "g" using {command down, shift down}
        delay 0.5
        keystroke (item 1 of argv)
        key code 36
        delay 0.8
        key code 36
    end tell
end tell
end run"""
                    if stage == "backup_save":
                        destination.unlink(missing_ok=True)
                    subprocess.run(
                        ["osascript", "-e", script, str(destination)],
                        check=True,
                        timeout=15,
                    )
                if report.get("ack"):
                    # The app cannot start the next clipboard write until the
                    # host has checked this one, even on a slow CI runner.
                    (path.parent / (report["ack"] + ".done")).touch()
            if not stage:
                assert report.get("ok"), report
                report["launch_to_interactive_s"] = interactive
                report["initial_core"] = initial_core
                return report
        if process.poll() is not None:
            raise RuntimeError(f"App exited {process.returncode}")
        time.sleep(0.1)
    raise TimeoutError("Native webview did not report")


def gone(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--dialogs", action="store_true")
    args = parser.parse_args()
    assert args.app.is_absolute() and args.root.is_absolute()
    args.root.mkdir(parents=True, exist_ok=True)
    report_path = args.root / "webview.json"
    report_path.unlink(missing_ok=True)
    extension.prepare(args.root)
    EXTENSION["app"] = args.app
    env = {**os.environ, "CIPHERMOTH_QA_ROOT": str(args.root)}
    listeners = (
        {
            (str(c.family), str(c.type), str(c.laddr))
            for c in psutil.net_connections(kind="inet")
            if c.status == psutil.CONN_LISTEN
        }
        if __import__("sys").platform.startswith("linux")
        else set()
    )
    started = time.monotonic()
    with (args.root / "shell.log").open("wb") as log:
        app = subprocess.Popen([str(args.app)], env=env, stdout=log, stderr=log)
        sampler = MemorySampler(app.pid)
        try:
            first = wait_report(report_path, app, dialogs=args.dialogs, started=started)
            first["launch_to_ui_s"] = round(time.monotonic() - started, 3)
            core_pid = first["core"]["info"]["pid"]
            if __import__("sys").platform.startswith("linux"):
                current = {
                    (str(c.family), str(c.type), str(c.laddr))
                    for c in psutil.net_connections(kind="inet")
                    if c.status == psutil.CONN_LISTEN
                }
                assert not current - listeners, (
                    "new listening socket in isolated test namespace"
                )
            first["shell_rss"] = psutil.Process(app.pid).memory_info().rss
            first["core_rss"] = psutil.Process(core_pid).memory_info().rss
            first["memory"] = sampler.finish()
            if not __import__("sys").platform.startswith("linux"):
                assert not [
                    c
                    for c in psutil.Process(core_pid).net_connections()
                    if c.status == psutil.CONN_LISTEN
                ]
            report_path.unlink()
            psutil.Process(core_pid).kill()
            restarted = wait_report(report_path, app, dialogs=args.dialogs)
            assert restarted["core"]["generation"] > first["core"]["generation"]
            assert "retrieve password through native IPC" in restarted["checks"]
            new_core = restarted["core"]["info"]["pid"]
            app.kill()
            app.wait(10)
            assert gone(new_core), "orphaned core after shell SIGKILL"
            report_path.unlink()
            started = time.monotonic()
            app = subprocess.Popen([str(args.app)], env=env, stdout=log, stderr=log)
            reopened = wait_report(
                report_path, app, dialogs=args.dialogs, started=started
            )
            assert not reopened["fresh"]
            core_pid = reopened["core"]["info"]["pid"]
            if __import__("sys").platform == "darwin":
                assert (
                    subprocess.check_output(["pbpaste"])
                    == b"Native-quit-clipboard-canary"
                )
                subprocess.run(
                    [
                        "osascript",
                        "-e",
                        'tell application id "com.ciphermoth.desktop.qa" to quit',
                    ],
                    check=True,
                    timeout=10,
                )
            else:
                app.terminate()
            app.wait(10)
            assert gone(core_pid), "orphaned core after quit"
            if __import__("sys").platform == "darwin":
                assert subprocess.check_output(["pbpaste"]) == b"", (
                    "owned clipboard survived quit"
                )
                reopened["clipboard_cleared_on_quit"] = True
            assert EXTENSION["results"].get("on") and EXTENSION["results"].get("off"), (
                "the browser-extension stages did not run"
            )
            result = {
                "extension": EXTENSION["results"],
                "first": first,
                "crash_restart": restarted,
                "reopen": reopened,
                "orphan_checks": True,
            }
            (args.root / "results.json").write_text(json.dumps(result, indent=2))
            print(json.dumps(result, indent=2))
        finally:
            sampler.finish()
            if app.poll() is None:
                app.kill()
                app.wait(10)


if __name__ == "__main__":
    main()
