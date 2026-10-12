import argparse
import glob
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPIKE = HERE.parent
CORE = SPIKE / "core"
APP = SPIKE / "app"
TAURI = APP / "src-tauri"
REPO = SPIKE.parents[1]
VECTORS = REPO / "testdata" / "vectors"


def run(
    command: list[str],
    cwd: Path | None = None,
    env: dict | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        check=check,
        shell=sys.platform == "win32" and command[0] in {"npm", "npx"},
    )


def venv_python(build_dir: Path) -> Path:
    if sys.platform == "win32":
        return build_dir / "venv" / "Scripts" / "python.exe"
    return build_dir / "venv" / "bin" / "python"


def size_of(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(
        p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()
    )


class Stages:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.out = args.out.resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.build_dir = CORE / "build"
        self.core_dir = CORE / "dist" / "ciphermoth-core"
        exe = "ciphermoth-core.exe" if sys.platform == "win32" else "ciphermoth-core"
        self.core_exe = self.core_dir / exe
        self.summary: dict = {
            "target": args.target,
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "cpu_count": os.cpu_count(),
            },
            "stages": {},
        }

    def record(self, name: str, started: float, ok: bool, **extra) -> None:
        self.summary["stages"][name] = {
            "ok": ok,
            "seconds": round(time.perf_counter() - started, 1),
            **extra,
        }
        (self.out / "summary.json").write_text(json.dumps(self.summary, indent=2))

    def core(self) -> None:
        started = time.perf_counter()
        report = self.out / "build-core.json"
        result = run(
            [
                sys.executable,
                str(CORE / "build_core.py"),
                "--python",
                self.args.python,
                "--target",
                self.args.target,
                "--report",
                str(report),
            ],
            check=False,
        )
        data = json.loads(report.read_text()) if report.exists() else {}
        self.record(
            "build_core",
            started,
            result.returncode == 0,
            core_dir_bytes=data.get("core_dir_bytes"),
            timings=data.get("timings"),
        )
        if result.returncode != 0:
            raise SystemExit("core build failed")

    def vectors(self) -> None:
        started = time.perf_counter()
        frozen = subprocess.run(
            [str(self.core_exe), "--check-vectors", str(VECTORS)],
            capture_output=True,
            text=True,
        )
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join([str(REPO / "backend"), str(CORE)]),
        }
        source = subprocess.run(
            [
                str(venv_python(self.build_dir)),
                str(CORE / "core_main.py"),
                "--check-vectors",
                str(VECTORS),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        (self.out / "vectors-frozen.json").write_text(frozen.stdout or frozen.stderr)
        (self.out / "vectors-source.json").write_text(source.stdout or source.stderr)
        try:
            f, s = json.loads(frozen.stdout), json.loads(source.stdout)
            identical = f["results_sha256"] == s["results_sha256"]
            ok = (
                frozen.returncode == 0
                and source.returncode == 0
                and identical
                and not f["failed"]
            )
            self.record(
                "vectors",
                started,
                ok,
                passed=f["passed"],
                failed=f["failed"],
                identical_digest=identical,
                digest=f["results_sha256"],
                environment=f["environment"],
            )
        except (json.JSONDecodeError, KeyError) as exc:
            self.record(
                "vectors",
                started,
                False,
                error=f"{type(exc).__name__}: {frozen.stderr[-2000:]}",
            )

    def core_tests(self) -> None:
        started = time.perf_counter()
        run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(venv_python(self.build_dir)),
                "-r",
                str(CORE / "requirements-test.txt"),
            ]
        )
        junit = self.out / "core-tests.xml"
        result = run(
            [
                str(venv_python(self.build_dir)),
                "-m",
                "pytest",
                "-q",
                f"--junitxml={junit}",
            ],
            cwd=CORE,
            env={"CORE_BIN": str(self.core_exe)},
            check=False,
        )
        self.record("core_protocol_tests", started, result.returncode == 0)

    def app(self) -> None:
        started = time.perf_counter()
        run(["npm", "ci", "--no-audit", "--no-fund"], cwd=APP)
        command = ["npx", "tauri", "build", "--bundles", self.args.bundles, "--ci"]
        if self.args.rust_target:
            command += ["--target", self.args.rust_target]
        result = run(command, cwd=APP, env={"CI": "true"}, check=False)
        target_dir = TAURI / "target" / (self.args.rust_target or "") / "release"
        bundles = {}
        for pattern in (
            "bundle/macos/*.app",
            "bundle/dmg/*.dmg",
            "bundle/deb/*.deb",
            "bundle/rpm/*.rpm",
            "bundle/appimage/*.AppImage",
            "bundle/nsis/*.exe",
            "bundle/msi/*.msi",
        ):
            for match in glob.glob(str(target_dir / pattern)):
                bundles[Path(match).name] = size_of(Path(match))
        binary = target_dir / (
            "ciphermoth-desktop-spike.exe"
            if sys.platform == "win32"
            else "ciphermoth-desktop-spike"
        )
        self.record(
            "build_app",
            started,
            result.returncode == 0 and bool(bundles),
            bundles=bundles,
            shell_binary_bytes=size_of(binary) if binary.exists() else None,
            core_dir_bytes=size_of(self.core_dir),
        )
        (self.out / "target_dir.txt").write_text(str(target_dir))
        if result.returncode != 0:
            raise SystemExit("app build failed")

    def install(self) -> Path:
        target_dir = Path((self.out / "target_dir.txt").read_text())
        started = time.perf_counter()
        if sys.platform == "darwin":
            app = next(iter(glob.glob(str(target_dir / "bundle/macos/*.app"))))
            installed = (
                Path(self.args.install_root or (Path.home() / "cm-spike-install"))
                / Path(app).name
            )
            shutil.rmtree(installed, ignore_errors=True)
            installed.parent.mkdir(parents=True, exist_ok=True)
            run(["ditto", app, str(installed)])
            executable = installed / "Contents" / "MacOS" / "ciphermoth-desktop-spike"
            how = "ditto .app"
        elif sys.platform == "win32":
            installer = next(iter(glob.glob(str(target_dir / "bundle/nsis/*.exe"))))
            run([installer, "/S"])
            root = Path(os.environ["LOCALAPPDATA"]) / "CipherMoth Spike"
            candidates = [
                p for p in root.glob("*.exe") if "uninstall" not in p.name.lower()
            ]
            executable = candidates[0]
            how = "NSIS /S (currentUser)"
        else:
            deb = next(iter(glob.glob(str(target_dir / "bundle/deb/*.deb"))))
            run(["sudo", "apt-get", "install", "-y", "--no-install-recommends", deb])
            executable = Path("/usr/bin/ciphermoth-desktop-spike")
            how = "apt install ./deb"
        self.record(
            "install", started, executable.exists(), how=how, executable=str(executable)
        )
        return executable

    def lifecycle(self, executable: Path) -> None:
        started = time.perf_counter()
        command = [
            str(venv_python(self.build_dir)),
            str(HERE / "lifecycle.py"),
            "--app",
            str(executable),
            "--out",
            str(self.out / "lifecycle.json"),
            "--repeat",
            str(self.args.repeat),
        ]
        if self.args.skip:
            command += ["--skip", *self.args.skip]
        if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
            command = [
                "xvfb-run",
                "-a",
                "-s",
                "-screen 0 1280x1024x24",
                "dbus-run-session",
                "--",
                *command,
            ]
        result = run(command, check=False)
        data = (
            json.loads((self.out / "lifecycle.json").read_text())
            if (self.out / "lifecycle.json").exists()
            else {}
        )
        self.record(
            "lifecycle",
            started,
            result.returncode == 0,
            scenarios={k: v.get("ok") for k, v in data.get("scenarios", {}).items()},
        )

    def appimage(self) -> None:
        recorded = self.out / "target_dir.txt"
        target_dir = (
            Path(recorded.read_text())
            if recorded.exists()
            else TAURI / "target" / "release"
        )
        images = glob.glob(str(target_dir / "bundle/appimage/*.AppImage"))
        if not images:
            return
        started = time.perf_counter()
        image = Path(images[0])
        image.chmod(0o755)
        command = [
            str(venv_python(self.build_dir)),
            str(HERE / "lifecycle.py"),
            "--app",
            str(image),
            "--out",
            str(self.out / "lifecycle-appimage.json"),
            "--repeat",
            "3",
            "--only",
            "repeated_launches",
            "ipc_selftest",
            "force_kill_shell",
        ]
        if not os.environ.get("DISPLAY"):
            command = [
                "xvfb-run",
                "-a",
                "-s",
                "-screen 0 1280x1024x24",
                "dbus-run-session",
                "--",
                *command,
            ]
        result = run(command, check=False, env={"APPIMAGE_EXTRACT_AND_RUN": "1"})
        self.record("appimage_lifecycle", started, result.returncode == 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--python", default="3.13.15")
    parser.add_argument("--bundles", required=True)
    parser.add_argument("--rust-target")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=8)
    parser.add_argument("--skip", nargs="*")
    parser.add_argument("--install-root")
    parser.add_argument(
        "--stages",
        nargs="*",
        default=[
            "core",
            "vectors",
            "core_tests",
            "app",
            "install",
            "lifecycle",
            "appimage",
        ],
    )
    args = parser.parse_args()
    stages = Stages(args)
    executable = None
    for stage in args.stages:
        print(f"\n===== {stage}", flush=True)
        if stage == "install":
            executable = stages.install()
        elif stage == "lifecycle":
            stages.lifecycle(executable or Path(args.install_root))
        else:
            getattr(stages, stage)()
    ok = all(s["ok"] for s in stages.summary["stages"].values())
    stages.summary["ok"] = ok
    (stages.out / "summary.json").write_text(json.dumps(stages.summary, indent=2))
    print(json.dumps(stages.summary, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
