import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BACKEND = REPO / "backend"


def run(command: list[str], **kwargs) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, **kwargs)


def directory_size(path: Path) -> int:
    return sum(
        p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()
    )


def venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--build-dir", type=Path, default=HERE / "build")
    parser.add_argument("--dist-dir", type=Path, default=HERE / "dist")
    parser.add_argument(
        "--target", default=f"{sys.platform}-{platform.machine().lower()}"
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--find-links", type=Path)
    args = parser.parse_args()

    build = args.build_dir.resolve()
    dist = args.dist_dir.resolve()
    venv = build / "venv"
    timings: dict[str, float] = {}

    if not args.skip_install:
        started = time.perf_counter()
        shutil.rmtree(venv, ignore_errors=True)
        build.mkdir(parents=True, exist_ok=True)
        requirements = build / "requirements-backend.txt"
        run(
            [
                "uv",
                "export",
                "--project",
                str(BACKEND),
                "--frozen",
                "--no-dev",
                "--no-hashes",
                "--no-emit-project",
                "--no-header",
                "-o",
                str(requirements),
            ]
        )
        run(["uv", "venv", str(venv), "--python", args.python])
        run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(venv_python(venv)),
                "-r",
                str(requirements),
                "-r",
                str(HERE / "requirements-spike.txt"),
                *(["--find-links", str(args.find_links)] if args.find_links else []),
            ]
        )
        timings["install_s"] = round(time.perf_counter() - started, 1)

    started = time.perf_counter()
    shutil.rmtree(dist / "ciphermoth-core", ignore_errors=True)
    run(
        [
            str(venv_python(venv)),
            "-m",
            "PyInstaller",
            str(HERE / "core.spec"),
            "--noconfirm",
            "--clean",
            "--distpath",
            str(dist),
            "--workpath",
            str(build / "pyinstaller"),
        ],
        env={**os.environ, "PYTHONHASHSEED": "0", "SOURCE_DATE_EPOCH": "1760000000"},
    )
    timings["pyinstaller_s"] = round(time.perf_counter() - started, 1)

    core_dir = dist / "ciphermoth-core"
    executable = core_dir / (
        "ciphermoth-core.exe" if sys.platform == "win32" else "ciphermoth-core"
    )
    freeze = subprocess.run(
        [str(venv_python(venv)), "-m", "pip", "freeze"], capture_output=True, text=True
    )
    if freeze.returncode != 0:
        freeze = subprocess.run(
            ["uv", "pip", "freeze", "--python", str(venv_python(venv))],
            capture_output=True,
            text=True,
        )
    report = {
        "target": args.target,
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "python": subprocess.run(
            [
                str(venv_python(venv)),
                "-c",
                "import sys,platform;print(sys.version.split()[0], platform.machine())",
            ],
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "timings": timings,
        "core_dir_bytes": directory_size(core_dir),
        "core_file_count": sum(1 for p in core_dir.rglob("*") if p.is_file()),
        "largest_files": [
            {"bytes": size, "path": name}
            for size, name in sorted(
                (
                    (p.stat().st_size, str(p.relative_to(core_dir)))
                    for p in core_dir.rglob("*")
                    if p.is_file()
                ),
                reverse=True,
            )[:15]
        ],
        "executable": str(executable),
        "packages": freeze.stdout.split(),
    }
    print(json.dumps({k: v for k, v in report.items() if k != "packages"}, indent=2))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
