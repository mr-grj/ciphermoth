"""Small install adapter using the feasibility harness's proven platform paths."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
bundle = root / "src-tauri/target/release/bundle"
python = (
    root
    / "core/build/venv"
    / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
)
if sys.platform == "darwin":
    app = bundle / "macos/CipherMoth QA.app"
    installed = args.out.parent / "installed/CipherMoth QA.app"
    installed.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ditto", str(app), str(installed)], check=True)
    executable = installed / "Contents/MacOS/ciphermoth-desktop"
elif sys.platform == "win32":
    installer = next((bundle / "nsis").glob("*QA*.exe"))
    subprocess.run([str(installer), "/S"], check=True)
    folder = Path(os.environ["LOCALAPPDATA"]) / "CipherMoth QA"
    # By name: the folder also holds the uninstaller and ciphermoth-native-host.exe.
    executable = folder / "ciphermoth-desktop.exe"
    assert executable.is_file(), sorted(p.name for p in folder.glob("*.exe"))
else:
    packages = list((bundle / "deb").glob("*.deb"))
    package = max(packages, key=lambda p: p.stat().st_mtime)
    subprocess.run(["sudo", "apt-get", "install", "-y", str(package)], check=True)
    executable = Path("/usr/bin/ciphermoth-desktop")
command = [
    str(python),
    str(root / "harness/native.py"),
    "--app",
    str(executable),
    "--root",
    str(args.out),
]
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
subprocess.run(command, check=True)
result_path = args.out / "results.json"
result = json.loads(result_path.read_text(encoding="utf-8"))
result["artifacts"] = [
    {"name": path.name, "bytes": path.stat().st_size}
    for path in bundle.rglob("*")
    if path.is_file() and path.suffix in (".dmg", ".deb", ".exe")
]
if sys.platform == "darwin":
    result["app_bundle_bytes"] = sum(
        p.stat().st_size
        for p in installed.rglob("*")
        if p.is_file() and not p.is_symlink()
    )
result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
