"""One version across both editions; --check never modifies the checkout."""

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def versions():
    values = {
        name: json.loads((ROOT / name).read_text())["version"]
        for name in (
            "frontend/package.json",
            "desktop/package.json",
            "extension/package.json",
            "extension/manifest/base.json",
            "desktop/src-tauri/tauri.conf.json",
        )
    }
    values["backend/pyproject.toml"] = tomllib.loads(
        (ROOT / "backend/pyproject.toml").read_text()
    )["project"]["version"]
    values["desktop/src-tauri/Cargo.toml"] = tomllib.loads(
        (ROOT / "desktop/src-tauri/Cargo.toml").read_text()
    )["package"]["version"]
    values["desktop/core/desktop_core/entry.py"] = re.search(
        r'CORE_VERSION = "([^"]+)"',
        (ROOT / "desktop/core/desktop_core/entry.py").read_text(),
    )[1]
    for name in (
        "frontend/package-lock.json",
        "desktop/package-lock.json",
        "extension/package-lock.json",
    ):
        data = json.loads((ROOT / name).read_text())
        values[name] = data["version"]
        values[name + " root"] = data["packages"][""]["version"]
    for name, package in (
        ("backend/uv.lock", "backend"),
        ("desktop/src-tauri/Cargo.lock", "ciphermoth-desktop"),
    ):
        values[name] = next(
            p["version"]
            for p in tomllib.loads((ROOT / name).read_text())["package"]
            if p["name"] == package
        )
    return values


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    assert re.fullmatch(r"\d+\.\d+\.\d+", args.version), "Stable X.Y.Z required"
    if not args.check:
        for folder in ("frontend", "desktop", "extension"):
            subprocess.run(
                [
                    "npm",
                    "--no-git-tag-version",
                    "--allow-same-version",
                    "version",
                    args.version,
                ],
                cwd=ROOT / folder,
                check=True,
            )
        for name in (
            "desktop/src-tauri/tauri.conf.json",
            "extension/manifest/base.json",
        ):
            p = ROOT / name
            data = json.loads(p.read_text())
            data["version"] = args.version
            p.write_text(json.dumps(data, indent=2) + "\n")
        for name in (
            "backend/pyproject.toml",
            "desktop/src-tauri/Cargo.toml",
            "desktop/core/desktop_core/entry.py",
        ):
            p = ROOT / name
            p.write_text(
                re.sub(
                    r'(?m)^(version|CORE_VERSION) = "[^"\n]+"',
                    lambda m: f'{m[1]} = "{args.version}"',
                    p.read_text(),
                    count=1,
                )
            )
        subprocess.run(["uv", "lock"], cwd=ROOT / "backend", check=True)
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=ROOT / "desktop/src-tauri",
            check=True,
            stdout=subprocess.DEVNULL,
        )
    values = versions()
    assert set(values.values()) == {args.version}, values
    print(f"All {len(values)} version sources agree: {args.version}")
