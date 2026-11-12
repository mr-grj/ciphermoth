"""Build two disposable native QA versions, restoring all source files afterwards."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from artifacts import ROOT, collect

FILES = [
    "backend/pyproject.toml",
    "frontend/package.json",
    "desktop/package.json",
    "desktop/src-tauri/Cargo.toml",
    "desktop/src-tauri/Cargo.lock",
    "desktop/src-tauri/tauri.conf.json",
    "desktop/core/desktop_core/entry.py",
]


def negative_signatures(destination):
    artifact = next(
        p
        for p in destination.iterdir()
        if p.name.startswith("CipherMoth_") and not p.name.endswith(".sig")
    )
    for scenario in ("signed-wrong-platform", "signed-wrong-version"):
        folder = destination.parent / scenario
        folder.mkdir(parents=True, exist_ok=True)
        name = artifact.name
        if scenario == "signed-wrong-platform":
            name = (
                name.replace("aarch64", "other")
                if "aarch64" in name
                else name.replace("x86_64", "other")
            )
        copied = folder / name
        shutil.copy2(artifact, copied)
        env = dict(os.environ)
        env["TAURI_SIGNING_PRIVATE_KEY_PATH"] = env.pop("TAURI_SIGNING_PRIVATE_KEY")
        result = subprocess.run(
            [
                "node",
                str(ROOT / "desktop/node_modules/@tauri-apps/cli/tauri.js"),
                "signer",
                "sign",
                "--app-version",
                "3.0.98" if scenario == "signed-wrong-version" else "3.0.99",
                str(copied),
            ],
            env=env,
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError("Negative signature fixture failed; output withheld")
        copied.unlink()


def main():
    out = Path(sys.argv[1]).resolve()
    original = {name: (ROOT / name).read_bytes() for name in FILES}
    bundle = ROOT / "desktop/src-tauri/target/release/bundle"
    bundles = (
        "app"
        if sys.platform == "darwin"
        else "nsis"
        if sys.platform == "win32"
        else "appimage"
    )
    try:
        for version in sys.argv[2:] or ("3.0.99", "3.0.98"):
            for name, data in original.items():
                path = ROOT / name
                text = data.decode()
                if name.endswith("Cargo.lock"):
                    # build-native-host.mjs builds with --locked, which refuses
                    # a lock file that disagrees with the app's Cargo.toml.
                    locked, count = re.subn(
                        r'(name = "ciphermoth-desktop"\r?\nversion = ")[^"\r\n]+(")',
                        lambda m, version=version: f"{m[1]}{version}{m[2]}",
                        text,
                    )
                    if count != 1:
                        raise SystemExit("ciphermoth-desktop not found in Cargo.lock")
                    path.write_bytes(locked.encode())
                    continue
                if name.endswith(".json"):
                    config = json.loads(text)
                    config["version"] = version
                    path.write_text(json.dumps(config, indent=2) + "\n")
                else:
                    # Preserve CRLF without a second Windows text-mode translation.
                    path.write_bytes(
                        re.sub(
                            r'(?m)^(version|CORE_VERSION) = "[^"\n]+"',
                            lambda m, version=version: f'{m[1]} = "{version}"',
                            text,
                            count=1,
                        ).encode()
                    )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "desktop/core/build_core.py"),
                    "--skip-install",
                ],
                check=True,
            )
            shutil.rmtree(bundle, ignore_errors=True)
            override = out / "fixture.json"
            override.parent.mkdir(parents=True, exist_ok=True)
            override.write_text(
                json.dumps(
                    {
                        "productName": "CipherMoth Update QA",
                        "identifier": "com.ciphermoth.desktop.update.qa",
                        "bundle": {"createUpdaterArtifacts": True},
                    }
                )
            )
            env = {**os.environ, "VITE_UPDATE_QA": "1"}
            subprocess.run(
                [
                    "node",
                    str(ROOT / "desktop/node_modules/@tauri-apps/cli/tauri.js"),
                    "build",
                    "--features",
                    "gui-test",
                    "--config",
                    "tauri.qa.json",
                    "--config",
                    str(override),
                    "--bundles",
                    bundles,
                    "--ci",
                ],
                cwd=ROOT / "desktop",
                env=env,
                check=True,
            )
            destination = out / version
            collect(bundle, destination, version, qa=True)
            if version == "3.0.99":
                negative_signatures(destination)
                # An authenticated but un-installable payload exercises actual
                # installer failure without altering OS permissions/protections.
                invalid = out / "invalid-bundle"
                folder, name = (
                    ("macos", "invalid.app.tar.gz")
                    if sys.platform == "darwin"
                    else ("nsis", "invalid.exe")
                    if sys.platform == "win32"
                    else ("appimage", "invalid.AppImage")
                )
                (invalid / folder).mkdir(parents=True, exist_ok=True)
                (invalid / folder / name).write_bytes(
                    b"CipherMoth intentionally invalid installer fixture\n"
                )
                collect(invalid, out / "installer-failure", version, qa=True)
            if sys.platform == "darwin":
                subprocess.run(
                    [
                        "ditto",
                        str(bundle / "macos/CipherMoth Update QA.app"),
                        str(destination / "CipherMoth Update QA.app"),
                    ],
                    check=True,
                )
    finally:
        for name, data in original.items():
            (ROOT / name).write_bytes(data)


if __name__ == "__main__":
    main()
