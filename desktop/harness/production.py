"""Install/extract the actual production package and test its bundled core.

Only disposable CI runners install system packages. macOS uses a private copy
from the DMG; existing Applications and vault directories are never touched.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "desktop/release"))
from artifacts import target  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    version = json.loads((ROOT / "desktop/package.json").read_text())["version"]
    native = target()
    prefix = f"CipherMoth_{version}_{native}"
    install = out / "installed"
    install.mkdir()
    if sys.platform == "darwin":
        mount = out / "dmg"
        mount.mkdir()
        subprocess.run(
            [
                "hdiutil",
                "attach",
                "-nobrowse",
                "-readonly",
                "-mountpoint",
                str(mount),
                str(args.packages / (prefix + ".dmg")),
            ],
            check=True,
        )
        try:
            subprocess.run(
                [
                    "ditto",
                    str(mount / "CipherMoth.app"),
                    str(install / "CipherMoth.app"),
                ],
                check=True,
            )
        finally:
            subprocess.run(["hdiutil", "detach", str(mount)], check=True)
        app = install / "CipherMoth.app"
        subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(app)], check=True
        )
        import plistlib

        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        assert info["CFBundleIdentifier"] == "com.ciphermoth.desktop"
        assert info["CFBundleShortVersionString"] == version
        assert "Alpha" not in info["CFBundleName"]
        shell = app / "Contents/MacOS/ciphermoth-desktop"
        assert subprocess.check_output(
            ["lipo", "-archs", str(shell)], text=True
        ).strip() == ("arm64" if native.endswith("aarch64") else "x86_64")
    elif sys.platform == "win32":
        assert os.environ.get("CI"), "Windows installation runs only on disposable CI"
        subprocess.run(
            [str(args.packages / (prefix + ".exe")), "/S", f"/D={install}"], check=True
        )
        shell = install / "ciphermoth-desktop.exe"
        data = shell.read_bytes()
        offset = struct.unpack_from("<I", data, 60)[0]
        assert struct.unpack_from("<H", data, offset + 4)[0] == (
            0xAA64 if native.endswith("aarch64") else 0x8664
        )
    else:
        assert os.environ.get("CI"), "Debian installation runs only on disposable CI"
        package = args.packages / (prefix + ".deb")
        subprocess.run(["sudo", "apt-get", "install", "-y", str(package)], check=True)
        subprocess.run(["dpkg-deb", "-x", str(package), str(install)], check=True)
        shell = install / "usr/bin/ciphermoth-desktop"
        assert struct.unpack_from("<H", shell.read_bytes(), 18)[0] == (
            183 if native.endswith("aarch64") else 62
        )
    # The browser extension's native host ships next to the shell (externalBin)
    # and, started for anyone but the pinned extensions, refuses.
    host = shell.parent / (
        "ciphermoth-native-host.exe"
        if sys.platform == "win32"
        else "ciphermoth-native-host"
    )
    assert host.is_file(), f"native host missing: {host}"
    if sys.platform == "darwin":
        assert subprocess.check_output(
            ["lipo", "-archs", str(host)], text=True
        ).strip() == ("arm64" if native.endswith("aarch64") else "x86_64")
    refused = subprocess.run(
        [str(host), "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"],
        input=b"",
        capture_output=True,
        timeout=30,
    )
    assert (refused.returncode, refused.stdout) == (2, b""), refused
    hello = json.dumps({"t": "hello", "id": "x", "nonce": "y"}).encode()
    # The store id and the throwaway id of 3.6.0-3.8.x unpacked copies.
    for chromium_id in (
        "gjdobbdnepjkgfpcmhjdagkcjholjkkd",
        "emeejhcdcdnlhejcpeohdafdnkmbaddn",
    ):
        probe = subprocess.run(
            [str(host), f"chrome-extension://{chromium_id}/"],
            input=struct.pack("=I", len(hello)) + hello,
            capture_output=True,
            timeout=30,
        )
        # No production app runs on the runner: the production host says so.
        answer = probe.stdout[4:]
        assert json.loads(answer) == {"t": "error", "code": "app_not_running"}, probe
    raw = shell.read_bytes()
    for forbidden in (
        b"qa_update_step",
        b"qa_report",
        b"CIPHERMOTH_QA_ROOT",
        b"CIPHERMOTH_QA_UPDATE_ENDPOINT",
        b"Native-GUI-password-canary!",
    ):
        assert forbidden not in raw, "QA hook/canary in production shell"
    cores = list(
        install.rglob(
            "ciphermoth-core.exe" if sys.platform == "win32" else "ciphermoth-core"
        )
    )
    cores = [p for p in cores if p.is_file()]
    assert len(cores) == 1, cores
    core = cores[0]
    assert (
        subprocess.check_output([str(core), "--version"], text=True).strip() == version
    )
    subprocess.run(
        [str(core), "--check-vectors", str(ROOT / "testdata/vectors")],
        check=True,
        stdout=(out / "vectors.json").open("wb"),
    )
    python = (
        ROOT
        / "desktop/core/build/venv"
        / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    )
    subprocess.run(
        [
            str(python),
            "-m",
            "pytest",
            "-q",
            str(ROOT / "desktop/core/tests"),
            f"--basetemp={out / 'core-data'}",
            f"--junitxml={out / 'core-tests.xml'}",
        ],
        env={**os.environ, "CORE_BIN": str(core)},
        cwd=ROOT,
        check=True,
    )
    result = {
        "target": native,
        "version": version,
        "production_identity": True,
        "native_architecture": True,
        "no_qa_hooks": True,
        "installed_core_tests": True,
        "native_host_refuses_strangers": True,
        "signature_scope": (
            "macOS ad-hoc bundle integrity; "
            "Tauri updater authorization checked separately"
        ),
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if sys.platform.startswith("linux"):
        # Production and the separately named QA .deb contain the same native
        # executable path. Remove only the package installed by this job before
        # the next QA install, on this disposable CI runner.
        package_name = subprocess.check_output(
            ["dpkg-deb", "-f", str(package), "Package"], text=True
        ).strip()
        subprocess.run(["sudo", "apt-get", "remove", "-y", package_name], check=True)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
