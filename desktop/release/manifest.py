"""Fail closed unless all six verified release artifact sets are complete."""

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

TARGETS = {
    f"{system}-{arch}"
    for system in ("darwin", "windows", "linux")
    for arch in ("aarch64", "x86_64")
}
# Installers also get a versionless copy (CipherMoth_<target>.<suffix>), so
# releases/latest/download/<name> links keep working across releases.
INSTALLERS = {"dmg", "exe", "deb", "AppImage"}


def generate(root, version, commit, verifier, public_key):
    config = json.loads(
        (Path(__file__).resolve().parents[1] / "src-tauri/tauri.conf.json").read_text()
    )
    assert public_key.read_text().strip() == config["plugins"]["updater"]["pubkey"]
    platforms = {}
    expected = set()
    for target in sorted(TARGETS):
        provenance = root / f"provenance-{target}.json"
        report = json.loads(provenance.read_text())
        assert report["commit"] == commit and report["version"] == version
        assert report["target"] == target and not report["qa"]
        formats = {
            "darwin": {"dmg", "app.tar.gz"},
            "windows": {"exe"},
            "linux": {"deb", "AppImage"},
        }[target.split("-")[0]]
        names = {f"CipherMoth_{version}_{target}.{suffix}" for suffix in formats}
        assert {row["file"] for row in report["artifacts"]} == names
        for row in report["artifacts"]:
            path = root / row["file"]
            assert path.stat().st_size == row["bytes"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
            expected.add(path.name)
            suffix = path.name.removeprefix(f"CipherMoth_{version}_{target}.")
            if suffix in INSTALLERS:
                latest = root / f"CipherMoth_{target}.{suffix}"
                shutil.copyfile(path, latest)
                expected.add(latest.name)
            if row["updater"]:
                assert target not in platforms
                sig = Path(str(path) + ".sig")
                subprocess.run(
                    [str(verifier), str(public_key), str(path), str(sig), version],
                    check=True,
                )
                platforms[target] = {
                    "url": f"https://github.com/mr-grj/ciphermoth/releases/download/v{version}/{path.name}",
                    "signature": sig.read_text().strip(),
                }
                expected.add(sig.name)
        expected.add(provenance.name)
    assert set(platforms) == TARGETS
    manifest = {
        "version": version,
        "notes": "A new CipherMoth release. See the release notes for changes.",
        "pub_date": datetime.datetime.now(datetime.UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "platforms": platforms,
    }
    (root / "latest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    expected.add("latest.json")
    sums = []
    for name in sorted(expected):
        sums.append(
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        )
    (root / "SHA256SUMS").write_text("".join(sums))
    return expected | {"SHA256SUMS"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    files = generate(
        args.artifacts, args.version, args.commit, args.verifier, args.public_key
    )
    print(f"Verified {len(files)} release files for all six native targets")
