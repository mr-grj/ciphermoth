"""Publish only a fully verified draft; never overwrite an existing release."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

version = sys.argv[1]
root = Path(sys.argv[2]).resolve()
tag = f"v{version}"
repo = "mr-grj/ciphermoth"


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


files = {
    line.split("  ", 1)[1]: line.split("  ", 1)[0]
    for line in (root / "SHA256SUMS").read_text().splitlines()
}
files["SHA256SUMS"] = hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest()
notes = Path(tempfile.mkdtemp(prefix="ciphermoth-notes-")) / "notes.txt"
changelog = Path("CHANGELOG.md").read_text()
section = (
    changelog.split(f"## [{version}]", 1)[1]
    .split("\n## ", 1)[0]
    .split("\n", 1)[1]
    .strip()
)
notes.write_text(
    f"{section}\n\nDownload the file for your OS and CPU below. macOS: open the DMG and drag CipherMoth to Applications. Windows: run the installer. Linux: use the AppImage or install the .deb. Create a master password on first launch.\n\nThese installers have no Apple notarization or Microsoft verified-publisher certificate. Tauri updater signatures are separate and mandatory. See [installation and update instructions](https://github.com/{repo}/blob/{tag}/docs/UPDATING.md#desktop-updates).\n\nAppImage supports built-in updates; Debian uses package updates. SHA256SUMS and per-target source/build provenance are attached.\n\nBrowser extension: install it from the [Chrome Web Store](https://chromewebstore.google.com/detail/ciphermoth/gjdobbdnepjkgfpcmhjdagkcjholjkkd) or [addons.mozilla.org](https://addons.mozilla.org/firefox/addon/ciphermoth/) (store updates can follow this release by a few days). The ciphermoth-extension-* files are reproducible builds of this tag: the chromium zip loads unpacked, the chromium-store and firefox zips are the packages sent to the stores; see [the extension guide](https://github.com/{repo}/blob/{tag}/docs/EXTENSION.md).\n"
)
# If this fails because a draft already exists, inspect it before resuming;
# an automatic retry must not replace previously staged artifacts.
gh(
    "release",
    "create",
    tag,
    "--repo",
    repo,
    "--verify-tag",
    "--draft",
    "--title",
    f"CipherMoth {tag}",
    "--notes-file",
    str(notes),
)
gh(
    "release",
    "upload",
    tag,
    "--repo",
    repo,
    *[str(root / name) for name in sorted(files)],
)
release = json.loads(
    gh(
        "release",
        "view",
        tag,
        "--repo",
        repo,
        "--json",
        "assets,isDraft,isPrerelease,targetCommitish",
    )
)
assert release["isDraft"] and not release["isPrerelease"]
assert {a["name"] for a in release["assets"]} == set(files)
download = Path(tempfile.mkdtemp(prefix="ciphermoth-release-verify-"))
gh("release", "download", tag, "--repo", repo, "--dir", str(download))
for name, digest in files.items():
    assert hashlib.sha256((download / name).read_bytes()).hexdigest() == digest, name
gh(
    "release",
    "edit",
    tag,
    "--repo",
    repo,
    "--draft=false",
    "--prerelease=false",
    "--latest",
)
print(f"Published https://github.com/{repo}/releases/tag/{tag}")
