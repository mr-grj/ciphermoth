"""Regression checks for release-workflow trust boundaries."""

import re
from pathlib import Path

WORKFLOW = (
    Path(__file__).parents[2] / ".github" / "workflows" / "desktop.yml"
).read_text()


def test_desktop_build_never_runs_an_unverified_rust_bootstrap() -> None:
    """An incomplete runner image must fail closed instead of executing a download."""
    assert "sh.rustup.rs" not in WORKFLOW
    assert "rustup-init" not in WORKFLOW
    assert "command -v rustup >/dev/null 2>&1" in WORKFLOW


def test_windows_vcpkg_source_is_verified_before_bootstrap() -> None:
    """Release jobs may only execute the reviewed, immutable vcpkg revision."""
    commit = re.search(r'^  VCPKG_COMMIT: "([0-9a-f]{40})"$', WORKFLOW, re.MULTILINE)
    assert commit is not None
    verify = "if ($LASTEXITCODE -ne 0 -or $actualCommit -cne $env:VCPKG_COMMIT)"
    bootstrap = '& "$vcpkgRoot\\bootstrap-vcpkg.bat" -disableMetrics'
    assert "git clone --depth 1 --branch $env:VCPKG_TAG" in WORKFLOW
    assert "git clone --depth 1 https://github.com/microsoft/vcpkg" not in WORKFLOW
    assert verify in WORKFLOW
    assert bootstrap in WORKFLOW
    assert WORKFLOW.index(verify) < WORKFLOW.index(bootstrap)


def test_openssl_source_uses_a_reviewed_digest() -> None:
    """A checksum downloaded beside an archive is not an independent pin."""
    digest = re.search(r'^  OPENSSL_SHA256: "([0-9a-f]{64})"$', WORKFLOW, re.MULTILINE)
    assert digest is not None
    build_script = (
        Path(__file__).parents[2] / "desktop" / "core" / "build_openssl.sh"
    ).read_text()
    assert "OPENSSL_SHA256:?" in build_script
    assert "openssl.tar.gz.sha256" not in build_script
    assert '[ "$expected" = "$actual" ]' in build_script
