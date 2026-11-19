"""Regression checks for release-workflow trust boundaries."""

import re
from pathlib import Path

WORKFLOW = (
    Path(__file__).parents[2] / ".github" / "workflows" / "desktop.yml"
).read_text()
RELEASE_WORKFLOW = (
    Path(__file__).parents[2] / ".github" / "workflows" / "release.yml"
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


def test_protected_signing_key_is_scoped_to_the_artifact_step() -> None:
    """Compilers, tests, and QA harnesses must never receive the release key."""
    configure = WORKFLOW.index("- name: Configure updater signing")
    build = WORKFLOW.index("- name: Build production application")
    signing = WORKFLOW.index("- name: Collect and sign production packages")
    install = WORKFLOW.index("- name: Install and test the actual production package")
    assert configure < build < signing < install
    assert "RELEASE_KEY:" not in WORKFLOW[configure:build]
    assert "RELEASE_KEY:" not in WORKFLOW[build:signing]
    assert "RELEASE_KEY:" in WORKFLOW[signing:install]


def test_verified_first_install_files_receive_build_attestations() -> None:
    """Unsigned OS installers still need identity-bound first-install provenance."""
    publish = RELEASE_WORKFLOW[RELEASE_WORKFLOW.index("\n  publish:") :]
    verify = publish.index("- name: Verify every signature and generate the manifest")
    attest = publish.index("- name: Attest the verified release files")
    release = publish.index("- name: Stage and publish the complete stable release")
    assert verify < attest < release
    assert "      id-token: write" in publish
    assert "      attestations: write" in publish
    assert "subject-path: release-assets/*" in publish
