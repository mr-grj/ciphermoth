"""Release signing secrets have a deliberately short filesystem lifetime."""

import importlib.util
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


def _artifacts_module():
    path = ROOT / "desktop" / "release" / "artifacts.py"
    spec = importlib.util.spec_from_file_location("release_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _update_fixtures_module():
    path = ROOT / "desktop" / "release" / "build_update_fixtures.py"
    spec = importlib.util.spec_from_file_location("release_update_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def test_protected_signing_key_exists_only_inside_signing_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _artifacts_module()
    secret = "synthetic release key"
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("RELEASE_SIGNING", "true")
    monkeypatch.setenv("RELEASE_KEY", secret)

    with artifacts.signing_key() as key:
        assert key.read_text() == secret
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        assert "RELEASE_KEY" not in artifacts.os.environ
        root = key.parent

    assert not root.exists()


def test_validation_build_refuses_an_accidental_protected_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _artifacts_module()
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("RELEASE_SIGNING", "false")
    monkeypatch.setenv("RELEASE_KEY", "synthetic release key")

    with pytest.raises(RuntimeError, match="validation build"):
        with artifacts.signing_key():
            pass


def test_qa_fixtures_replace_the_production_updater_public_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = _update_fixtures_module()
    config = tmp_path / "desktop" / "src-tauri" / "tauri.conf.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"plugins":{"updater":{"pubkey":"synthetic production key"}}}\n')
    private = tmp_path / "updater.key"
    private.write_text("synthetic disposable private key")
    Path(str(private) + ".pub").write_text("synthetic disposable public key\n")
    monkeypatch.setattr(fixtures, "ROOT", tmp_path)
    monkeypatch.setenv("TAURI_SIGNING_PRIVATE_KEY", str(private))

    fixtures.configure_disposable_updater_key()

    assert (
        fixtures.json.loads(config.read_text())["plugins"]["updater"]["pubkey"]
        == "synthetic disposable public key"
    )


def test_qa_fixtures_fail_closed_without_a_complete_key_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = _update_fixtures_module()
    private = tmp_path / "updater.key"
    private.write_text("synthetic disposable private key")
    monkeypatch.setattr(fixtures, "ROOT", tmp_path)
    monkeypatch.setenv("TAURI_SIGNING_PRIVATE_KEY", str(private))

    with pytest.raises(RuntimeError, match="key pair is incomplete"):
        fixtures.configure_disposable_updater_key()


def test_every_qa_fixture_build_uses_the_disposable_key_after_version_rewrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = _update_fixtures_module()
    production = '{"version":"1.0.0","plugins":{"updater":{"pubkey":"production"}}}\n'
    sources = {
        "backend/pyproject.toml": 'version = "1.0.0"\n',
        "frontend/package.json": '{"version":"1.0.0"}\n',
        "desktop/package.json": '{"version":"1.0.0"}\n',
        "desktop/src-tauri/Cargo.toml": 'version = "1.0.0"\n',
        "desktop/src-tauri/Cargo.lock": (
            '[[package]]\nname = "ciphermoth-desktop"\nversion = "1.0.0"\n'
        ),
        "desktop/src-tauri/tauri.conf.json": production,
        "desktop/core/desktop_core/entry.py": 'CORE_VERSION = "1.0.0"\n',
    }
    assert set(sources) == set(fixtures.FILES)
    for name, text in sources.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    private = tmp_path / "updater.key"
    private.write_text("synthetic disposable private key")
    Path(str(private) + ".pub").write_text("disposable\n")
    config = tmp_path / "desktop/src-tauri/tauri.conf.json"
    builds = []

    def run(command, **kwargs):
        if "build" in command and any(
            str(part).endswith("tauri.js") for part in command
        ):
            built = fixtures.json.loads(config.read_text())
            builds.append((built["version"], built["plugins"]["updater"]["pubkey"]))
        return fixtures.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(fixtures, "ROOT", tmp_path)
    monkeypatch.setattr(fixtures.subprocess, "run", run)
    monkeypatch.setattr(fixtures, "collect", lambda *args, **kwargs: None)
    monkeypatch.setattr(fixtures, "negative_signatures", lambda destination: None)
    monkeypatch.setenv("TAURI_SIGNING_PRIVATE_KEY", str(private))
    monkeypatch.setattr(
        fixtures.sys, "argv", ["fixtures", str(tmp_path / "out"), "3.0.99", "3.0.98"]
    )

    fixtures.main()

    assert builds == [("3.0.99", "disposable"), ("3.0.98", "disposable")]
    for name, text in sources.items():
        assert (tmp_path / name).read_text() == text
