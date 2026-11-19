"""Release signing secrets have a deliberately short filesystem lifetime."""

import importlib.util
import stat
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
