"""Check Docker's actual ignore rules using only synthetic files and a scratch image."""

import io
import json
import secrets
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(
    command: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=check, capture_output=True)


def main() -> None:
    project = f"cm-context-{secrets.token_hex(6)}"
    public = {
        "backend/main.py",
        "frontend/package.json",
        "docker/frontend/runtime-config.mjs",
    }
    private = {
        ".env",
        "backend/.env.local",
        "backend/local-signing.key",
        "frontend/.env.production.local",
        "docs/architecture/private-audit.md",
        "CLAUDE.md",
    }
    with tempfile.TemporaryDirectory(prefix="cm-context-") as folder:
        context = Path(folder)
        (context / ".dockerignore").write_bytes((ROOT / ".dockerignore").read_bytes())
        for name in public | private:
            target = context / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic-build-context-canary\n", encoding="utf-8")
        (context / "Dockerfile").write_text(
            'FROM scratch\nCOPY . /context\nCMD ["/unused"]\n', encoding="utf-8"
        )
        compose = context / "compose.json"
        compose.write_text(
            json.dumps({"services": {"probe": {"build": {"context": str(context)}}}}),
            encoding="utf-8",
        )
        command = [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-p",
            project,
            "-f",
            str(compose),
        ]
        try:
            run([*command, "build", "probe"])
            # Creating the container exposes its filesystem without executing it.
            run([*command, "create", "--no-build", "probe"])
            container = (
                run([*command, "ps", "-a", "-q", "probe"]).stdout.decode().strip()
            )
            archive = run(["docker", "cp", f"{container}:/context", "-"]).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
                names = set(contents.getnames())
            assert {f"context/{name}" for name in public} <= names
            leaked = {name for name in private if f"context/{name}" in names}
            assert not leaked, f"private build-context paths included: {sorted(leaked)}"
            print("PASS Docker context excludes local secrets and private audit files")
        finally:
            run(
                [*command, "down", "-v", "--remove-orphans", "--rmi", "local"],
                check=False,
            )


if __name__ == "__main__":
    main()
