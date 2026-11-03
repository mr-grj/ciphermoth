"""
End-to-end checks of the production images with the real docker-compose.prod.yml,
in throwaway Compose projects named <prefix>-*. Needs the backend and frontend
images tagged ghcr.io/mr-grj/ciphermoth-{backend,frontend}:<tag>.

    python3 docker/smoke/compose_smoke.py --tag smoke
    python3 docker/smoke/compose_smoke.py --tag smoke --legacy-compose old.yml

Only Python's standard library is used. Every project and volume it creates is
removed at the end. --installer creates and removes a volume named
ciphermoth_postgres_data, so it refuses to run outside GitHub Actions.
"""

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.prod.yml"
MASTER = "Smoke-Test-Vault-2026!"
ROTATED = "Smoke-Rotated-Vault-2027?"
ATTACHMENT = os.urandom(200_000)
ENFORCED_OWNERSHIP = platform.system() == "Linux"
CHECKS: list[str] = []


def ok(name: str, detail: str = "") -> None:
    CHECKS.append(name)
    print(f"PASS {name}" + (f": {detail}" if detail else ""), flush=True)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL {message}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if check and result.returncode != 0:
        fail(
            f"{' '.join(args)} -> {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result


class Stack:
    def __init__(self, project: str, compose: Path, env: dict[str, str]) -> None:
        self.project = project
        self.compose = compose
        self.backend_port = free_port()
        self.frontend_port = free_port()
        self.env = {
            **os.environ,
            "CIPHERMOTH_BACKEND_PORT": str(self.backend_port),
            "CIPHERMOTH_FRONTEND_PORT": str(self.frontend_port),
            "CIPHERMOTH_API_URL": f"http://localhost:{self.backend_port}/api",
            "CIPHERMOTH_FRONTEND_ORIGIN": f"http://localhost:{self.frontend_port}",
            **env,
        }
        self.api = f"http://127.0.0.1:{self.backend_port}/api"
        if not project.startswith("cm-") or project == "ciphermoth":
            fail(f"refusing to drive the Compose project {project!r}")
        config = json.loads(self.dc("config", "--format", "json").stdout)
        if config.get("name") != project:
            fail(f"docker compose resolved the project {config.get('name')!r}")

    def compose_args(self, *extra: str) -> list[str]:
        args = ["docker", "compose", "-p", self.project, "-f", str(self.compose)]
        for override in extra:
            args += ["-f", override]
        return args

    def dc(
        self,
        *args: str,
        check: bool = True,
        overrides: tuple[str, ...] = (),
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess:
        return run(
            *self.compose_args(*overrides),
            *args,
            check=check,
            env=self.env,
            input=stdin,
            cwd=self.compose.parent,
        )

    def request(
        self,
        method: str,
        path: str,
        body: object = None,
        token: str | None = None,
        raw: bytes | None = None,
        content_type: str | None = None,
        timeout: float = 30,
    ) -> tuple[int, bytes, dict]:
        data = (
            raw
            if raw is not None
            else (json.dumps(body).encode() if body is not None else None)
        )
        request = urllib.request.Request(f"{self.api}{path}", data=data, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if content_type:
            request.add_header("Content-Type", content_type)
        if token:
            request.add_header("x-ciphermoth-session", token)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read(), dict(error.headers)

    def json(
        self,
        method: str,
        path: str,
        body: object = None,
        token: str | None = None,
        expect: int = 200,
    ) -> Any:
        status, payload, _ = self.request(method, path, body, token)
        if status != expect:
            fail(f"{method} {path} -> {status} (expected {expect}): {payload[:200]!r}")
        return json.loads(payload) if payload else None

    def wait_healthy(self, timeout: float = 90) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status, payload, _ = self.request("GET", "/health", timeout=3)
                if status == 200:
                    return json.loads(payload)
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(1)
        logs = self.dc("logs", "--tail", "40", "backend", check=False).stdout
        fail(f"{self.project}: backend never became healthy\n{logs}")
        return {}

    def unlock(self, password: str = MASTER) -> str:
        body = self.json(
            "POST", "/master_password/unlock", {"master_password": password}
        )
        if not body["valid"]:
            fail(f"{self.project}: unlock with the expected password was refused")
        return body["session_token"]

    def backend_exited_with(self, message: str, timeout: float = 60) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            logs = self.dc("logs", "backend", check=False).stdout
            if message in logs:
                return logs
            time.sleep(1)
        fail(f"{self.project}: backend logs never said {message!r}\n{logs[-2000:]}")
        return ""

    def wait_backend_exit(self, expected: int, timeout: float = 30) -> str:
        """Wait for the refusal process to exit before reading its exit code."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            container = self.dc("ps", "-a", "-q", "backend").stdout.strip()
            if container:
                state = json.loads(run("docker", "inspect", container).stdout)[0][
                    "State"
                ]
                if state["Status"] == "exited":
                    if state["ExitCode"] != expected:
                        fail(
                            f"the new backend exited with {state['ExitCode']}, "
                            f"not {expected}"
                        )
                    return container
            time.sleep(0.2)
        fail(f"{self.project}: backend did not exit with {expected}")
        return ""

    def admin(
        self, *args: str, running: bool = True, check: bool = True
    ) -> subprocess.CompletedProcess:
        if running:
            return self.dc(
                "exec", "-T", "backend", "ciphermoth-admin", *args, check=check
            )
        return self.dc(
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "backend",
            "ciphermoth-admin",
            *args,
            check=check,
        )

    def python(self, code: str) -> str:
        return self.dc(
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            "python",
            "backend",
            "-c",
            code,
        ).stdout.strip()

    def vault_sha256(self) -> str:
        return self.python(
            "import hashlib, pathlib;"
            "print(':'.join(hashlib.sha256(p.read_bytes()).hexdigest()"
            " for p in sorted(pathlib.Path('/data').glob('vault.db*'))"
            " if not p.name.endswith('-shm') and p.stat().st_size))"
        )

    def down(self) -> None:
        self.dc("down", "-v", "--remove-orphans", check=False)


def seed(stack: Stack) -> str:
    body = stack.json("POST", "/master_password/create", {"master_password": MASTER})
    token = body["session_token"]
    for item in (
        {
            "password_name": "github",
            "password_value": "gh-Value-1",
            "url": "https://github.com",
        },
        {"password_name": "wifi", "password_value": "note body\n", "kind": "note"},
        {"password_name": "trashed", "password_value": "old-1"},
    ):
        stack.json("POST", "/passwords/create", item, token)
    stack.json("DELETE", "/passwords/trashed", token=token)
    stack.json(
        "POST",
        "/passwords/create",
        {"password_name": "trashed", "password_value": "reused-1"},
        token,
    )
    stack.json(
        "PATCH",
        "/passwords/update",
        {
            "password": {"password_name": "github", "password_value": "gh-Value-1"},
            "new_password": {
                "password_name": "github",
                "password_value": "gh-Value-2",
                "url": "https://github.com",
            },
        },
        token,
    )
    boundary = "smokeboundary"
    form = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="codes.bin"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + ATTACHMENT
        + f"\r\n--{boundary}--\r\n".encode()
    )
    status, payload, _ = stack.request(
        "POST",
        "/passwords/github/attachments",
        raw=form,
        token=token,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    if status != 200:
        fail(f"attachment upload -> {status} {payload[:200]!r}")
    stack.json(
        "PATCH",
        "/settings",
        {
            "inactivity_ms": 300_000,
            "warn_before_ms": 30_000,
            "hidden_ms": 90_000,
            "debounce_ms": 500,
            "clipboard_clear_ms": 15_000,
            "update_check_enabled": False,
        },
        token,
    )
    return token


def state(stack: Stack, token: str) -> dict:
    entries = stack.json("GET", "/passwords", token=token)
    github = stack.json("GET", "/passwords/github", token=token)
    attachments = stack.json("GET", "/passwords/github/attachments", token=token)
    status, content, _ = stack.request(
        "GET", f"/passwords/github/attachments/{attachments[0]['id']}", token=token
    )
    return {
        "names": sorted(e["password_name"] for e in entries),
        "trash": [
            e["password_name"]
            for e in stack.json("GET", "/passwords/trash", token=token)
        ],
        "value": github["password_value"],
        "history": [h["value"] for h in github["password_history"]],
        "attachment": status == 200 and content == ATTACHMENT,
        "settings": stack.json("GET", "/settings", token=token)["hidden_ms"],
    }


EXPECTED = {
    "names": ["github", "trashed", "wifi"],
    "trash": ["trashed"],
    "value": "gh-Value-2",
    "history": ["gh-Value-1"],
    "attachment": True,
    "settings": 90_000,
}


def fresh_install(
    tag: str, prefix: str, workdir: Path, expect_version: str | None
) -> None:
    folder = workdir / "fresh"
    folder.mkdir()
    shutil.copy(COMPOSE, folder / "docker-compose.prod.yml")
    stack = Stack(
        f"{prefix}-fresh",
        folder / "docker-compose.prod.yml",
        {"CIPHERMOTH_VERSION": tag},
    )
    try:
        if (folder / ".env").exists():
            fail("the fresh install folder has a .env")
        stack.dc("up", "-d")
        health = stack.wait_healthy()
        if health.get("schema") != "current":
            fail(f"health: {health}")
        ok("fresh install without .env", f"health {health}")

        services = stack.dc("ps", "--services").stdout.split()
        volumes = run(
            "docker",
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={stack.project}",
        ).stdout.split()
        if sorted(services) != ["backend", "frontend"] or volumes != [
            f"{stack.project}_vault_data"
        ]:
            fail(f"services {services}, volumes {volumes}")
        ok("two containers and one volume", f"{services} {volumes}")

        runtime = stack.dc(
            "exec",
            "-T",
            "backend",
            "python",
            "-c",
            "import platform, sqlite3, sys, storage; storage.require_supported_sqlite();"
            "print(platform.machine(), sys.version.split()[0], sqlite3.sqlite_version)",
        ).stdout.strip()
        ok("SQLite inside the running backend", runtime)

        owner = stack.dc(
            "exec",
            "-T",
            "backend",
            "sh",
            "-c",
            "id -u; stat -c '%u %a' /data /data/vault.db",
        ).stdout.split("\n")
        if owner[0] != "1000" or owner[1] != "1000 700" or owner[2] != "1000 600":
            fail(f"ownership {owner}")
        ok("non-root backend owns /data (0700) and vault.db (0600)", " | ".join(owner))

        page = urllib.request.urlopen(
            f"http://127.0.0.1:{stack.frontend_port}/", timeout=10
        )
        csp = page.headers.get("Content-Security-Policy", "")
        if f"http://localhost:{stack.backend_port}" not in csp:
            fail(f"frontend CSP {csp}")
        ok("frontend serves with the API in its CSP")

        token = seed(stack)
        tokens = [token]
        if state(stack, token) != EXPECTED:
            fail(f"state after seeding {state(stack, token)}")
        ok(
            "vault lifecycle: logins, notes, trash and name reuse, history, attachments, settings"
        )

        listing = stack.dc(
            "exec",
            "-T",
            "backend",
            "ciphermoth",
            "password",
            "list",
            stdin=MASTER + "\n",
        ).stdout
        if "github" not in listing or "wifi" not in listing:
            fail(f"CLI listing {listing}")
        ok("bundled ciphermoth CLI lists the vault")

        def cli(*args: str, answers: tuple[str, ...] = ()) -> str:
            return stack.dc(
                "exec",
                "-T",
                "backend",
                "ciphermoth",
                *args,
                stdin="\n".join((MASTER, *answers)) + "\n",
            ).stdout

        if "gh-Value-2" not in cli("password", "get", "github"):
            fail("ciphermoth password get")
        if "trashed" not in cli("password", "trash"):
            fail("ciphermoth password trash")
        cli(
            "password",
            "create",
            "cli-entry",
            answers=("cli-Value-1", "cli-Value-1", "", "", "", "", ""),
        )
        if "cli-Value-1" not in cli("password", "get", "cli-entry"):
            fail("ciphermoth password create")
        cli("password", "delete", "cli-entry", "--yes")
        cli("password", "purge", "cli-entry", "--yes")
        cli("backup", "--out", "/tmp")
        backups = stack.dc(
            "exec", "-T", "backend", "sh", "-c", "ls /tmp/ciphermoth_backup_*.cmbackup"
        ).stdout.split()
        if len(backups) != 1:
            fail(f"ciphermoth backup wrote {backups}")
        restored = cli("import", backups[0], answers=("",))
        if "0 added" not in restored or "4 skipped" not in restored:
            fail(f"ciphermoth import of its own backup: {restored}")
        for command in (("ciphermoth", "--help"), ("ciphermoth-admin", "--help")):
            stack.dc("exec", "-T", "backend", *command)
        ok(
            "CLI get, trash, create, delete, purge, complete backup and restore, admin help"
        )

        short = stack.unlock()
        stack.json(
            "PATCH",
            "/settings",
            {
                "inactivity_ms": 30_000,
                "warn_before_ms": 10_000,
                "hidden_ms": 90_000,
                "debounce_ms": 500,
                "clipboard_clear_ms": 15_000,
                "update_check_enabled": False,
            },
            short,
        )
        expiring = stack.unlock()
        if stack.request("GET", "/passwords", token=expiring)[0] != 200:
            fail("a fresh session was refused")
        time.sleep(37)
        status, payload, _ = stack.request("GET", "/passwords", token=expiring)
        if status != 401 or json.loads(payload).get("code") != "invalid_session":
            fail(f"an idle session outlived the 30 s timeout: {status} {payload!r}")
        stack.json(
            "PATCH",
            "/settings",
            {
                "inactivity_ms": 300_000,
                "warn_before_ms": 30_000,
                "hidden_ms": 90_000,
                "debounce_ms": 500,
                "clipboard_clear_ms": 15_000,
                "update_check_enabled": False,
            },
            stack.unlock(),
        )
        token = stack.unlock()
        ok("an idle session expires after the configured inactivity timeout")

        for method, path in (
            ("GET", "/updates/apply/status"),
            ("POST", "/updates/apply"),
        ):
            status = stack.request(
                method, path, body={"target": "v9.9.9"}, token=token
            )[0]
            if status not in (404, 405):
                fail(f"{method} /api{path} answered {status}")
        page = (
            urllib.request.urlopen(
                f"http://127.0.0.1:{stack.frontend_port}/", timeout=10
            )
            .read()
            .decode()
        )
        bundle = ""
        for src in re.findall(r'src="(/assets/[^"]+\.js)"', page):
            bundle += (
                urllib.request.urlopen(
                    f"http://127.0.0.1:{stack.frontend_port}{src}", timeout=10
                )
                .read()
                .decode()
            )
        if "updates/apply" in bundle or "ciphermoth-admin snapshot" not in bundle:
            fail("the web UI still offers one-click updates or lacks the manual steps")
        ok(
            "no one-click update anywhere: API routes gone, UI shows the manual snapshot, pull and up"
        )

        out = stack.admin("snapshot").stdout
        snapshot = out.strip().split("Snapshot written: ")[-1]
        stack.admin("check")
        stack.admin("check", snapshot)
        ok("ciphermoth-admin snapshot and check", snapshot)

        stack.dc("restart", "backend")
        stack.wait_healthy()
        if stack.request("GET", "/passwords", token=token)[0] != 401:
            fail("a session survived a restart")
        token = stack.unlock()
        if state(stack, token) != EXPECTED:
            fail("data changed across a restart")
        stack.dc("up", "-d", "--force-recreate", "backend")
        stack.wait_healthy()
        token = stack.unlock()
        if state(stack, token) != EXPECTED:
            fail("data changed across a container recreation")
        ok("restart and recreation keep the vault and end sessions")

        stack.json(
            "POST",
            "/passwords/create",
            {"password_name": "last-write", "password_value": "v"},
            token,
        )
        stack.dc("kill", "-s", "SIGKILL", "backend")
        stack.dc("up", "-d", "backend")
        stack.wait_healthy()
        token = stack.unlock()
        names = state(stack, token)["names"]
        if "last-write" not in names:
            fail(f"an acknowledged write was lost after SIGKILL: {names}")
        stack.json("DELETE", "/passwords/last-write", token=token)
        stack.json("DELETE", "/passwords/last-write/purge", token=token)
        ok("an acknowledged write survives SIGKILL")

        other = stack.unlock()
        stack.json(
            "PATCH",
            "/master_password/update",
            {"master_password": MASTER, "new_master_password": ROTATED},
            token,
        )
        for old in (token, other):
            if stack.request("GET", "/passwords", token=old)[0] != 401:
                fail("a session opened before the rotation still works")
        if stack.json("POST", "/master_password/unlock", {"master_password": MASTER})[
            "valid"
        ]:
            fail("the old master password still unlocks after the rotation")
        rotated = stack.unlock(ROTATED)
        if state(stack, rotated) != EXPECTED:
            fail("data changed across the rotation")
        ok("rotation re-encrypts the vault and ends every session")

        refused = stack.admin("restore", snapshot, "--yes", running=False, check=False)
        if (
            refused.returncode == 0
            or "Another CipherMoth process" not in refused.stdout + refused.stderr
        ):
            fail(
                f"restore while running: {refused.returncode} {refused.stdout} {refused.stderr}"
            )
        ok("restore refuses while the backend runs")

        stack.json(
            "POST",
            "/passwords/create",
            {"password_name": "in-wal", "password_value": "v"},
            rotated,
        )
        rows_at_kill = len(stack.json("GET", "/passwords", token=rotated)) + len(
            stack.json("GET", "/passwords/trash", token=rotated)
        )
        stack.dc("kill", "-s", "SIGKILL", "backend")
        container = stack.dc("ps", "-a", "-q", "backend").stdout.strip()
        time.sleep(2)
        state_after_kill = json.loads(run("docker", "inspect", container).stdout)[0][
            "State"
        ]
        if state_after_kill["Running"]:
            fail("Docker restarted the killed backend; the WAL check needs it down")
        wal = stack.python("import os; print(os.path.getsize('/data/vault.db-wal'))")
        if int(wal) == 0:
            fail("the killed backend left no committed data in the WAL")
        tokens.extend([token, other, rotated])
        restored = stack.admin("restore", snapshot, "--yes", running=False).stdout
        kept = restored.split("kept as ")[-1].split()[0]
        found = stack.python(
            "import shutil, sqlite3, tempfile, pathlib\n"
            f"kept = pathlib.Path('{kept}')\n"
            "scratch = pathlib.Path(tempfile.mkdtemp())\n"
            "for f in kept.iterdir(): shutil.copy(f, scratch / f.name)\n"
            "c = sqlite3.connect(scratch / 'vault.db')\n"
            "print(c.execute('SELECT count(*) FROM entries').fetchone()[0])"
        )
        if int(found) != rows_at_kill:
            fail(f"the kept vault lost the commit that was only in the WAL: {found}")
        stack.dc("start", "backend")
        stack.wait_healthy()
        if stack.json("POST", "/master_password/unlock", {"master_password": ROTATED})[
            "valid"
        ]:
            fail("the rotated password still unlocks after the restore")
        token = stack.unlock(MASTER)
        if state(stack, token) != EXPECTED:
            fail(f"state after restore {state(stack, token)}")
        ok("offline restore brings back the snapshot", restored.strip().splitlines()[0])
        ok("the replaced vault is kept with the commit that was only in its WAL", kept)

        stack.dc("stop", "backend")
        stack.python(
            "import sqlite3; c = sqlite3.connect('/data/vault.db');"
            "c.execute('PRAGMA user_version=99'); c.commit()"
        )
        before = stack.vault_sha256()
        stack.dc("start", "backend")
        stack.backend_exited_with("newer CipherMoth")
        stack.dc("stop", "backend")
        if stack.vault_sha256() != before:
            fail("a vault of a newer schema was changed")
        stack.admin("restore", snapshot, "--yes", running=False)
        stack.dc("start", "backend")
        stack.wait_healthy()
        if state(stack, stack.unlock()) != EXPECTED:
            fail("snapshot recovery after a schema refusal")
        ok("a newer schema is refused untouched and the snapshot recovers the vault")

        stack.dc("stop", "backend")
        stack.python(
            "import sqlite3; from contextlib import closing\n"
            "with closing(sqlite3.connect('file:/data/vault.db?mode=ro', uri=True)) as c:\n"
            "    size = c.execute('PRAGMA page_size').fetchone()[0]\n"
            "    root = c.execute(\"SELECT rootpage FROM sqlite_schema WHERE name = 'uq_entries_name_active'\").fetchone()[0]\n"
            "data = bytearray(open('/data/vault.db', 'rb').read())\n"
            "data[(root - 1) * size:(root - 1) * size + 8] = b'\\xff' * 8\n"
            "open('/data/vault.db', 'wb').write(bytes(data))\n"
        )
        before = stack.vault_sha256()
        stack.dc("start", "backend")
        stack.backend_exited_with("integrity check")
        stack.dc("stop", "backend")
        if stack.vault_sha256() != before:
            fail("a damaged vault was changed by the startup check")
        stack.admin("restore", snapshot, "--yes", running=False)
        stack.dc("start", "backend")
        stack.wait_healthy()
        if state(stack, stack.unlock()) != EXPECTED:
            fail("snapshot recovery of a damaged vault")
        ok("a damaged vault is refused untouched and the snapshot recovers it")

        stack.dc("stop", "backend")
        stack.python(
            "import sqlite3; c = sqlite3.connect('/data/vault.db');"
            "c.execute('PRAGMA user_version=1'); c.commit()"
        )
        before = stack.vault_sha256()
        stack.dc("start", "backend")
        stack.backend_exited_with("CipherMoth 2.0 or earlier")
        stack.dc("stop", "backend")
        if stack.vault_sha256() != before:
            fail("a vault of format 1 was changed")
        moved = stack.admin("set-aside", "--yes", running=False).stdout
        kept_vault = moved.split("moved to ")[-1].split()[0]
        kept_sha = stack.python(
            "import hashlib, pathlib;"
            "print(':'.join(hashlib.sha256(p.read_bytes()).hexdigest()"
            f" for p in sorted(pathlib.Path('{kept_vault}').glob('vault.db*'))"
            " if not p.name.endswith('-shm') and p.stat().st_size))"
        )
        if kept_sha != before:
            fail("set-aside changed the vault it moved")
        stack.dc("start", "backend")
        stack.wait_healthy()
        if stack.json("GET", "/master_password/status")["initialized"]:
            fail("a new vault was not empty after set-aside")
        ok("a format 1 vault is refused untouched and set-aside moves it byte for byte")

        logs = stack.dc("logs", "--no-color").stdout
        backend_logs = stack.dc("logs", "--no-color", "backend").stdout
        secrets = [MASTER, ROTATED, "gh-Value-1", "gh-Value-2", "cli-Value-1", *tokens]
        names = ["github", "wifi", "cli-entry", "in-wal"]
        leaked = [secret for secret in secrets if secret and secret in logs]
        leaked += [name for name in names if name in backend_logs]
        if leaked or "GET /api/passwords/{password_name}" not in logs:
            lines = [
                line.replace(secret, "***")
                for line in logs.splitlines()
                for secret in leaked
                if secret in line
            ]
            fail("secrets or entry names in the logs:\n" + "\n".join(lines[:20]))
        ok("no master password, value, entry name or session token in the logs")

        if expect_version:
            reported = {
                "backend /api/meta": stack.json("GET", "/meta")["version"],
                "backend /api/health": stack.json("GET", "/health")["version"],
                "frontend /version.json": json.loads(
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{stack.frontend_port}/version.json",
                        timeout=10,
                    ).read()
                )["version"],
            }
            if set(reported.values()) != {expect_version}:
                fail(f"reported versions {reported}")
            for image in ("backend", "frontend"):
                info = json.loads(
                    run(
                        "docker",
                        "image",
                        "inspect",
                        f"ghcr.io/mr-grj/ciphermoth-{image}:{tag}",
                    ).stdout
                )[0]
                labels = info["Config"]["Labels"] or {}
                if labels.get("io.ciphermoth.min-updater-protocol") != "3":
                    fail(f"{image} labels {labels}")
                ok(
                    f"published {image} image",
                    f"{info['Architecture']} {info['RepoDigests']}",
                )
            ok("the published images report the expected version", str(reported))
    finally:
        stack.down()


def bind_mounted(tag: str, prefix: str, workdir: Path) -> None:
    folder = workdir / "bind"
    folder.mkdir()
    shutil.copy(COMPOSE, folder / "docker-compose.prod.yml")
    host = workdir / "vault-folder"
    host.mkdir()
    override = folder / "override.yml"
    override.write_text(
        "services:\n  backend:\n    environment:\n      CIPHERMOTH_DATA_DIR: /srv/vault\n"
        f"    volumes:\n      - {host}:/srv/vault\n"
    )
    image = f"ghcr.io/mr-grj/ciphermoth-backend:{tag}"
    stack = Stack(
        f"{prefix}-bind",
        folder / "docker-compose.prod.yml",
        {"CIPHERMOTH_VERSION": tag},
    )
    try:
        run(
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{host}:/x",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "chown 0:0 /x && chmod 755 /x",
        )
        stack.dc("up", "-d", overrides=(str(override),))
        if ENFORCED_OWNERSHIP:
            logs = stack.backend_exited_with("cannot write its vault")
            if "chown" not in logs:
                fail("the ownership error does not say how to fix it")
            ok(
                "a data folder the app user cannot write is refused with the fix",
                "chown hint present",
            )
        else:
            stack.wait_healthy()
            ok(
                "root-owned bind mount on Docker Desktop",
                "not enforced by Docker Desktop file sharing, the backend can write; "
                "Linux hosts refuse (checked in CI)",
            )
            stack.dc("down", "-v")
        run(
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{host}:/x",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "chown 1000:1000 /x",
        )
        stack.dc("up", "-d", "--force-recreate", "backend", overrides=(str(override),))
        stack.wait_healthy()
        stack.json("POST", "/master_password/create", {"master_password": MASTER})
        listing = run(
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{host}:/x",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "stat -c '%n %u %a' /x/vault.db",
        ).stdout.strip()
        if ENFORCED_OWNERSHIP and not listing.endswith("1000 600"):
            fail(f"vault in the bind-mounted folder: {listing}")
        ok("an explicit data folder (CIPHERMOTH_DATA_DIR + bind mount) works", listing)
    finally:
        stack.down()
        run(
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{host}:/x",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "rm -rf /x/* /x/.[!.]*",
            check=False,
        )


def legacy(tag: str, prefix: str, workdir: Path, old_compose: Path) -> None:
    folder = workdir / "legacy"
    folder.mkdir()
    compose = folder / "docker-compose.prod.yml"
    shutil.copy(old_compose, compose)
    refusal_override = folder / "refusal.yml"
    refusal_override.write_text(
        'services:\n  backend:\n    restart: "no"\n', encoding="utf-8"
    )
    env = {"POSTGRES_PASSWORD": "smoke-legacy-password", "CIPHERMOTH_VERSION": "1.6.0"}
    stack = Stack(f"{prefix}-legacy", compose, env)
    try:
        stack.dc("up", "-d")
        stack.wait_healthy(timeout=180)
        token = stack.json(
            "POST", "/master_password/create", {"master_password": MASTER}
        )["session_token"]
        stack.json(
            "POST",
            "/passwords/create",
            {"password_name": "legacy-entry", "password_value": "v"},
            token,
        )
        ok("a v1.6.0 PostgreSQL install runs from its own compose file")

        stack.env["CIPHERMOTH_VERSION"] = tag
        stack.dc("up", "-d", overrides=(str(refusal_override),))
        stack.backend_exited_with("no longer uses PostgreSQL")
        container = stack.wait_backend_exit(78)
        inspect = json.loads(run("docker", "inspect", container).stdout)[0]
        code = inspect["State"]["ExitCode"]
        mounts = [m for m in inspect["Mounts"] if m["Destination"] == "/data"]
        if mounts:
            listing = run(
                "docker",
                "run",
                "--rm",
                "-v",
                f"{mounts[0]['Name']}:/d",
                "--entrypoint",
                "ls",
                f"ghcr.io/mr-grj/ciphermoth-backend:{tag}",
                "-A",
                "/d",
            ).stdout.split()
            if any(name.startswith("vault.db") for name in listing):
                fail(
                    f"the new image created a vault next to the PostgreSQL install: {listing}"
                )
        try:
            status = stack.request("GET", "/health", timeout=3)[0]
        except (urllib.error.URLError, OSError):
            status = None
        if status == 200:
            fail("the new backend served requests from the old compose file")
        rows = stack.dc(
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "ciphermoth",
            "-d",
            "ciphermoth",
            "-tAc",
            "SELECT count(*) FROM passwords",
        ).stdout.strip()
        if rows != "1":
            fail(f"the PostgreSQL vault changed: {rows} rows")
        ok(
            "the new image refuses the old compose file, creates no vault, leaves PostgreSQL intact",
            f"exit code {code}",
        )

        stack.env["CIPHERMOTH_VERSION"] = "1.6.0"
        stack.dc("up", "-d")
        stack.wait_healthy(timeout=180)
        token = stack.unlock()
        names = [
            e["password_name"] for e in stack.json("GET", "/passwords", token=token)
        ]
        if names != ["legacy-entry"]:
            fail(f"pinned back to v1.6.0: {names}")
        ok("pinning the old release back brings the PostgreSQL vault back unchanged")
    finally:
        stack.down()


def installer(workdir: Path) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        fail("--installer creates a volume named ciphermoth_postgres_data; CI only")
    volume = "ciphermoth_postgres_data"
    if run("docker", "volume", "inspect", volume, check=False).returncode == 0:
        fail(f"{volume} already exists here; refusing to touch it")
    run("docker", "volume", "create", volume)
    try:
        target = workdir / "installed"
        result = run(
            "sh",
            str(ROOT / "install.sh"),
            check=False,
            env={**os.environ, "CIPHERMOTH_DIR": str(target)},
            stdin=subprocess.DEVNULL,
        )
        output = result.stdout + result.stderr
        if result.returncode == 0 or "Nothing was changed" not in output:
            fail(
                f"install.sh with an old PostgreSQL volume: {result.returncode}\n{output}"
            )
        if target.exists():
            fail("install.sh created its folder before refusing")
        if run("docker", "volume", "inspect", volume, check=False).returncode != 0:
            fail("install.sh removed the old volume")
        ok("install.sh stops before touching an existing PostgreSQL install")
    finally:
        run("docker", "volume", "rm", volume, check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--prefix", default="cm-smoke")
    parser.add_argument("--legacy-compose", type=Path)
    parser.add_argument("--installer", action="store_true")
    parser.add_argument("--skip-bind", action="store_true")
    parser.add_argument("--expect-version")
    args = parser.parse_args()
    if not args.prefix.startswith("cm-"):
        fail("the project prefix must start with 'cm-'")
    workdir = Path(tempfile.mkdtemp(prefix="ciphermoth-smoke-"))
    try:
        fresh_install(args.tag, args.prefix, workdir, args.expect_version)
        if not args.skip_bind:
            bind_mounted(args.tag, args.prefix, workdir)
        if args.legacy_compose:
            legacy(args.tag, args.prefix, workdir, args.legacy_compose)
        if args.installer:
            installer(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print(f"ALL {len(CHECKS)} CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
