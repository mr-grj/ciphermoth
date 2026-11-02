import asyncio
import base64
import io
import json
import os
import secrets
import socket
import sqlite3
import struct
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import insert, text

from crud.engine import Database
from device_unlock import DEVICE_UNLOCK_FILE
from helpers import VaultKey
from main import app, get_application
from models import SETTINGS_DEFAULTS, SettingsModel
from storage import VAULT_FILE
from vault_sessions import Instant, VaultSessions, system_clock

BACKEND_DIR = Path(__file__).resolve().parent.parent

MASTER_PASSWORD = "Moth-Test-Vault-2026!"
NEW_MASTER_PASSWORD = "Moth-Rotated-Vault-2027?"
WRONG_MASTER_PASSWORD = "Not-The-Vault-Password-1"

TABLES = ("vault", "entries", "attachments", "settings")

engine = app.state.database.engine


def data_dir() -> Path:
    return Path(os.environ["CIPHERMOTH_DATA_DIR"])


async def reset_vault() -> None:
    """Return the shared test vault to the state of a fresh install."""
    async with engine.begin() as conn:
        for table in ("attachments", "entries", "vault"):
            await conn.execute(text(f"DELETE FROM {table}"))
        await conn.execute(text("DELETE FROM settings"))
        await conn.execute(text("DELETE FROM sqlite_sequence"))
        await conn.execute(insert(SettingsModel).values(**SETTINGS_DEFAULTS))
    (data_dir() / DEVICE_UNLOCK_FILE).unlink(missing_ok=True)


def fresh_vault_sessions(clock: Callable[[], Instant] = system_clock) -> VaultSessions:
    return VaultSessions(
        idle_timeout_ms=SETTINGS_DEFAULTS["inactivity_ms"],
        clock=clock,
    )


Headers = list[tuple[bytes, bytes]]


def auth(token: str | bytes | None) -> Headers:
    """Headers for a vault session token, the credential current clients use."""
    if token is None:
        return []
    value = token if isinstance(token, bytes) else token.encode("latin-1")
    return [(b"x-ciphermoth-session", value)]


def retired_key_header(key: str | bytes | None) -> Headers:
    """The vault key header v1.4.x clients sent, which v1.6.0 refuses."""
    if key is None:
        return []
    value = key if isinstance(key, bytes) else key.encode("latin-1")
    return [(b"x-ciphermoth-key-derivation", value)]


async def create_vault(
    client: httpx.AsyncClient, master_password: str = MASTER_PASSWORD
) -> str:
    resp = await client.post(
        "/master_password/create", json={"master_password": master_password}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "key_derivation" not in body
    return body["session_token"]


async def unlock(
    client: httpx.AsyncClient, master_password: str = MASTER_PASSWORD
) -> str:
    resp = await client.post(
        "/master_password/unlock", json={"master_password": master_password}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is True
    assert "key_derivation" not in body
    return body["session_token"]


def _hkdf(key: bytes, label: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()
    ).derive(key)


def unwrap_vault_key(row: tuple, master_password: str) -> bytes:
    """The raw vault key of a ``vault`` row, unwrapped with the primitives
    following docs/VAULT_FORMAT.md rather than through helpers.py."""
    memory, iterations, lanes, salt, wrapped = row
    derived = Argon2id(
        salt=bytes(salt),
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory,
    ).derive(master_password.encode())
    wrapped = bytes(wrapped)
    associated = (
        b"ciphermoth/v2/wrapped-vault-key"
        + struct.pack(">HIII", 2, memory, iterations, lanes)
        + bytes(salt)
    )
    return AESGCM(_hkdf(derived, "ciphermoth/v2/key-wrapping")).decrypt(
        wrapped[1:13], wrapped[13:], associated
    )


async def raw_vault_key(master_password: str = MASTER_PASSWORD) -> bytes:
    [row] = await db_execute(
        "SELECT kdf_memory_kib, kdf_iterations, kdf_lanes, kdf_salt, wrapped_key "
        "FROM vault"
    )
    return unwrap_vault_key(row, master_password)


async def stored_vault_key(master_password: str = MASTER_PASSWORD) -> str:
    """The raw vault key as text (base64url), for checking that it never shows
    up in responses or logs and for forged credentials."""
    raw = await raw_vault_key(master_password)
    return base64.urlsafe_b64encode(raw).decode()


async def vault_key(master_password: str = MASTER_PASSWORD) -> VaultKey:
    return VaultKey(await raw_vault_key(master_password))


def entry(name: str, value: str = "s3cret-Value!", **fields: object) -> dict:
    return {"password_name": name, "password_value": value, **fields}


def forged_keys(real_key: str) -> dict[str, str | bytes | None]:
    raw = base64.urlsafe_b64decode(real_key)
    return {
        "missing": None,
        "empty": "",
        "malformed": "not-a-fernet-key",
        "truncated": real_key[:-4],
        "random-valid-format": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "right-signing-half": base64.urlsafe_b64encode(
            raw[:16] + os.urandom(16)
        ).decode(),
        "right-encryption-half": base64.urlsafe_b64encode(
            os.urandom(16) + raw[16:]
        ).decode(),
        "non-ascii": "ключ-вольта".encode(),
    }


async def forged_tokens(
    client: httpx.AsyncClient, real_token: str, vault_key: str
) -> dict[str, Headers]:
    """Session credentials that must never open the vault whose live session is
    ``real_token``."""
    locked = await unlock(client)
    resp = await client.post("/master_password/lock", headers=auth(locked))
    assert resp.status_code == 200, resp.text
    return {
        "missing": [],
        "empty": [(b"x-ciphermoth-session", b"")],
        "bearer prefixed": auth("Bearer " + real_token),
        "malformed": auth("not a session token"),
        "random": auth(secrets.token_urlsafe(32)),
        "truncated": auth(real_token[:-1]),
        "extended": auth(real_token + "A"),
        "case flipped": auth(real_token.swapcase()),
        "padded": auth(real_token + "="),
        "non-ascii": auth("сессия-токен".encode()),
        "in Authorization": [(b"authorization", b"Bearer " + real_token.encode())],
        "vault key as token": auth(vault_key),
        "token as vault key": retired_key_header(real_token),
        "locked": auth(locked),
    }


def bump_patch(version: str, delta: int = 1) -> str:
    major, minor, patch = (int(part) for part in version.lstrip("v").split("."))
    return f"v{major}.{minor}.{patch + delta}"


def previous_version(version: str) -> str:
    major, minor, patch = (int(part) for part in version.lstrip("v").split("."))
    if patch:
        return f"v{major}.{minor}.{patch - 1}"
    if minor:
        return f"v{major}.{minor - 1}.99"
    return f"v{major - 1}.99.99"


async def db_snapshot() -> dict[str, list[tuple]]:
    snapshot: dict[str, list[tuple]] = {}
    async with engine.connect() as conn:
        for table in TABLES:
            rows = await conn.execute(text(f"SELECT * FROM {table} ORDER BY id"))
            snapshot[table] = [tuple(row) for row in rows.all()]
    return snapshot


async def db_execute(sql: str, **params: object) -> list[tuple]:
    async with engine.begin() as conn:
        result = await conn.execute(text(sql), params)
        return [tuple(row) for row in result.all()] if result.returns_rows else []


@contextmanager
def write_lock_held(folder: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Hold the vault's write lock from another connection, like a second
    process in the middle of a write, until the block ends."""
    blocker = sqlite3.connect(
        (folder or data_dir()) / VAULT_FILE, isolation_level=None, timeout=30
    )
    try:
        blocker.execute("BEGIN IMMEDIATE")
        yield blocker
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
    finally:
        blocker.close()


async def wait_for_queued_requests(count: int, timeout: float = 30) -> None:
    """Wait until ``count`` requests of the test app have checked out a database
    connection, which while ``write_lock_held`` means they wait for the lock."""
    pool = engine.sync_engine.pool
    deadline = time.monotonic() + timeout
    while pool.checkedout() < count:
        assert time.monotonic() < deadline, (
            f"only {pool.checkedout()} of {count} requests reached the database"
        )
        await asyncio.sleep(0.02)


@asynccontextmanager
async def client_for_data_dir(
    folder: Path | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    """An API client of a separate app instance, with its own vault sessions and
    connections, on the vault in ``folder`` (by default the shared test vault),
    like a second CipherMoth process."""
    other = Database(folder or data_dir())
    try:
        await other.prepare()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=get_application(database=other)),
            base_url="http://testserver/api",
            timeout=60,
        ) as http:
            yield http
    finally:
        await other.dispose()


@dataclass
class ApiServer:
    process: subprocess.Popen
    base_url: str


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def api_server(
    log_path: Path,
    folder: Path | None = None,
    *,
    pause_marker: Path | None = None,
) -> Iterator[ApiServer]:
    """A real uvicorn process serving the vault in ``folder``, by default the
    shared test vault. Only one server can hold a vault folder at a time. With
    ``pause_marker`` its write transactions stop right before committing
    (``tests/paused_server.py``)."""
    port = _free_port()
    env = dict(os.environ)
    if folder is not None:
        env["CIPHERMOTH_DATA_DIR"] = str(folder)
    target = ["main:app"]
    if pause_marker is not None:
        env["CIPHERMOTH_TEST_PAUSE_MARKER"] = str(pause_marker)
        target = ["--app-dir", "tests", "--factory", "paused_server:create_app"]
    with log_path.open("ab") as log_file:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", *target, "--port", str(port)],
            cwd=BACKEND_DIR,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        base_url = f"http://127.0.0.1:{port}/api"
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    if httpx.get(f"{base_url}/meta", timeout=1).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if process.poll() is not None or time.monotonic() > deadline:
                    output = log_path.read_text(errors="replace")
                    raise RuntimeError(f"Test API server did not start:\n{output}")
                time.sleep(0.2)
            yield ApiServer(process, base_url)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


def crash_after_committing(folder: Path, sql: str) -> None:
    """Commit ``sql`` from another process and kill it before it can checkpoint,
    so the committed change exists only in the WAL."""
    script = (
        "import os, sqlite3, sys\n"
        "connection = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
        "connection.execute('PRAGMA wal_autocheckpoint=0')\n"
        "connection.execute(sys.argv[2])\n"
        "os._exit(0)\n"
    )
    subprocess.run(
        [sys.executable, "-c", script, str(folder / VAULT_FILE), sql], check=True
    )
    assert (folder / f"{VAULT_FILE}-wal").stat().st_size > 0


def corrupt_name_index(vault: Path) -> None:
    with closing(sqlite3.connect(f"{vault.resolve().as_uri()}?mode=ro", uri=True)) as c:
        page_size = c.execute("PRAGMA page_size").fetchone()[0]
        root = c.execute(
            "SELECT rootpage FROM sqlite_schema WHERE name = 'uq_entries_name_active'"
        ).fetchone()[0]
    data = bytearray(vault.read_bytes())
    offset = (root - 1) * page_size
    data[offset : offset + 8] = b"\xff" * 8
    vault.write_bytes(bytes(data))


async def plant_entry(
    name: str,
    value: str = "planted-Value-1",
    *,
    master_password: str = MASTER_PASSWORD,
    deleted: str | None = None,
    **fields: object,
) -> int:
    """Store an entry directly in the vault file, sealed with the vault key but
    without the API's input rules, like a row an older release or an import
    without validation could have written."""
    key = await vault_key(master_password)
    document = {
        "name": name,
        "kind": "login",
        "username": None,
        "value": value,
        "url": None,
        "totp_secret": None,
        "description": None,
        "tags": [],
        "custom_fields": [],
        "folder": None,
        "favorite": False,
        "history": [],
        **fields,
    }
    uid = os.urandom(16)
    sealed = key.seal_entry(uid, json.dumps(document).encode())
    await db_execute(
        "INSERT INTO entries (uid, name_index, document, backed_up, deleted) "
        "VALUES (:uid, :index, :document, 0, :deleted)",
        uid=uid,
        index=key.name_index(name),
        document=sealed,
        deleted=deleted,
    )
    [(entry_id,)] = await db_execute("SELECT id FROM entries WHERE uid = :uid", uid=uid)
    return entry_id


def legacy_backup_zip(entries: list[dict[str, object]], password: str) -> bytes:
    """A backup ZIP as CipherMoth 2.0 and earlier wrote it (backup format 1)."""
    payload = json.dumps(
        {"exported_at": "2026-10-01T00:00:00+00:00", "passwords": entries},
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(password.encode())
        archive.writestr("ciphermoth_backup.json", payload)
    return buffer.getvalue()


async def read_current_vault(
    master_password: str = MASTER_PASSWORD, *, strict: bool = True
):
    """Every entry and attachment of the shared test vault, decrypted by the
    independent reader in tests/integrity.py."""
    from tests.integrity import read_vault

    key = await stored_vault_key(master_password)
    async with engine.connect() as conn:
        return await read_vault(
            conn, key, master_password=master_password, strict=strict
        )


async def name_index(name: str, master_password: str = MASTER_PASSWORD) -> bytes:
    return (await vault_key(master_password)).name_index(name)


async def active_rows_named(name: str) -> int:
    [(count,)] = await db_execute(
        "SELECT count(*) FROM entries WHERE name_index = :index AND deleted IS NULL",
        index=await name_index(name),
    )
    return count


def backup_entry(name: str, value: str = "backed-Value-1", **fields: object) -> dict:
    return {
        "name": name,
        "kind": "login",
        "username": None,
        "value": value,
        "url": None,
        "totp_secret": None,
        "description": None,
        "tags": [],
        "custom_fields": [],
        "folder": None,
        "favorite": False,
        "history": [],
        "created": "2026-01-02T03:04:05.000006+00:00",
        "updated": "2026-01-03T03:04:05.000006+00:00",
        "deleted": None,
        "attachments": [],
        **fields,
    }


def backup_file(
    entries: list[dict],
    password: str = MASTER_PASSWORD,
    *,
    contents: tuple[bytes, ...] | list[bytes] = (),
    settings: dict | None = None,
    manifest: dict | None = None,
    frames: int | None = None,
) -> bytes:
    """A backup (format 2) built with the frame writer, for import tests that
    need files the export would never produce."""
    from backup_format import BackupWriter
    from helpers import (
        DEFAULT_KDF,
        BackupHeader,
        BackupKey,
        argon2id,
    )

    document = manifest or {
        "format": "ciphermoth-backup",
        "version": 2,
        "exported_at": "2026-10-15T00:00:00+00:00",
        "app_version": "test",
        "settings": settings or dict(SETTINGS_DEFAULTS),
        "entries_count": len(entries),
    }
    entries_to_write = document.pop("entries", entries)
    document.setdefault("entries_count", len(entries_to_write))
    salt = os.urandom(16)
    key = BackupKey(argon2id(password, salt, DEFAULT_KDF))
    header = BackupHeader(
        params=DEFAULT_KDF,
        salt=salt,
        frames=frames
        if frames is not None
        else 1 + len(entries_to_write) + len(contents),
        commitment=key.commitment,
    )
    target = io.BytesIO()
    writer = BackupWriter(target, key, header)
    writer.write(json.dumps(document).encode())
    content_iter = iter(contents)
    for entry in entries_to_write:
        writer.write(json.dumps(entry).encode())
        for _ in entry.get("attachments", []):
            try:
                writer.write(next(content_iter))
            except StopIteration:
                break
    for content in content_iter:
        writer.write(content)
    writer.finish()
    return target.getvalue()
