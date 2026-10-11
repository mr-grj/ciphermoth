import asyncio
import hashlib
import os
import platform
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import helpers
import sqlalchemy as sa
from api.exceptions import UnhandledErrorMiddleware
from fastapi import Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from schemas import MasterPassword, MasterPasswordCreatePayload
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from . import memory

ATTACHMENT_LIMIT = 5 * 1024 * 1024

metadata = sa.MetaData()

vault_table = sa.Table(
    "spike_vault",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("salt", sa.LargeBinary, nullable=False),
    sa.Column("hash_key", sa.String, nullable=False),
    sa.Column("key_check", sa.LargeBinary, nullable=False),
)

attachment_table = sa.Table(
    "spike_attachment",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("filename", sa.LargeBinary, nullable=False),
    sa.Column("content", sa.LargeBinary, nullable=False),
    sa.Column("size_bytes", sa.Integer, nullable=False),
)

entry_table = sa.Table(
    "spike_entry",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("name", sa.LargeBinary, nullable=False),
    sa.Column("value", sa.LargeBinary, nullable=False),
)


@dataclass
class VaultSession:
    key: str | None = None
    unlocked_at: float | None = None


@dataclass
class CoreState:
    engine: AsyncEngine
    data_dir: Path
    session: VaultSession = field(default_factory=VaultSession)
    cancelled: int = 0
    started: float = field(default_factory=time.monotonic)


def _sqlite_pragmas(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    for pragma in (
        "PRAGMA foreign_keys=ON",
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=FULL",
        "PRAGMA secure_delete=ON",
        "PRAGMA busy_timeout=5000",
    ):
        cursor.execute(pragma)
    cursor.close()


async def open_state(data_dir: Path) -> CoreState:
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = data_dir / "spike.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database}")
    event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    if sys.platform != "win32":
        os.chmod(database, 0o600)
    return CoreState(engine=engine, data_dir=data_dir)


def build_spike_app(state: CoreState, test_hooks: bool) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(UnhandledErrorMiddleware, headers={"Cache-Control": "no-store"})

    def vault_key() -> str:
        if state.session.key is None:
            raise HTTPException(status_code=423, detail="Vault is locked.")
        return state.session.key

    @app.get("/spike/health")
    async def health() -> dict:
        return {"ok": True}

    @app.get("/spike/vault/status")
    async def vault_status() -> dict:
        async with state.engine.connect() as conn:
            exists = (await conn.execute(sa.select(vault_table.c.id))).first()
        return {"exists": exists is not None, "unlocked": state.session.key is not None}

    @app.post("/spike/vault/create")
    async def vault_create(payload: MasterPasswordCreatePayload) -> dict:
        salt = os.urandom(16)
        key = await asyncio.to_thread(
            helpers.generate_key_derivation, salt, payload.master_password
        )
        hash_key = await asyncio.to_thread(
            helpers.hash_master_password, payload.master_password
        )
        async with state.engine.begin() as conn:
            if (await conn.execute(sa.select(vault_table.c.id))).first():
                raise HTTPException(status_code=409, detail="Vault already exists.")
            await conn.execute(
                vault_table.insert().values(
                    id=1,
                    salt=salt,
                    hash_key=hash_key,
                    key_check=helpers.create_key_check(key, salt),
                )
            )
        state.session = VaultSession(key=key.decode(), unlocked_at=time.time())
        return {"unlocked": True}

    @app.post("/spike/vault/unlock")
    async def vault_unlock(payload: MasterPassword) -> dict:
        async with state.engine.connect() as conn:
            row = (await conn.execute(sa.select(vault_table))).first()
        if row is None:
            raise HTTPException(status_code=404, detail="No vault yet.")
        valid = await asyncio.to_thread(
            helpers.verify_master_password, payload.master_password, row.hash_key
        )
        if not valid:
            raise HTTPException(status_code=403, detail="Wrong master password.")
        key = await asyncio.to_thread(
            helpers.generate_key_derivation, row.salt, payload.master_password
        )
        if not helpers.verify_key_check(key, row.key_check, row.salt):
            raise HTTPException(status_code=403, detail="Key check failed.")
        state.session = VaultSession(key=key.decode(), unlocked_at=time.time())
        return {"unlocked": True}

    @app.post("/spike/vault/lock")
    async def vault_lock() -> dict:
        state.session = VaultSession()
        return {"unlocked": False}

    @app.post("/spike/attachments")
    async def upload(file: UploadFile, key: str = Depends(vault_key)) -> dict:
        data = await file.read()
        if len(data) > ATTACHMENT_LIMIT:
            raise HTTPException(status_code=400, detail="Attachment is too large.")
        async with state.engine.begin() as conn:
            result = await conn.execute(
                attachment_table.insert().values(
                    filename=helpers.encrypt(key, (file.filename or "").encode()),
                    content=helpers.encrypt(key, data),
                    size_bytes=len(data),
                )
            )
        return {
            "id": result.inserted_primary_key[0],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @app.get("/spike/attachments/{attachment_id}")
    async def download(attachment_id: int, key: str = Depends(vault_key)) -> Response:
        async with state.engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(attachment_table).where(
                        attachment_table.c.id == attachment_id
                    )
                )
            ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Attachment not found.")
        data = helpers.decrypt_bytes(key, row.content)
        if data is None:
            raise HTTPException(status_code=500, detail="Attachment is unreadable.")
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"x-sha256": hashlib.sha256(data).hexdigest()},
        )

    @app.post("/spike/echo")
    async def echo(request: Request) -> Response:
        body = await request.body()
        return Response(
            content=body,
            media_type="application/octet-stream",
            headers={"x-sha256": hashlib.sha256(body).hexdigest()},
        )

    @app.get("/spike/sleep")
    async def sleep(ms: int = Query(ge=0, le=600_000)) -> dict:
        try:
            await asyncio.sleep(ms / 1000)
        except asyncio.CancelledError:
            state.cancelled += 1
            raise
        return {"slept_ms": ms}

    @app.get("/spike/raise")
    async def explode() -> dict:
        raise RuntimeError("synthetic failure CANARY-EXCEPTION-7f3a")

    @app.post("/spike/entries/seed")
    async def seed(
        count: int = Query(ge=1, le=10_000), key: str = Depends(vault_key)
    ) -> dict:
        rows = [
            {
                "name": helpers.encrypt(key, f"Synthetic entry {i:05d}".encode()),
                "value": helpers.encrypt(key, f"synthetic-secret-{i:05d}".encode()),
            }
            for i in range(count)
        ]
        async with state.engine.begin() as conn:
            await conn.execute(entry_table.delete())
            await conn.execute(entry_table.insert(), rows)
        return {"seeded": count}

    @app.get("/spike/entries")
    async def entries(key: str = Depends(vault_key)) -> list[dict]:
        async with state.engine.connect() as conn:
            rows = (await conn.execute(sa.select(entry_table))).all()
        return [
            {
                "id": row.id,
                "name": helpers.decrypt(key, row.name),
                "value": helpers.decrypt(key, row.value),
            }
            for row in rows
        ]

    @app.get("/spike/stats")
    async def stats() -> dict:
        return {
            "pid": os.getpid(),
            "frozen": bool(getattr(sys, "frozen", False)),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "sqlite_version": sqlite3.sqlite_version,
            "rss_bytes": memory.current_rss(),
            "peak_rss_bytes": memory.peak_rss(),
            "cancelled": state.cancelled,
            "uptime_s": round(time.monotonic() - state.started, 3),
            "unlocked": state.session.key is not None,
        }

    @app.post("/spike/kdf")
    async def kdf() -> dict:
        before = memory.peak_rss()
        started = time.perf_counter()
        await asyncio.to_thread(
            helpers.generate_key_derivation, os.urandom(16), "synthetic kdf bench"
        )
        return {
            "argon2id_ms": round((time.perf_counter() - started) * 1000, 1),
            "peak_rss_before": before,
            "peak_rss_after": memory.peak_rss(),
            "rss_after": memory.current_rss(),
        }

    if test_hooks:

        @app.post("/spike/crash")
        async def crash(mode: str = "exit") -> dict:
            sys.stderr.flush()
            if mode == "abort":
                os.abort()
            if mode == "segv":
                import ctypes

                ctypes.string_at(0)
            os._exit(70)

        @app.post("/spike/stray-output")
        async def stray_output() -> dict:
            print("stray print CM\x01\x02 should never reach the protocol stream")
            os.write(1, b"CM\x01\x02 raw write to fd 1\n")
            return {"printed": True}

        @app.get("/spike/tempfiles")
        async def tempfiles() -> dict:
            import tempfile

            return {"tempdir": tempfile.gettempdir(), "data_dir": str(state.data_dir)}

    return app
