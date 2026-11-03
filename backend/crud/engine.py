import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import URL, Connection, event, text
from sqlalchemy.exc import DatabaseError, DBAPIError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backup_format import MAX_BACKUP_BYTES, MAX_FRAMES
from errors import InvalidRequest, VaultBusy
from settings import get_storage_settings
from storage import (
    SCHEMA_VERSION,
    UPGRADABLE_SCHEMAS,
    StorageError,
    configure_connection,
    ensure_schema,
    prepare_data_dir,
    require_supported_sqlite,
    schema_version,
    snapshot,
    snapshot_dir,
    timestamped,
    vault_file,
)

logger = logging.getLogger(__name__)

_AFTER_COMMIT = "ciphermoth_after_commit"
_AFTER_ROLLBACK = "ciphermoth_after_rollback"
_BEGIN = "ciphermoth_begin"
_BUSY_CODES = frozenset({5, 6})
_BUSY_DETAIL = "The vault is busy with another change. Try again in a moment."
_ENTRY_BACKUP_OVERHEAD = 32 * 1024
_ATTACHMENT_BACKUP_OVERHEAD = 256
_BACKUP_FIXED_OVERHEAD = 4096


async def _enforce_backup_capacity(session: AsyncSession) -> None:
    """Keep every committed vault within the documented complete-backup cap.

    Stored ciphertext lengths plus conservative per-record JSON/framing budgets
    bound the largest portable backup without decrypting data on each write.
    """
    entry_bytes, entry_count = (
        await session.execute(
            text("SELECT coalesce(sum(length(document)), 0), count(*) FROM entries")
        )
    ).one()
    attachment_bytes, attachment_count = (
        await session.execute(
            text(
                "SELECT coalesce(sum(length(meta) + length(content)), 0), count(*) "
                "FROM attachments"
            )
        )
    ).one()
    if 1 + int(entry_count) + int(attachment_count) > MAX_FRAMES:
        raise InvalidRequest(
            "This change would exceed the vault's complete-backup frame limit. "
            "Nothing was saved."
        )
    estimated = (
        int(entry_bytes)
        + int(entry_count) * _ENTRY_BACKUP_OVERHEAD
        + int(attachment_bytes)
        + int(attachment_count) * _ATTACHMENT_BACKUP_OVERHEAD
        + _BACKUP_FIXED_OVERHEAD
    )
    if estimated > MAX_BACKUP_BYTES:
        raise InvalidRequest(
            "This change would exceed the vault's 1 GiB complete-backup capacity. "
            "Nothing was saved."
        )


def _tolerant_text(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def _connect(dbapi_connection: Any, _record: object) -> None:
    """
    Every vault connection: the SQLite settings, and a text decoder that
    cannot fail. Python's sqlite3 raises while fetching a TEXT value that is
    not UTF-8 and leaves that statement un-reset, holding its snapshot (and
    in a write, the write lock) until the garbage collector frees it. With
    surrogate escapes the fetch completes, and the strict readers refuse the
    value as damage instead.
    """
    configure_connection(dbapi_connection)
    dbapi_connection._connection.text_factory = _tolerant_text


def _begin(connection: Connection) -> None:
    mode = connection.get_execution_options().get(_BEGIN, "DEFERRED")
    connection.exec_driver_sql(f"BEGIN {mode}")


def create_engine(path: Path, **pool: Any) -> AsyncEngine:
    require_supported_sqlite()
    engine = create_async_engine(
        URL.create("sqlite+aiosqlite", database=str(path)), **pool
    )
    event.listen(engine.sync_engine, "connect", _connect)
    event.listen(engine.sync_engine, "begin", _begin)
    return engine


def is_busy(error: OperationalError) -> bool:
    code = getattr(error.orig, "sqlite_errorcode", None)
    return isinstance(code, int) and code & 0xFF in _BUSY_CODES


def after_commit(session: AsyncSession, callback: Callable[[], object]) -> None:
    """
    Run ``callback`` once the request's transaction has committed, and never if
    it rolls back. Used for in-memory state that must not get ahead of the
    database, such as ending every vault session after a master password
    change.
    """
    session.info.setdefault(_AFTER_COMMIT, []).append(callback)


def after_rollback(session: AsyncSession, callback: Callable[[], object]) -> None:
    """Run ``callback`` if the request's transaction rolls back instead."""
    session.info.setdefault(_AFTER_ROLLBACK, []).append(callback)


def _run(session: AsyncSession, hooks: str) -> None:
    callbacks = session.info.pop(hooks, [])
    session.info.pop(_AFTER_COMMIT, None)
    session.info.pop(_AFTER_ROLLBACK, None)
    for callback in callbacks:
        callback()


class Database:
    """
    The SQLite vault of one app instance. The engine is created on first use,
    so building an app opens no file.

    Read transactions are deferred and see one consistent WAL snapshot next to
    a running writer. A connection that raised a database error is discarded
    instead of returned to the pool, so a statement left un-reset by a failed
    fetch can never keep its old snapshot open on a pooled connection (the
    text decoder set in ``_connect`` removes the known cause). Write
    transactions start with
    BEGIN IMMEDIATE, which takes SQLite's single write lock before their first
    read, so every write request checks its session key, reads and writes as
    one serialized unit, and a master password change can never interleave with
    another write.
    """

    def __init__(
        self, data_dir: Path | None = None, *, engine: AsyncEngine | None = None
    ) -> None:
        self._data_dir = data_dir
        self._engine = engine
        self._sessions: dict[bool, async_sessionmaker[AsyncSession]] = {}

    @property
    def data_dir(self) -> Path:
        return self._data_dir or get_storage_settings().data_dir

    @property
    def path(self) -> Path:
        return vault_file(self.data_dir)

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            self._engine = create_engine(self.path)
        return self._engine

    def writer(self) -> AsyncEngine:
        return self.engine.execution_options(**{_BEGIN: "IMMEDIATE"})

    def sessions(self, *, write: bool = True) -> async_sessionmaker[AsyncSession]:
        if write not in self._sessions:
            self._sessions[write] = async_sessionmaker(
                self.writer() if write else self.engine,
                expire_on_commit=False,
                class_=AsyncSession,
            )
        return self._sessions[write]

    @asynccontextmanager
    async def transaction(self, *, write: bool = True) -> AsyncIterator[AsyncSession]:
        async with self.sessions(write=write)() as session:
            try:
                yield session
                if write:
                    await _enforce_backup_capacity(session)
                await session.commit()
            except BaseException as error:
                try:
                    if isinstance(error, DBAPIError):
                        await session.invalidate()
                    else:
                        await session.rollback()
                finally:
                    _run(session, _AFTER_ROLLBACK)
                if (
                    isinstance(error, OperationalError) and is_busy(error)
                ) or isinstance(error, PoolTimeout):
                    raise VaultBusy(_BUSY_DETAIL) from error
                raise
            _run(session, _AFTER_COMMIT)

    async def prepare(self) -> None:
        """Create or open the vault file: folder and file modes, a read-only
        identity and integrity check of an existing file, then the schema."""
        await asyncio.to_thread(prepare_data_dir, self.data_dir)
        await asyncio.to_thread(self._snapshot_before_upgrade)
        try:
            async with self.writer().begin() as connection:
                await connection.run_sync(ensure_schema)
        except DatabaseError as error:
            raise StorageError(
                f"SQLite cannot open the vault file {self.path}: {error.orig}. "
                "Restore a snapshot (docs/UPDATING.md)."
            ) from error

    def _snapshot_before_upgrade(self) -> None:
        """An older schema is upgraded in place by ``ensure_schema``; keep a copy of
        the vault exactly as the previous release left it first."""
        if schema_version(self.path) not in UPGRADABLE_SCHEMAS:
            return
        kept = snapshot(
            self.data_dir,
            snapshot_dir(self.data_dir)
            / timestamped(f"before-schema-{SCHEMA_VERSION}"),
        )
        logger.info("Upgrading the vault schema; the previous file is in %s.", kept)

    async def dispose(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
