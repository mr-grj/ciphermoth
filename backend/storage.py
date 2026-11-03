import contextlib
import os
import shutil
import sqlite3
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, insert

from helpers import FORMAT_VERSION
from models import (
    SETTINGS_DEFAULTS,
    BaseModel,
    RecoveryModel,
    SecurityKeyModel,
    SettingsModel,
)

MIN_SQLITE_VERSION = (3, 51, 3)
APPLICATION_ID = 0x434D5448
SCHEMA_VERSION = 3
FORMAT_1_SCHEMA = 1
# Older schemas this release upgrades in place, after a snapshot.
UPGRADABLE_SCHEMAS = frozenset({2})
BUSY_TIMEOUT_MS = 15_000
RESTORE_BUSY_TIMEOUT_MS = 2_000
JOURNAL_SIZE_LIMIT = 16 * 1024 * 1024

VAULT_FILE = "vault.db"
LOCK_FILE = "vault.lock"
SNAPSHOT_DIR = "snapshots"
SET_ASIDE_PENDING = "set-aside-in-progress"
RESTORING_SUFFIX = ".restoring"
_SIDECARS = ("-wal", "-shm", "-journal")
_UNREADABLE = (11, 26)

_PRAGMAS = (
    "PRAGMA foreign_keys=ON",
    f"PRAGMA journal_size_limit={JOURNAL_SIZE_LIMIT}",
    f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}",
    "PRAGMA synchronous=FULL",
    "PRAGMA secure_delete=ON",
    "PRAGMA trusted_schema=OFF",
)


class StorageError(Exception):
    """A vault file that cannot be opened, checked, copied or restored safely.
    The message is meant for the operator."""


def require_supported_sqlite(
    version: tuple[int, int, int] = sqlite3.sqlite_version_info,
) -> None:
    if version < MIN_SQLITE_VERSION:
        found = ".".join(map(str, version))
        needed = ".".join(map(str, MIN_SQLITE_VERSION))
        raise StorageError(
            f"SQLite {found} is too old for a CipherMoth vault: {needed} or newer "
            "fixes the WAL-reset corruption bug that concurrent connections can "
            "trigger. Use the official images or a uv-managed Python."
        )


def vault_file(data_dir: Path) -> Path:
    return data_dir / VAULT_FILE


def snapshot_dir(data_dir: Path) -> Path:
    return data_dir / SNAPSHOT_DIR


def prepare_data_dir(data_dir: Path) -> Path:
    """Create the data folder (0700) and an empty vault file (0600) if they are
    missing, so SQLite never creates the vault or its WAL with looser modes."""
    try:
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise StorageError(_unwritable(data_dir, error)) from error
    path = vault_file(data_dir)
    refuse_pending_set_aside(data_dir)
    refuse_orphaned_journals(path)
    refuse_unusable_file(path)
    try:
        with contextlib.suppress(FileExistsError):
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        if not os.access(data_dir, os.W_OK | os.X_OK) or not os.access(path, os.W_OK):
            raise PermissionError(13, "Permission denied")
    except OSError as error:
        raise StorageError(_unwritable(data_dir, error)) from error
    return path


def refuse_pending_set_aside(data_dir: Path) -> None:
    if (snapshot_dir(data_dir) / SET_ASIDE_PENDING).exists():
        raise StorageError(
            "A vault set-aside was interrupted. Nothing was changed. Run "
            "'ciphermoth-admin set-aside' again to finish moving the vault and "
            "its journals together before starting or restoring CipherMoth."
        )


def refuse_orphaned_journals(path: Path) -> None:
    """A write-ahead log or rollback journal next to a missing or empty vault
    file belongs to a vault that was moved away (an interrupted set-aside, a
    copy gone wrong). Creating a new vault there would make SQLite discard it,
    and with it commits that exist nowhere else."""
    if path.is_file() and path.stat().st_size > 0:
        return
    for suffix in ("-wal", "-journal"):
        journal = path.with_name(path.name + suffix)
        if journal.is_file() and journal.stat().st_size > 0:
            raise StorageError(
                f"{journal.name} exists but {path.name} is missing or empty, so the "
                "journal belongs to a vault that is not there. Nothing was changed. "
                "Run 'ciphermoth-admin set-aside' again to move it next to the vault "
                "it belongs to, or put that vault file back (docs/UPDATING.md)."
            )


def _unwritable(data_dir: Path, error: OSError) -> str:
    message = f"CipherMoth cannot write its vault in {data_dir}: {error.strerror}."
    if sys.platform != "win32" and data_dir.exists():
        owner = data_dir.stat().st_uid
        user = os.getuid()
        if owner != user:
            message += (
                f" The folder belongs to uid {owner} but CipherMoth runs as uid "
                f"{user}; give it to that user (chown -R {user}:{os.getgid()})."
            )
    return message


def configure_connection(dbapi_connection: Any) -> None:
    """Connection settings every vault connection uses. Python's sqlite3 module
    must not open transactions on its own (the engine emits BEGIN), WAL lets
    readers run next to the single writer, and FULL sync keeps an acknowledged
    write through a power cut."""
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        mode = cursor.fetchone()
        if not mode or str(mode[0]).lower() != "wal":
            raise StorageError(
                "The vault's file system does not support SQLite's WAL mode. "
                "Keep the data folder on a local disk."
            )
        for pragma in _PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


FORMAT_1_VAULT = (
    "was created by CipherMoth 2.0 or earlier (vault format 1), which this "
    "release no longer opens. Nothing was changed. To move your entries, make a "
    "backup with CipherMoth 2.0, stop CipherMoth, run 'ciphermoth-admin "
    "set-aside' to move the old vault into the snapshot folder, start this "
    "release, create a new vault and import the backup (docs/UPDATING.md)"
)


def identity_problem(application_id: int, user_version: int) -> str | None:
    if application_id != APPLICATION_ID:
        return "is not a CipherMoth vault"
    if user_version == FORMAT_1_SCHEMA:
        return FORMAT_1_VAULT
    if user_version > SCHEMA_VERSION:
        return (
            f"was written by a newer CipherMoth (vault schema {user_version}, this "
            f"release understands {SCHEMA_VERSION}); update CipherMoth"
        )
    if user_version != SCHEMA_VERSION and user_version not in UPGRADABLE_SCHEMAS:
        return f"has an unsupported vault schema ({user_version})"
    return None


_VAULT_FORMATS = "SELECT format_version FROM vault"


def format_problem(formats: Sequence[object]) -> str | None:
    """Whether the vault row (if the vault is set up) has a cryptographic format
    this release reads. Kept apart from the schema version: the same tables
    could one day hold a newer format."""
    if len(formats) > 1:
        return "has more than one vault key row"
    if formats and not isinstance(formats[0], int):
        return "has an invalid vault format marker"
    if formats and formats[0] != FORMAT_VERSION:
        if isinstance(formats[0], int) and formats[0] > FORMAT_VERSION:
            return (
                f"was written by a newer CipherMoth (vault format {formats[0]}, "
                f"this release understands {FORMAT_VERSION}); update CipherMoth"
            )
        return f"has an unsupported vault format ({formats[0]})"
    return None


def ensure_schema(connection: Connection) -> None:
    """Create the schema in an empty vault file, or check that an existing file is
    a vault this release understands. Runs inside one write transaction, so an
    interrupted first start leaves an empty file that the next start fills."""
    application_id = connection.exec_driver_sql("PRAGMA application_id").scalar()
    user_version = connection.exec_driver_sql("PRAGMA user_version").scalar()
    objects = connection.exec_driver_sql("SELECT count(*) FROM sqlite_schema").scalar()
    if application_id == 0 and user_version == 0 and objects == 0:
        BaseModel.metadata.create_all(connection)
        connection.execute(insert(SettingsModel).values(**SETTINGS_DEFAULTS))
        connection.exec_driver_sql(f"PRAGMA application_id={APPLICATION_ID}")
        connection.exec_driver_sql(f"PRAGMA user_version={SCHEMA_VERSION}")
        return
    problem = identity_problem(application_id or 0, user_version or 0)
    if problem is None:
        formats = connection.exec_driver_sql(_VAULT_FORMATS).scalars().all()
        problem = format_problem(list(formats))
    if problem:
        raise StorageError(f"The vault file {problem}.")
    for version in range(user_version, SCHEMA_VERSION):
        _UPGRADES[version](connection)
    if user_version != SCHEMA_VERSION:
        connection.exec_driver_sql(f"PRAGMA user_version={SCHEMA_VERSION}")


def _upgrade_2_to_3(connection: Connection) -> None:
    """Security keys and the recovery code: two new tables and one new column.
    Nothing existing changes, so a vault without either works exactly as before."""
    BaseModel.metadata.create_all(
        connection,
        tables=[
            BaseModel.metadata.tables[RecoveryModel.__tablename__],
            BaseModel.metadata.tables[SecurityKeyModel.__tablename__],
        ],
    )
    connection.exec_driver_sql("ALTER TABLE vault ADD COLUMN factor_key_escrow BLOB")


_UPGRADES = {2: _upgrade_2_to_3}


def schema_version(path: Path) -> int | None:
    """The schema version of an existing vault file, read without writing."""
    if not path.is_file() or path.stat().st_size == 0:
        return None
    with contextlib.closing(_connect_existing(path)) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def refuse_unusable_file(path: Path) -> None:
    """Check an existing, non-empty file through a read-only connection before
    anything opens it for writing: a file that is not a vault of this release,
    or that fails SQLite's quick check, is refused exactly as it is, WAL
    included."""
    if not path.is_file() or path.stat().st_size == 0:
        return
    try:
        with contextlib.closing(_connect_existing(path)) as connection:
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            objects = connection.execute(
                "SELECT count(*) FROM sqlite_schema"
            ).fetchone()
            if application_id == 0 and user_version == 0 and objects == (0,):
                return
            problem = identity_problem(application_id, user_version)
            if problem is None:
                problem = format_problem(_formats(connection))
            if problem:
                raise StorageError(f"The vault file {problem}.")
            damage = [
                str(row[0])
                for row in connection.execute("PRAGMA quick_check")
                if str(row[0]) != "ok"
            ]
    except sqlite3.DatabaseError as error:
        raise StorageError(
            f"SQLite cannot open the vault file {path}: {error}. Restore a "
            "snapshot (docs/UPDATING.md)."
        ) from error
    if damage:
        raise StorageError(
            "The vault file failed SQLite's integrity check: "
            + "; ".join(damage[:5])
            + ". Restore a snapshot (docs/UPDATING.md)."
        )


def check_connection(connection: sqlite3.Connection) -> list[str]:
    """Every problem SQLite finds in a vault: page and index integrity, foreign
    keys, and whether the file is a vault of this release at all."""
    problems = [
        str(row[0])
        for row in connection.execute("PRAGMA integrity_check")
        if str(row[0]) != "ok"
    ]
    problems += [
        f"{row[0]} row {row[1]} references a missing row of {row[2]}"
        for row in connection.execute("PRAGMA foreign_key_check")
    ]
    application_id = connection.execute("PRAGMA application_id").fetchone()[0]
    user_version = connection.execute("PRAGMA user_version").fetchone()[0]
    problem = identity_problem(application_id, user_version)
    if problem is None:
        problem = format_problem(_formats(connection))
    if problem:
        problems.append(f"the file {problem}")
    return problems


def _formats(connection: sqlite3.Connection) -> list[int]:
    return [row[0] for row in connection.execute(_VAULT_FORMATS)]


def _connect_existing(path: Path, *, writable: bool = False) -> sqlite3.Connection:
    """A connection to an existing file. Read-only unless asked otherwise: a
    read-only connection never checkpoints or deletes the WAL, so reading a vault
    (to check, copy or keep it) changes none of its files."""
    if not path.is_file():
        raise StorageError(f"{path} does not exist.")
    mode = "rw" if writable else "ro"
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode={mode}", uri=True)
    connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def check_file(path: Path) -> list[str]:
    require_supported_sqlite()
    try:
        with contextlib.closing(_connect_existing(path)) as connection:
            return check_connection(connection)
    except sqlite3.DatabaseError as error:
        return [f"SQLite cannot read the file: {error}"]


def _fsync(path: Path) -> None:
    fd = os.open(path, os.O_RDWR if sys.platform == "win32" else os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    if sys.platform == "win32":
        return
    _fsync(path)


def _discard(path: Path) -> None:
    """Remove a file this module wrote (a partial copy or a staged restore) and
    any journal SQLite left next to it."""
    for suffix in ("", *_SIDECARS):
        path.with_name(path.name + suffix).unlink(missing_ok=True)


def _copy(source: Path, destination: Path, *, journal_mode: str = "DELETE") -> None:
    """A consistent, self-contained copy of the vault through SQLite's online
    backup API, so committed transactions still in the WAL are included and
    concurrent writers are no problem. The copy is checked before it gets its
    final name."""
    partial = destination.with_name(destination.name + ".partial")
    _discard(partial)
    os.close(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    try:
        with (
            contextlib.closing(_connect_existing(source)) as src,
            contextlib.closing(sqlite3.connect(partial)) as dst,
        ):
            src.backup(dst)
            dst.execute(f"PRAGMA journal_mode={journal_mode}")
            problems = check_connection(dst)
        if problems:
            raise StorageError(
                f"The copy of {source.name} failed its integrity check: "
                + "; ".join(problems[:5])
            )
        _fsync(partial)
        os.replace(partial, destination)
        _fsync_dir(destination.parent)
    except BaseException:
        _discard(partial)
        raise


def timestamped(prefix: str) -> str:
    return f"{prefix}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.db"


def snapshot(data_dir: Path, destination: Path | None = None) -> Path:
    """Copy the live vault to ``destination`` (by default a new file in the
    snapshot folder). Safe while CipherMoth is running."""
    require_supported_sqlite()
    folder = snapshot_dir(data_dir)
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise StorageError(f"Could not create {folder}: {error}") from error
    target = destination or folder / timestamped("vault")
    if target.resolve().parent == data_dir.resolve() and target.name.startswith(
        VAULT_FILE
    ):
        raise StorageError(
            f"{target.name} is a name the vault itself uses; choose another name."
        )
    if target.exists():
        raise StorageError(f"{target} already exists.")
    try:
        _copy(vault_file(data_dir), target)
    except sqlite3.DatabaseError as error:
        raise StorageError(f"Could not copy the vault: {error}") from error
    except OSError as error:
        raise StorageError(f"Could not write the snapshot: {error}") from error
    return target


class VaultLock:
    """An exclusive lock on the data folder: one CipherMoth process serves a
    vault (vault sessions live in its memory), and a restore runs only while
    none does."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / LOCK_FILE
        self._fd: int | None = None

    def acquire(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as error:
            raise StorageError(_unwritable(self.path.parent, error)) from error
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise StorageError(
                f"Another CipherMoth process is using {self.path.parent}. Stop it "
                "first."
            ) from None
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "VaultLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


def _is_busy(error: sqlite3.Error) -> bool:
    return _primary_code(error) in (5, 6)


def _primary_code(error: sqlite3.Error) -> int | None:
    code = getattr(error, "sqlite_errorcode", None)
    return code & 0xFF if isinstance(code, int) else None


def _take_exclusively(live: Path) -> sqlite3.Connection | None:
    """Open the live vault and keep every other connection out until this one
    closes (exclusive locking mode). The connection never checkpoints on close,
    so closing it after a failure changes nothing. None if the file is not a
    database SQLite can read at all, in which case nothing else can use it
    either; any other problem stops the restore."""
    try:
        connection = _connect_existing(live, writable=True)
    except sqlite3.DatabaseError as error:
        raise StorageError(
            f"Could not open {live} for the restore: {error}. Nothing was changed."
        ) from error
    try:
        connection.setconfig(sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, True)
        connection.execute(f"PRAGMA busy_timeout={RESTORE_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        connection.execute("COMMIT")
    except sqlite3.DatabaseError as error:
        connection.close()
        if _is_busy(error):
            raise StorageError(
                f"{live} is open in another program. Stop CipherMoth and anything "
                "else using the vault, then restore again. Nothing was changed."
            ) from error
        if _primary_code(error) in _UNREADABLE:
            return None
        raise StorageError(
            f"Could not take {live} for the restore: {error}. Nothing was changed."
        ) from error
    return connection


def _kept_folder(folder: Path) -> Path:
    kept = folder / timestamped("replaced").removesuffix(".db")
    kept.mkdir(mode=0o700)
    return kept


def _keep_raw(live: Path, kept: Path) -> None:
    """Copy the vault's files byte for byte, WAL included, into ``kept``. Called
    while nothing else can write them."""
    for suffix in ("", "-wal"):
        source = live.with_name(live.name + suffix)
        if source.exists():
            target = kept / source.name
            shutil.copyfile(source, target)
            os.chmod(target, 0o600)
            _fsync(target)
    _fsync_dir(kept)
    _fsync_dir(kept.parent)


def _move_sidecars(live: Path, kept: Path) -> None:
    """Move whatever journal files remain next to the vault into ``kept``, so
    they can never be replayed into the restored file. Never deleted."""
    for suffix in _SIDECARS:
        sidecar = live.with_name(live.name + suffix)
        if sidecar.exists():
            os.replace(sidecar, kept / f"{sidecar.name}.unfolded")
    _fsync_dir(kept)
    _fsync_dir(live.parent)


def _retire(live: Path, folder: Path) -> Path | None:
    """Keep the vault a restore replaces and make sure no journal of it can be
    replayed into the restored file. A vault is kept byte for byte with its WAL,
    then its WAL is folded in by SQLite; journal files SQLite cannot fold, or
    left next to a missing or empty vault, are moved into the kept folder."""
    sidecars = [live.with_name(live.name + suffix) for suffix in _SIDECARS]
    has_vault = live.exists() and live.stat().st_size > 0
    if not has_vault and not any(path.exists() for path in sidecars):
        return None
    connection = _take_exclusively(live) if has_vault else None
    try:
        kept = _kept_folder(folder)
        try:
            if has_vault:
                _keep_raw(live, kept)
        except BaseException:
            shutil.rmtree(kept, ignore_errors=True)
            raise
        if connection is not None:
            with contextlib.suppress(sqlite3.DatabaseError):
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("PRAGMA journal_mode=DELETE")
    finally:
        if connection is not None:
            connection.close()
    _move_sidecars(live, kept)
    return kept


def restore(data_dir: Path, source: Path) -> Path | None:
    """Replace the vault with the snapshot ``source``. CipherMoth must not be
    running. The replaced vault is kept, byte for byte, in a folder in the
    snapshot folder, and that folder is returned. If a restore is interrupted,
    the vault file is the old vault (complete, its WAL folded by SQLite or kept)
    or the restored one, and running the restore again completes it."""
    require_supported_sqlite()
    live = vault_file(data_dir)
    folder = snapshot_dir(data_dir)
    problems = check_file(source)
    if problems:
        raise StorageError(f"{source} cannot be restored: " + "; ".join(problems[:5]))
    staged = live.with_name(live.name + RESTORING_SUFFIX)
    try:
        with VaultLock(data_dir):
            refuse_pending_set_aside(data_dir)
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                _copy(source, staged, journal_mode="WAL")
            except sqlite3.DatabaseError as error:
                raise StorageError(f"Could not copy {source}: {error}") from error
            kept = _retire(live, folder)
            os.replace(staged, live)
            _fsync_dir(data_dir)
    except StorageError:
        _discard(staged)
        raise
    except OSError as error:
        _discard(staged)
        raise StorageError(
            f"The restore failed: {error}. Nothing was replaced."
        ) from error
    return kept


def set_aside(data_dir: Path) -> Path | None:
    """
    Move the vault file and its journal files, unchanged and together, into a
    new folder in the snapshot folder, so that the next start creates a new,
    empty vault. Nothing is deleted or rewritten: moving the files back (with
    CipherMoth stopped) restores the vault exactly. Works on any file, also one
    this release refuses to open. CipherMoth must not be running. Returns the
    folder, or None if there was nothing to move.
    """
    require_supported_sqlite()
    live = vault_file(data_dir)
    files = [live.with_name(live.name + suffix) for suffix in ("", *_SIDECARS)]
    folder = snapshot_dir(data_dir)
    pending = folder / SET_ASIDE_PENDING
    try:
        with VaultLock(data_dir):
            if not pending.exists() and not any(path.exists() for path in files):
                return None
            if live.exists() and live.stat().st_size > 0:
                connection = _take_exclusively(live)
                if connection is not None:
                    connection.close()
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            pending.mkdir(mode=0o700, exist_ok=True)
            # Publish a durable recovery marker before moving any vault file.
            # Its fixed name lets a retry reunite a DB and WAL split by a kill.
            _fsync_dir(folder)
            _fsync_dir(data_dir)
            for path in files:
                if path.exists():
                    target = pending / path.name
                    if target.exists():
                        raise StorageError(
                            f"Both {path} and {target} exist. Nothing was overwritten; "
                            "keep both copies and resolve the interrupted set-aside."
                        )
                    os.replace(path, target)
            _fsync_dir(pending)
            _fsync_dir(data_dir)
            kept = folder / timestamped("set-aside").removesuffix(".db")
            os.replace(pending, kept)
            _fsync_dir(folder)
            _fsync_dir(data_dir)
    except OSError as error:
        raise StorageError(f"Could not move the vault aside: {error}") from error
    return kept
