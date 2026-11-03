from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    false,
    func,
    text,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from helpers import new_uid

SETTINGS_DEFAULTS = {
    "inactivity_ms": 120_000,
    "warn_before_ms": 60_000,
    "hidden_ms": 60_000,
    "debounce_ms": 1_000,
    "clipboard_clear_ms": 30_000,
    "update_check_enabled": True,
}


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class BaseModel(DeclarativeBase):
    pass


class RecordTimestamp(TypeDecorator[datetime]):
    """Keep corrupt SQLite values available to the record integrity checks.

    SQLite permits arbitrary values in a TIMESTAMP column. The dialect's
    ordinary decoder raises while fetching the whole result set, preventing
    even healthy rows from being listed or damaged rows from being removed.
    Preserve invalid values for the strict readers instead of guessing a time.
    The stored SQL type and the normal datetime writer remain unchanged.
    """

    impl = TIMESTAMP
    cache_ok = True

    def result_processor(self, dialect: Dialect, coltype: object):
        process = super().result_processor(dialect, coltype)

        def read(value: Any) -> Any:
            try:
                return process(value) if process is not None else value
            except (ValueError, TypeError):
                return value

        return read


class VaultModel(BaseModel):
    __tablename__ = "vault"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_vault_singleton"),
        CheckConstraint("length(kdf_salt) = 16", name="ck_vault_salt"),
        CheckConstraint("length(password_check) = 32", name="ck_vault_password_check"),
        CheckConstraint("length(key_check) = 32", name="ck_vault_key_check"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created: Mapped[datetime] = mapped_column(
        TIMESTAMP, default=utc_now, server_default=func.current_timestamp()
    )
    updated: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.current_timestamp(),
    )

    format_version: Mapped[int] = mapped_column(Integer)
    kdf: Mapped[str] = mapped_column(String)
    kdf_memory_kib: Mapped[int] = mapped_column(Integer)
    kdf_iterations: Mapped[int] = mapped_column(Integer)
    kdf_lanes: Mapped[int] = mapped_column(Integer)
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary)
    password_check: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    key_check: Mapped[bytes] = mapped_column(LargeBinary)
    # Schema 3. Set while a security key is required: the factor key sealed under
    # the vault key, so the recovery code can keep the security keys working.
    factor_key_escrow: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)


class RecoveryModel(BaseModel):
    """Schema 3. The recovery code's public key and the vault key sealed to it."""

    __tablename__ = "recovery"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_recovery_singleton"),
        CheckConstraint("length(salt) = 16", name="ck_recovery_salt"),
        CheckConstraint("length(public_key) = 32", name="ck_recovery_public_key"),
        CheckConstraint("length(binding) = 32", name="ck_recovery_binding"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created: Mapped[datetime] = mapped_column(
        TIMESTAMP, default=utc_now, server_default=func.current_timestamp()
    )
    kdf_memory_kib: Mapped[int] = mapped_column(Integer)
    kdf_iterations: Mapped[int] = mapped_column(Integer)
    kdf_lanes: Mapped[int] = mapped_column(Integer)
    salt: Mapped[bytes] = mapped_column(LargeBinary)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sealed_key: Mapped[bytes] = mapped_column(LargeBinary)
    binding: Mapped[bytes] = mapped_column(LargeBinary)


class SecurityKeyModel(BaseModel):
    """
    Schema 3. One registered FIDO2 security key: its WebAuthn credential, the
    PRF salt that makes it produce its secret, and the factor key wrapped under
    that secret. The name the user gave it is sealed under the vault key.
    """

    __tablename__ = "security_keys"
    __table_args__ = (
        CheckConstraint("length(uid) = 16", name="ck_security_keys_uid"),
        CheckConstraint("length(prf_salt) = 32", name="ck_security_keys_prf_salt"),
        {"sqlite_autoincrement": True},
    )

    def __init__(self, **fields: object) -> None:
        fields.setdefault("uid", new_uid())
        super().__init__(**fields)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created: Mapped[datetime] = mapped_column(
        TIMESTAMP, default=utc_now, server_default=func.current_timestamp()
    )
    last_used: Mapped[datetime | None] = mapped_column(TIMESTAMP, default=None)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    rp_id: Mapped[str] = mapped_column(String)
    prf_salt: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    wrapped_factor_key: Mapped[bytes] = mapped_column(LargeBinary)
    name: Mapped[bytes] = mapped_column(LargeBinary)


class EntryModel(BaseModel):
    __tablename__ = "entries"
    __table_args__ = (
        Index(
            "uq_entries_name_active",
            "name_index",
            unique=True,
            sqlite_where=text("deleted IS NULL"),
        ),
        CheckConstraint("length(uid) = 16", name="ck_entries_uid"),
        CheckConstraint("length(name_index) = 32", name="ck_entries_name_index"),
        {"sqlite_autoincrement": True},
    )

    def __init__(self, **fields: object) -> None:
        fields.setdefault("uid", new_uid())
        super().__init__(**fields)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created: Mapped[datetime] = mapped_column(
        RecordTimestamp, default=utc_now, server_default=func.current_timestamp()
    )
    updated: Mapped[datetime] = mapped_column(
        RecordTimestamp,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.current_timestamp(),
    )
    deleted: Mapped[datetime | None] = mapped_column(RecordTimestamp, default=None)

    name_index: Mapped[bytes] = mapped_column(LargeBinary)
    document: Mapped[bytes] = mapped_column(LargeBinary)
    backed_up: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )


class AttachmentModel(BaseModel):
    __tablename__ = "attachments"
    __table_args__ = (
        CheckConstraint("length(uid) = 16", name="ck_attachments_uid"),
        CheckConstraint("size_bytes > 0", name="ck_attachments_size"),
        {"sqlite_autoincrement": True},
    )

    def __init__(self, **fields: object) -> None:
        fields.setdefault("uid", new_uid())
        super().__init__(**fields)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created: Mapped[datetime] = mapped_column(
        RecordTimestamp, default=utc_now, server_default=func.current_timestamp()
    )
    entry_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("entries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    size_bytes: Mapped[int] = mapped_column(Integer)
    meta: Mapped[bytes] = mapped_column(LargeBinary)
    content: Mapped[bytes] = mapped_column(LargeBinary)


class SettingsModel(BaseModel):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created: Mapped[datetime] = mapped_column(
        TIMESTAMP, default=utc_now, server_default=func.current_timestamp()
    )
    updated: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.current_timestamp(),
    )

    inactivity_ms: Mapped[int] = mapped_column(Integer)
    warn_before_ms: Mapped[int] = mapped_column(Integer)
    hidden_ms: Mapped[int] = mapped_column(Integer)
    debounce_ms: Mapped[int] = mapped_column(Integer)
    clipboard_clear_ms: Mapped[int] = mapped_column(Integer)
    update_check_enabled: Mapped[bool] = mapped_column(Boolean)
