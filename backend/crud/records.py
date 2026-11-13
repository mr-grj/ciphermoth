import hmac
import json
from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    TypeAdapter,
    ValidationError,
    field_validator,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backup_format import MAX_ENTRY_STORED_BYTES
from errors import InvalidRequest, NotFound, VaultDamaged
from helpers import DecryptionFailed, VaultKey
from models import AttachmentModel, EntryModel

_DAMAGED = (
    "{what} in the vault file failed its integrity check, so it was not read. The "
    "file was damaged or altered: restore a snapshot (docs/UPDATING.md), or "
    "remove the damaged rows (GET /api/vault/damaged, `ciphermoth damaged`)."
)


_TIMESTAMP = TypeAdapter(datetime)


def history_timestamp(value: str) -> str:
    """A history time the API's response model can read back: validated with
    the same parser (``PasswordHistoryEntry.changed_at``), so a value Python's
    ``fromisoformat`` accepts but pydantic does not can never be stored."""
    _TIMESTAMP.validate_python(value)
    return value


def damaged(what: str) -> VaultDamaged:
    return VaultDamaged(_DAMAGED.format(what=what))


class _Strict(BaseModel):
    # Keep plaintext record values out of pydantic's parser string cache.
    model_config = ConfigDict(extra="forbid", strict=True, cache_strings=False)


class StoredField(_Strict):
    label: str
    value: str
    hidden: bool


class HistoryItem(_Strict):
    value: str
    changed_at: str

    @field_validator("changed_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return history_timestamp(value)


class EntryDocument(_Strict):
    """
    The encrypted content of one entry, exactly as vault format 2 stores it
    (docs/VAULT_FORMAT.md). Every key is required and nothing else is allowed,
    so a document this release did not write is refused instead of guessed at.
    """

    name: str
    kind: Literal["login", "note"]
    username: str | None
    value: str
    url: str | None
    totp_secret: str | None
    description: str | None
    tags: list[str]
    custom_fields: list[StoredField]
    folder: str | None
    favorite: bool
    history: list[HistoryItem]

    def encode(self) -> bytes:
        return self.model_dump_json().encode()


class AttachmentMetadata(_Strict):
    filename: str
    content_type: str | None

    def encode(self) -> bytes:
        return self.model_dump_json().encode()


def _decode[T: BaseModel](model: type[T], raw: bytes) -> T:
    return model.model_validate(json.loads(raw.decode()), strict=True)


def open_entry(key: VaultKey, entry: EntryModel) -> EntryDocument:
    """Decrypt and check one entry. Its name must hash to the row's name index,
    so a document copied into another row, or an index pointed at another
    entry, is refused."""
    if not (
        isinstance(entry.created, datetime)
        and isinstance(entry.updated, datetime)
        and (entry.deleted is None or isinstance(entry.deleted, datetime))
    ):
        raise damaged(f"Entry #{entry.id}")
    try:
        document = _decode(EntryDocument, key.open_entry(entry.uid, entry.document))
    except (DecryptionFailed, ValidationError, ValueError) as error:
        raise damaged(f"Entry #{entry.id}") from error
    stored_index = entry.name_index
    if not isinstance(stored_index, bytes) or not hmac.compare_digest(
        key.name_index(document.name), stored_index
    ):
        raise damaged(f"Entry #{entry.id}")
    return document


def seal_entry(key: VaultKey, entry: EntryModel, document: EntryDocument) -> None:
    encoded = document.encode()
    if len(encoded) > MAX_ENTRY_STORED_BYTES:
        raise InvalidRequest("This entry exceeds the 64 MiB per-entry backup capacity.")
    entry.name_index = key.name_index(document.name)
    entry.document = key.seal_entry(entry.uid, encoded)


def open_attachment_metadata(
    key: VaultKey, attachment: AttachmentModel, entry_uid: bytes
) -> AttachmentMetadata:
    if not (
        isinstance(attachment.created, datetime)
        and type(attachment.size_bytes) is int
        and attachment.size_bytes > 0
    ):
        raise damaged(f"Attachment #{attachment.id}")
    try:
        return _decode(
            AttachmentMetadata,
            key.open_attachment_metadata(attachment.uid, entry_uid, attachment.meta),
        )
    except (DecryptionFailed, ValidationError, ValueError) as error:
        raise damaged(f"Attachment #{attachment.id}") from error


def open_attachment_content(
    key: VaultKey, attachment: AttachmentModel, entry_uid: bytes
) -> bytes:
    try:
        content = key.open_attachment_content(
            attachment.uid, entry_uid, attachment.content
        )
    except DecryptionFailed as error:
        raise damaged(f"Attachment #{attachment.id}") from error
    if not isinstance(attachment.size_bytes, int) or len(content) != (
        attachment.size_bytes
    ):
        raise damaged(f"Attachment #{attachment.id}")
    return content


def seal_attachment(
    key: VaultKey,
    attachment: AttachmentModel,
    entry_uid: bytes,
    metadata: AttachmentMetadata,
    content: bytes,
) -> None:
    if len(metadata.encode()) > 2048:
        raise InvalidRequest("Attachment metadata exceeds the 2 KiB limit.")
    attachment.size_bytes = len(content)
    attachment.meta = key.seal_attachment_metadata(
        attachment.uid, entry_uid, metadata.encode()
    )
    attachment.content = key.seal_attachment_content(attachment.uid, entry_uid, content)


async def find_entry(
    session: AsyncSession,
    key: VaultKey,
    name: str,
    *,
    deleted: bool = False,
    entry_id: int | None = None,
) -> tuple[EntryModel, EntryDocument]:
    """
    The active entry named ``name`` (or, with ``deleted``, the most recently
    trashed one), found through its name index and checked after decryption.
    """
    trashed = (
        EntryModel.deleted.is_not(None) if deleted else EntryModel.deleted.is_(None)
    )
    model = None
    if "\x00" not in name:
        identity = [] if entry_id is None else [EntryModel.id == entry_id]
        model = (
            await session.execute(
                select(EntryModel)
                .where(
                    EntryModel.name_index == key.name_index(name), trashed, *identity
                )
                .order_by(EntryModel.deleted.desc(), EntryModel.id.desc())
                .limit(1)
            )
        ).scalar()
    if model is None:
        where = "trash" if deleted else "vault"
        raise NotFound(f"No password found for '{name}' in the {where}.")
    document = open_entry(key, model)
    if document.name != name:
        raise damaged(f"Entry #{model.id}")
    return model, document


async def active_entry_exists(session: AsyncSession, key: VaultKey, name: str) -> bool:
    found = await session.scalar(
        select(EntryModel.id).where(
            EntryModel.name_index == key.name_index(name),
            EntryModel.deleted.is_(None),
        )
    )
    return found is not None
