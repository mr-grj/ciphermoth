import csv
import io
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from crud.base import BaseCRUD
from crud.records import (
    EntryDocument,
    HistoryItem,
    StoredField,
    active_entry_exists,
    find_entry,
    open_entry,
    seal_entry,
)
from errors import InvalidRequest, VaultDamaged
from helpers import VaultKey
from models import AttachmentModel, EntryModel, utc_now
from schemas import (
    BulkResult,
    ImportRowReport,
    OnConflict,
    Password,
    PasswordCreate,
    PasswordDelete,
    PasswordImportResult,
    PasswordResponse,
    PasswordUpdate,
    RestoredPassword,
    TrashedEntryRef,
)
from validators import normalize_totp_secret, normalize_totp_secret_leniently

Imported = Password | RestoredPassword

logger = logging.getLogger(__name__)

HISTORY_LIMIT = 10
_CSV_FIELD_SIZE_LIMIT = 16 * 1024 * 1024
_REPORTED_IMPORT_PROBLEMS = 3
SOURCE_KEYS = {"password_name": "name", "password_value": "value"}
_REPORTED_IGNORED_ROWS = 100
_CSV_NOTE_TYPES = ("note", "secure note", "securenote", "secure_note")
_CSV_UNSUPPORTED_TYPES = (
    "card",
    "creditcard",
    "credit card",
    "identity",
    "alias",
    "sshkey",
    "ssh key",
    "ssh_key",
)
_MAX_NAME_LENGTH = 255
_NAME_TAKEN = "A password with that name already exists."


def _entries_word(count: int) -> str:
    return f"{count} {'entry' if count == 1 else 'entries'}"


csv.field_size_limit(_CSV_FIELD_SIZE_LIMIT)

_CSV_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "name": ("name", "title", "account", "login_name", "item name"),
    "username": ("username", "login_username", "user", "email", "login", "e-mail"),
    "value": ("password", "login_password", "pass"),
    "url": ("url", "uri", "login_uri", "website", "web site", "site", "link"),
    "description": ("notes", "note", "description", "comment", "comments", "extra"),
    "folder": ("folder", "grouping", "group", "category", "collection"),
    "type": ("type", "item type", "item_type"),
    "totp_secret": (
        "totp",
        "login_totp",
        "otpauth",
        "otp",
        "2fa",
        "otp_auth",
        "totpauth",
    ),
}


@dataclass(frozen=True)
class Ignored:
    name: object
    reason: str


ImportRow = tuple[str, dict[str, object] | Ignored | None]


def document_from(
    password: Imported, history: list[HistoryItem] | None = None
) -> EntryDocument:
    return EntryDocument(
        name=password.password_name,
        kind="note" if password.kind == "note" else "login",
        username=password.username,
        value=password.password_value,
        url=password.url,
        totp_secret=password.totp_secret,
        description=password.description,
        tags=list(password.tags),
        custom_fields=[
            StoredField(label=field.label, value=field.value, hidden=field.hidden)
            for field in password.custom_fields
        ],
        folder=password.folder or None,
        favorite=password.favorite,
        history=history or [],
    )


def normalize_custom_fields(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        return []
    fields: list[dict[str, object]] = []
    for item in raw:
        if isinstance(item, dict) and item.get("label"):
            fields.append(
                {
                    "label": str(item.get("label")),
                    "value": str(item.get("value", "")),
                    "hidden": bool(item.get("hidden", False)),
                }
            )
    return fields


class PasswordCRUD(BaseCRUD):
    async def flush_or_conflict(self, conflict: str) -> None:
        try:
            await self.session.flush()
        except IntegrityError as e:
            raise InvalidRequest(conflict) from e

    @staticmethod
    def to_response(
        model: EntryModel, document: EntryDocument, attachment_count: int = 0
    ) -> PasswordResponse:
        return PasswordResponse(
            id=model.id,
            password_name=document.name,
            kind=document.kind,
            username=document.username,
            password_value=document.value,
            url=document.url,
            totp_secret=normalize_totp_secret_leniently(document.totp_secret),
            description=document.description,
            tags=document.tags,
            custom_fields=[field.model_dump() for field in document.custom_fields],
            folder=document.folder or None,
            favorite=document.favorite,
            backed_up=model.backed_up,
            updated=model.updated,
            deleted=model.deleted,
            password_history=[item.model_dump() for item in document.history],
            attachment_count=attachment_count,
        )

    async def _attachment_counts(self, entry_ids: list[int]) -> dict[int, int]:
        if not entry_ids:
            return {}
        rows = (
            await self.session.execute(
                select(AttachmentModel.entry_id, func.count())
                .where(AttachmentModel.entry_id.in_(entry_ids))
                .group_by(AttachmentModel.entry_id)
            )
        ).all()
        return {entry_id: count for entry_id, count in rows}

    async def _listed(self, key: VaultKey, *, deleted: bool) -> list[PasswordResponse]:
        stmt = select(EntryModel)
        if deleted:
            stmt = stmt.where(EntryModel.deleted.is_not(None)).order_by(
                EntryModel.deleted.desc(), EntryModel.id.desc()
            )
        else:
            stmt = stmt.where(EntryModel.deleted.is_(None))
        models = list((await self.session.execute(stmt)).scalars())
        counts = await self._attachment_counts([m.id for m in models])
        responses = []
        for model in models:
            try:
                document = open_entry(key, model)
            except VaultDamaged:
                logger.warning("Entry #%s is damaged; not listed.", model.id)
                continue
            responses.append(self.to_response(model, document, counts.get(model.id, 0)))
        if not deleted:
            responses.sort(key=lambda response: response.password_name)
        return responses

    async def get_passwords(self, key: VaultKey) -> list[PasswordResponse]:
        return await self._listed(key, deleted=False)

    async def get_trash(self, key: VaultKey) -> list[PasswordResponse]:
        return await self._listed(key, deleted=True)

    async def get_password(self, password_name: str, key: VaultKey) -> PasswordResponse:
        model, document = await find_entry(self.session, key, password_name)
        count = (await self._attachment_counts([model.id])).get(model.id, 0)
        return self.to_response(model, document, count)

    async def create_password(
        self, password: Password, key: VaultKey
    ) -> PasswordCreate:
        model = EntryModel()
        seal_entry(key, model, document_from(password))
        self.session.add(model)
        await self.flush_or_conflict(_NAME_TAKEN)
        return PasswordCreate(created=True, detail="Password created successfully.")

    async def update_password(
        self, password_name: str, new_password: Password, key: VaultKey
    ) -> PasswordUpdate:
        model, current = await find_entry(self.session, key, password_name)

        if current.name != new_password.password_name and await active_entry_exists(
            self.session, key, new_password.password_name
        ):
            raise InvalidRequest(_NAME_TAKEN)

        history = list(current.history)
        if (
            current.value != new_password.password_value
            and new_password.kind == "login"
        ):
            history.insert(
                0,
                HistoryItem(
                    value=current.value, changed_at=datetime.now(UTC).isoformat()
                ),
            )
            del history[HISTORY_LIMIT:]

        seal_entry(key, model, document_from(new_password, history))
        model.backed_up = False
        await self.flush_or_conflict(_NAME_TAKEN)
        return PasswordUpdate(updated=True, detail="Password updated successfully.")

    async def set_favorite(
        self, password_name: str, favorite: bool, key: VaultKey
    ) -> PasswordUpdate:
        model, document = await find_entry(self.session, key, password_name)
        seal_entry(key, model, document.model_copy(update={"favorite": favorite}))
        await self.session.flush()
        detail = "Added to favorites." if favorite else "Removed from favorites."
        return PasswordUpdate(updated=True, detail=detail)

    async def delete_password(
        self, password_name: str, key: VaultKey
    ) -> PasswordDelete:
        model, _ = await find_entry(self.session, key, password_name)
        model.deleted = datetime.now(UTC).replace(tzinfo=None)
        await self.session.flush()
        return PasswordDelete(deleted=True, detail="Password moved to trash.")

    async def restore_password(
        self, password_name: str, key: VaultKey, *, entry_id: int | None = None
    ) -> PasswordUpdate:
        model, _ = await find_entry(
            self.session, key, password_name, deleted=True, entry_id=entry_id
        )
        conflict = (
            f"An active password named '{password_name}' already exists. "
            "Rename or delete it before restoring."
        )
        if await active_entry_exists(self.session, key, password_name):
            raise InvalidRequest(conflict)
        model.deleted = None
        await self.flush_or_conflict(conflict)
        return PasswordUpdate(updated=True, detail="Password restored from trash.")

    async def purge_password(
        self, password_name: str, key: VaultKey, *, entry_id: int | None = None
    ) -> PasswordDelete:
        model, _ = await find_entry(
            self.session, key, password_name, deleted=True, entry_id=entry_id
        )
        await self.session.delete(model)
        await self.session.flush()
        return PasswordDelete(deleted=True, detail="Password permanently deleted.")

    async def trash_passwords(self, names: Sequence[str], key: VaultKey) -> BulkResult:
        """
        Move every named active entry to the trash in one transaction: one
        missing or unreadable entry refuses them all.
        """
        now = utc_now()
        for name in names:
            model, _ = await find_entry(self.session, key, name)
            model.deleted = now
        await self.session.flush()
        return BulkResult(
            count=len(names),
            detail=_entries_word(len(names)) + " moved to trash.",
        )

    async def restore_passwords(
        self, targets: Sequence[TrashedEntryRef], key: VaultKey
    ) -> BulkResult:
        """
        Restore every listed trashed entry, or none: a name that is active, or
        listed twice, would leave two active entries with one name.
        """
        restoring: set[bytes] = set()
        for target in targets:
            name = target.password_name
            model, _ = await find_entry(
                self.session, key, name, deleted=True, entry_id=target.entry_id
            )
            if model.name_index in restoring:
                raise InvalidRequest(
                    f"More than one selected entry is named '{name}'. "
                    "Restore one of them at a time."
                )
            if await active_entry_exists(self.session, key, name):
                raise InvalidRequest(
                    f"An active password named '{name}' already exists. "
                    "Rename or delete it before restoring."
                )
            restoring.add(model.name_index)
            model.deleted = None
        await self.flush_or_conflict(_NAME_TAKEN)
        return BulkResult(
            count=len(targets), detail=_entries_word(len(targets)) + " restored."
        )

    async def purge_passwords(
        self, targets: Sequence[TrashedEntryRef], key: VaultKey
    ) -> BulkResult:
        """Permanently delete every listed trashed entry and its attachments."""
        for target in targets:
            model, _ = await find_entry(
                self.session,
                key,
                target.password_name,
                deleted=True,
                entry_id=target.entry_id,
            )
            await self.session.delete(model)
        await self.session.flush()
        return BulkResult(
            count=len(targets),
            detail=_entries_word(len(targets)) + " permanently deleted.",
        )

    async def _upsert_entry(
        self,
        existing: dict[bytes, EntryModel],
        key: VaultKey,
        on_conflict: OnConflict,
        password: Imported,
    ) -> str:
        """
        Add one imported entry. An entry it overwrites is moved to the trash,
        with its history and attachments, and the imported one takes its name,
        so an import never destroys anything.
        """
        index = key.name_index(password.password_name)
        current = existing.get(index)
        outcome = "imported"
        if current is not None:
            open_entry(key, current)
            if on_conflict == OnConflict.skip:
                return "skipped"
            current.deleted = utc_now()
            await self.session.flush()
            outcome = "overwritten"
        model = EntryModel()
        seal_entry(key, model, document_from(password))
        self.session.add(model)
        existing[index] = model
        return outcome

    async def load_active(self) -> dict[bytes, EntryModel]:
        return {
            model.name_index: model
            for model in (
                await self.session.execute(
                    select(EntryModel).where(EntryModel.deleted.is_(None))
                )
            ).scalars()
        }

    @staticmethod
    def validate_import(
        rows: Iterable[ImportRow],
        label_for: Callable[[str], str],
        schema: type[Imported] = Password,
    ) -> tuple[list[tuple[str, Imported]], list[ImportRowReport]]:
        """
        Validate every row before anything is written, so an import either stores
        data the vault can read back or stores nothing. CSV rows use the create
        endpoint's schema; backups use RestoredPassword. Problems name the row and
        column, never the value. Rows that hold no importable entry (blank rows
        excepted) are returned as ignored, with the reason, for the report.
        """
        valid: list[tuple[str, Imported]] = []
        ignored: list[ImportRowReport] = []
        problems: list[str] = []
        for where, fields in rows:
            if fields is None:
                continue
            if isinstance(fields, Ignored):
                name = fields.name if isinstance(fields.name, str) else None
                ignored.append(
                    ImportRowReport(
                        where=where, name=name and name[:100], reason=fields.reason
                    )
                )
                continue
            try:
                valid.append((where, schema.model_validate(fields)))
            except ValidationError as e:
                error = e.errors()[0]
                field = str(error["loc"][0]) if error["loc"] else "entry"
                problems.append(f"{where} ({label_for(field)}): {error['msg']}")
        if problems:
            shown = "; ".join(problems[:_REPORTED_IMPORT_PROBLEMS])
            more = len(problems) - _REPORTED_IMPORT_PROBLEMS
            suffix = f"; and {more} more" if more > 0 else ""
            raise InvalidRequest(f"Nothing was imported. {shown}{suffix}.")
        return valid, ignored

    async def _store_import(
        self,
        passwords: list[tuple[str, Imported]],
        ignored: list[ImportRowReport],
        key: VaultKey,
        on_conflict: OnConflict,
    ) -> PasswordImportResult:
        """
        Store validated rows. A name that appears again later in the same file is
        imported under a unique name ('name (2)') and reported, so two exported
        accounts for one site never collapse into one entry.
        """
        existing = await self.load_active()
        taken = set(existing)
        seen: set[bytes] = set()
        renamed: list[ImportRowReport] = []
        counts = {"imported": 0, "skipped": 0, "overwritten": 0}
        for where, password in passwords:
            name = password.password_name
            if key.name_index(name) in seen:
                unique = self._unique_name(name, taken, key)
                renamed.append(
                    ImportRowReport(
                        where=where,
                        name=name[:100],
                        reason=f"imported as '{unique[:120]}' because the file "
                        "has another entry with this name",
                    )
                )
                password = password.model_copy(update={"password_name": unique})
            index = key.name_index(password.password_name)
            seen.add(index)
            taken.add(index)
            counts[await self._upsert_entry(existing, key, on_conflict, password)] += 1
        await self.flush_or_conflict(
            "An entry with the same name was added while importing. "
            "Nothing was imported; try again."
        )
        return self.result(counts, ignored, renamed)

    @staticmethod
    def _unique_name(name: str, taken: set[bytes], key: VaultKey) -> str:
        limit = max(_MAX_NAME_LENGTH, len(name))
        number = 2
        while True:
            suffix = f" ({number})"
            candidate = name[: limit - len(suffix)] + suffix
            if key.name_index(candidate) not in taken:
                return candidate
            number += 1

    @classmethod
    def _csv_fields(
        cls, row: dict[str, str], column_for: dict[str, list[str]]
    ) -> dict[str, object] | Ignored | None:
        if not any(isinstance(cell, str) and cell.strip() for cell in row.values()):
            return None
        name = cls._csv_cell(row, column_for, "name")
        item_type = cls._csv_cell(row, column_for, "type") or ""
        if item_type.lower() in _CSV_NOTE_TYPES:
            body = cls._csv_cell(row, column_for, "description", strip=False)
            if not name:
                return Ignored(None, "secure note without a name")
            if not body or not body.strip():
                return Ignored(name, "secure note without text")
            return {
                "password_name": name,
                "kind": "note",
                "password_value": body,
                "folder": cls._csv_cell(row, column_for, "folder"),
            }
        if item_type.lower() in _CSV_UNSUPPORTED_TYPES:
            return Ignored(name, f"'{item_type[:40]}' items can't be imported")
        value = cls._csv_cell(row, column_for, "value", strip=False)
        if not name:
            return Ignored(None, "no name")
        if not value:
            return Ignored(name, "no password")
        return {
            "password_name": name,
            "password_value": value,
            "username": cls._csv_cell(row, column_for, "username"),
            "url": cls._csv_cell(row, column_for, "url"),
            "totp_secret": cls._csv_totp(row, column_for),
            "description": cls._csv_cell(row, column_for, "description"),
            "folder": cls._csv_cell(row, column_for, "folder"),
        }

    async def import_passwords_csv(
        self,
        file_bytes: bytes,
        key: VaultKey,
        on_conflict: OnConflict,
    ) -> PasswordImportResult:
        try:
            text = file_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise InvalidRequest("CSV file must be UTF-8 encoded.") from e

        reader = csv.DictReader(io.StringIO(text, newline=""))
        try:
            fieldnames = reader.fieldnames
            rows = list(reader)
        except csv.Error as e:
            raise InvalidRequest(
                f"Could not read the CSV file near line {reader.line_num}."
            ) from e
        if not fieldnames:
            raise InvalidRequest("CSV file has no header row.")

        column_for = self._map_csv_columns(fieldnames)
        if "name" not in column_for or "value" not in column_for:
            raise InvalidRequest(
                "CSV must have a name/title column and a password column."
            )

        passwords, ignored = self.validate_import(
            (
                (f"row {index}", self._csv_fields(row, column_for))
                for index, row in enumerate(rows, start=2)
            ),
            label_for=lambda field: column_for.get(
                SOURCE_KEYS.get(field, field), [field]
            )[0],
        )
        return await self._store_import(passwords, ignored, key, on_conflict)

    @staticmethod
    def _map_csv_columns(fieldnames: Sequence[str]) -> dict[str, list[str]]:
        normalized = {(name or "").strip().lower(): name for name in fieldnames}
        return {
            field: columns
            for field, aliases in _CSV_FIELD_ALIASES.items()
            if (
                columns := [
                    normalized[alias] for alias in aliases if alias in normalized
                ]
            )
        }

    @staticmethod
    def _csv_cell(
        row: dict[str, str],
        column_for: dict[str, list[str]],
        field: str,
        *,
        strip: bool = True,
    ) -> str | None:
        for column in column_for.get(field, ()):
            raw = row.get(column) or ""
            value = raw.strip() if strip else raw
            if value:
                return value
        return None

    @staticmethod
    def _csv_totp(row: dict[str, str], column_for: dict[str, list[str]]) -> str | None:
        raw = PasswordCRUD._csv_cell(row, column_for, "totp_secret")
        try:
            return normalize_totp_secret(raw)
        except ValueError:
            return None

    @staticmethod
    def result(
        counts: dict[str, int],
        ignored: list[ImportRowReport],
        renamed: list[ImportRowReport],
    ) -> PasswordImportResult:
        return PasswordImportResult(
            imported=counts["imported"],
            skipped=counts["skipped"],
            overwritten=counts["overwritten"],
            total=counts["imported"] + counts["skipped"] + counts["overwritten"],
            ignored=len(ignored),
            ignored_rows=ignored[:_REPORTED_IGNORED_ROWS],
            renamed=len(renamed),
            renamed_rows=renamed[:_REPORTED_IGNORED_ROWS],
        )
