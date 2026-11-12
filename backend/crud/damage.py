import logging
from typing import Literal

from sqlalchemy import select

from crud.base import BaseCRUD
from crud.records import open_attachment_content, open_attachment_metadata, open_entry
from errors import InvalidRequest, NotFound, VaultDamaged
from helpers import VaultKey
from models import AttachmentModel, EntryModel
from schemas import DamagedRows, PasswordDelete

logger = logging.getLogger(__name__)

DamagedKind = Literal["entries", "attachments"]


def entry_is_damaged(key: VaultKey, entry: EntryModel) -> bool:
    try:
        open_entry(key, entry)
    except VaultDamaged:
        return True
    return False


class DamageCRUD(BaseCRUD):
    """
    Rows that fail authenticated decryption or their format check. Listings
    skip them so the rest of the vault stays usable; this finds them and
    removes one only after checking, under the write lock, that it really
    cannot be read. Backups and master password changes refuse to run while
    any remain.
    """

    @staticmethod
    def _attachment_is_damaged(
        key: VaultKey, attachment: AttachmentModel, entry_uid: bytes | None
    ) -> bool:
        if entry_uid is None:
            return True
        try:
            open_attachment_metadata(key, attachment, entry_uid)
            open_attachment_content(key, attachment, entry_uid)
        except VaultDamaged:
            return True
        return False

    async def find(self, key: VaultKey) -> DamagedRows:
        entries = [
            entry.id
            for entry in (
                await self.session.scalars(select(EntryModel).order_by(EntryModel.id))
            )
            if entry_is_damaged(key, entry)
        ]
        attachments = []
        # Stream one attachment at a time, including its parent's binding UID,
        # so the scan neither buffers the vault's file bytes nor queries per file.
        rows = await self.session.stream(
            select(AttachmentModel, EntryModel.uid)
            .outerjoin(EntryModel, AttachmentModel.entry_id == EntryModel.id)
            .order_by(AttachmentModel.id),
            execution_options={"yield_per": 1},
        )
        try:
            async for attachment, entry_uid in rows:
                if self._attachment_is_damaged(key, attachment, entry_uid):
                    attachments.append(attachment.id)
                self.session.expunge(attachment)
        finally:
            await rows.close()
        return DamagedRows(entries=entries, attachments=attachments)

    async def remove(
        self, key: VaultKey, kind: DamagedKind, row_id: int
    ) -> PasswordDelete:
        if kind == "entries":
            row = await self.session.get(EntryModel, row_id)
            damaged = row is not None and entry_is_damaged(key, row)
        else:
            row = await self.session.get(AttachmentModel, row_id)
            entry_uid = (
                await self.session.scalar(
                    select(EntryModel.uid).where(EntryModel.id == row.entry_id)
                )
                if row is not None
                else None
            )
            damaged = row is not None and self._attachment_is_damaged(
                key, row, entry_uid
            )
        if row is None:
            raise NotFound("No such row.")
        if not damaged:
            raise InvalidRequest("That row is not damaged; nothing was removed.")
        await self.session.delete(row)
        await self.session.flush()
        logger.warning("Removed damaged %s row #%s.", kind, row_id)
        return PasswordDelete(deleted=True, detail="Damaged row removed.")
