import logging

from sqlalchemy import func, select
from sqlalchemy.orm import defer

from crud.base import BaseCRUD
from crud.records import (
    AttachmentMetadata,
    find_entry,
    open_attachment_content,
    open_attachment_metadata,
    seal_attachment,
)
from errors import InvalidRequest, NotFound, VaultDamaged
from helpers import VaultKey
from models import AttachmentModel, EntryModel
from schemas import AttachmentResponse

logger = logging.getLogger(__name__)

MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_ATTACHMENTS_PER_ENTRY = 20
MAX_TOTAL_BYTES = 25 * 1024 * 1024


class AttachmentCRUD(BaseCRUD):
    async def _get_attachment(
        self, entry_id: int, attachment_id: int
    ) -> AttachmentModel:
        model = (
            await self.session.execute(
                select(AttachmentModel).where(
                    AttachmentModel.id == attachment_id,
                    AttachmentModel.entry_id == entry_id,
                )
            )
        ).scalar()
        if not model:
            raise NotFound("Attachment not found.")
        return model

    @staticmethod
    def _to_response(
        model: AttachmentModel, metadata: AttachmentMetadata
    ) -> AttachmentResponse:
        return AttachmentResponse(
            id=model.id,
            filename=metadata.filename,
            content_type=metadata.content_type,
            size_bytes=model.size_bytes,
            created=model.created,
        )

    async def list_attachments(
        self, password_name: str, key: VaultKey
    ) -> list[AttachmentResponse]:
        entry, _ = await find_entry(self.session, key, password_name)
        models = (
            await self.session.execute(
                select(AttachmentModel)
                .options(defer(AttachmentModel.content, raiseload=True))
                .where(AttachmentModel.entry_id == entry.id)
                .order_by(AttachmentModel.created, AttachmentModel.id)
            )
        ).scalars()
        listed = []
        for model in models:
            try:
                metadata = open_attachment_metadata(key, model, entry.uid)
            except VaultDamaged:
                logger.warning(
                    "Attachment #%s failed its integrity check; skipped.", model.id
                )
                continue
            listed.append(self._to_response(model, metadata))
        return listed

    async def add_attachment(
        self,
        password_name: str,
        filename: str,
        content_type: str | None,
        data: bytes,
        key: VaultKey,
    ) -> AttachmentResponse:
        if not data:
            raise InvalidRequest("Attachment is empty.")
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise InvalidRequest("Attachment too large. Maximum size is 5 MB.")

        entry, _ = await find_entry(self.session, key, password_name)
        await self.check_capacity(entry, len(data))

        model = AttachmentModel(entry_id=entry.id)
        metadata = AttachmentMetadata(filename=filename, content_type=content_type)
        seal_attachment(key, model, entry.uid, metadata, data)
        self.session.add(model)
        await self.session.flush()
        return self._to_response(model, metadata)

    async def check_capacity(self, entry: EntryModel, size: int) -> None:
        count, used = (
            await self.session.execute(
                select(
                    func.count(), func.coalesce(func.sum(AttachmentModel.size_bytes), 0)
                ).where(AttachmentModel.entry_id == entry.id)
            )
        ).one()
        if count >= MAX_ATTACHMENTS_PER_ENTRY:
            raise InvalidRequest(
                f"This entry already has the maximum of "
                f"{MAX_ATTACHMENTS_PER_ENTRY} attachments."
            )
        if used + size > MAX_TOTAL_BYTES:
            raise InvalidRequest(
                "Attachments for this entry would exceed the 25 MB total limit."
            )

    async def get_attachment_data(
        self, password_name: str, attachment_id: int, key: VaultKey
    ) -> tuple[str, str | None, bytes]:
        entry, _ = await find_entry(self.session, key, password_name)
        model = await self._get_attachment(entry.id, attachment_id)
        metadata = open_attachment_metadata(key, model, entry.uid)
        data = open_attachment_content(key, model, entry.uid)
        return metadata.filename, metadata.content_type, data

    async def delete_attachment(
        self, password_name: str, attachment_id: int, key: VaultKey
    ) -> None:
        entry, _ = await find_entry(self.session, key, password_name)
        model = await self._get_attachment(entry.id, attachment_id)
        await self.session.delete(model)
        await self.session.flush()
