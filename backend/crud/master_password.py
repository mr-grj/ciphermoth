import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from crud.base import BaseCRUD
from crud.records import (
    damaged,
    open_attachment_content,
    open_attachment_metadata,
    open_entry,
    seal_attachment,
    seal_entry,
)
from errors import Forbidden, InvalidKey, InvalidRequest, NotFound
from helpers import (
    FORMAT_VERSION,
    KDF_NAME,
    DecryptionFailed,
    KdfParams,
    KeyMaterial,
    UnsupportedKdf,
    VaultKey,
    create_key_material,
    unlock_key_material,
    wrap_key_for_device,
)
from models import AttachmentModel, EntryModel, VaultModel
from schemas import MasterPasswordUpdate

logger = logging.getLogger(__name__)

_INVALID_KEY = "Invalid or expired vault key. Unlock the vault again."

_DAMAGED = (
    "The vault's key record does not verify with this master password. The vault "
    "file may be damaged; restore a snapshot (docs/UPDATING.md)."
)


async def fetch_vault(session: AsyncSession) -> VaultModel | None:
    stmt = (
        select(VaultModel)
        .where(VaultModel.id == 1)
        .execution_options(populate_existing=True)
    )
    return (await session.execute(stmt)).scalar()


def key_material(model: VaultModel) -> KeyMaterial:
    # SQLite affinity is not a type check. In particular bytes(integer) allocates
    # that many zeroes; never coerce hostile scalar values from the file.
    for value, length in (
        (model.kdf_salt, 16),
        (model.password_check, 32),
        (model.wrapped_key, 61),
        (model.key_check, 32),
    ):
        if not isinstance(value, bytes) or len(value) != length:
            raise InvalidRequest(_DAMAGED)
    return KeyMaterial(
        params=KdfParams(model.kdf_memory_kib, model.kdf_iterations, model.kdf_lanes),
        salt=model.kdf_salt,
        password_check=model.password_check,
        wrapped_key=model.wrapped_key,
        key_check=model.key_check,
    )


def _store(model: VaultModel, material: KeyMaterial) -> None:
    model.format_version = FORMAT_VERSION
    model.kdf = KDF_NAME
    model.kdf_memory_kib = material.params.memory_kib
    model.kdf_iterations = material.params.iterations
    model.kdf_lanes = material.params.lanes
    model.kdf_salt = material.salt
    model.password_check = material.password_check
    model.wrapped_key = material.wrapped_key
    model.key_check = material.key_check


class MasterPasswordCRUD(BaseCRUD):
    async def is_initialized(self) -> bool:
        return await fetch_vault(self.session) is not None

    async def _get_model(self) -> VaultModel:
        model = await fetch_vault(self.session)
        if not model:
            raise NotFound("No master password found.")
        if model.format_version != FORMAT_VERSION or model.kdf != KDF_NAME:
            raise InvalidRequest(
                "The vault uses a key format this release cannot read."
            )
        return model

    @staticmethod
    async def _open(master_password: str, material: KeyMaterial) -> VaultKey | None:
        try:
            return await unlock_key_material(master_password, material)
        except UnsupportedKdf as error:
            raise InvalidRequest(str(error)) from None
        except DecryptionFailed:
            logger.error("The vault key record failed to verify.")
            raise InvalidRequest(_DAMAGED) from None

    async def verify_vault_key(self, key: VaultKey | None) -> VaultKey:
        """
        Check that ``key`` belongs to the current vault key, inside the
        request's transaction. Write requests run under SQLite's write lock from
        their first statement (BEGIN IMMEDIATE), so a master password change can
        never commit between this check and their writes; read requests see the
        key check and the rows of one snapshot.
        """
        if key is None:
            raise InvalidKey("Vault key is missing.")
        model = await fetch_vault(self.session)
        if model is None:
            raise Forbidden("No master password set.")
        if not key.matches(model.key_check):
            raise InvalidKey(_INVALID_KEY)
        return key

    async def unlock(self, master_password: str) -> VaultKey | None:
        """
        Return the vault key for ``master_password``, or None if it is wrong.

        The transaction is ended before the slow KDF so a queue of unlocks holds
        no connection and no lock. The key is then confirmed against the current
        key check, so a password that a concurrent change has just replaced is
        refused instead of opening a session every route would reject.
        """
        material = key_material(await self._get_model())
        await self.session.commit()
        key = await self._open(master_password, material)
        if key is None:
            return None
        current = await fetch_vault(self.session)
        if current is None or not key.matches(current.key_check):
            return None
        return key

    async def create_master_password(self, master_password: str) -> VaultKey:
        if await self.is_initialized():
            raise Forbidden("Master password already exists.")
        if (
            await self.session.scalar(select(EntryModel.id).limit(1)) is not None
            or await self.session.scalar(select(AttachmentModel.id).limit(1))
            is not None
        ):
            raise InvalidRequest(
                "The vault file holds records but no key record, so it is damaged. "
                "Restore a snapshot, or move it aside with 'ciphermoth-admin "
                "set-aside' to start a new vault (docs/UPDATING.md)."
            )
        await self.session.commit()
        material, key = await create_key_material(master_password)

        if await self.is_initialized():
            raise Forbidden("Master password already exists.")

        model = VaultModel(id=1)
        _store(model, material)
        self.session.add(model)
        await self.session.flush()
        return key

    async def check_master_password(self, master_password: str) -> VaultKey:
        """
        Check the master password a backup asks for and return the key it
        opens. The transaction is ended first, so the KDF never holds the write
        lock; ``confirm_same_key`` must run afterwards, in the new transaction.
        """
        material = key_material(await self._get_model())
        await self.session.commit()
        opened = await self._open(master_password, material)
        if opened is None:
            raise Forbidden("Incorrect master password.")
        return opened

    async def wrap_for_device(
        self, master_password: str, secret: bytes, credential_id: str
    ) -> bytes:
        """
        The vault key wrapped for a biometric enrollment, which only the master
        password can authorize. Like every slow step this runs outside any
        transaction; a master password change that committed meanwhile stops it.
        """
        observed = key_material(await self._get_model())
        await self.session.commit()
        try:
            wrapped = await wrap_key_for_device(
                master_password, observed, secret, credential_id
            )
        except UnsupportedKdf as error:
            raise InvalidRequest(str(error)) from None
        except DecryptionFailed:
            logger.error("The vault key record failed to verify.")
            raise InvalidRequest(_DAMAGED) from None
        if wrapped is None:
            raise Forbidden("Incorrect master password.")
        if key_material(await self._get_model()) != observed:
            raise InvalidKey(_INVALID_KEY)
        return wrapped

    async def confirm_same_key(self, opened: VaultKey, key: VaultKey) -> None:
        """Check, in the request's new transaction, that the session's key is
        still the vault's and is the one the master password opened, so a
        master password change that committed meanwhile stops the request."""
        await self.verify_vault_key(key)
        if not opened.matches(key.check):
            raise InvalidKey(_INVALID_KEY)

    async def update_master_password(
        self, master_password: str, new_master_password: str
    ) -> MasterPasswordUpdate:
        """
        Re-key the vault: a new random vault key and salt, every entry and
        attachment decrypted with the old keys and sealed again with the new
        ones, every name index recomputed. The KDFs run before the write lock
        is taken; the re-encryption then runs in one write transaction that
        first confirms the vault still holds the key record the KDFs used.
        """
        observed = key_material(await self._get_model())
        await self.session.commit()
        old_key = await self._open(master_password, observed)
        if old_key is None:
            raise Forbidden("Current master password is incorrect.")

        material, new_key = await create_key_material(new_master_password)

        model = await self._get_model()
        if key_material(model) != observed:
            raise InvalidKey(_INVALID_KEY)

        await _reencrypt_entries(self.session, old_key, new_key)
        await _reencrypt_attachments(self.session, old_key, new_key)

        _store(model, material)
        self.session.add(model)
        await self.session.flush()

        return MasterPasswordUpdate(
            updated=True, detail="Master password updated successfully."
        )


async def _reencrypt_entries(
    session: AsyncSession, old_key: VaultKey, new_key: VaultKey
) -> None:
    ids = (await session.scalars(select(EntryModel.id).order_by(EntryModel.id))).all()
    for entry_id in ids:
        entry = await session.get_one(EntryModel, entry_id)
        seal_entry(new_key, entry, open_entry(old_key, entry))
        flag_modified(entry, "updated")
        await session.flush()
        session.expunge(entry)


async def _reencrypt_attachments(
    session: AsyncSession, old_key: VaultKey, new_key: VaultKey
) -> None:
    rows = (
        await session.execute(
            select(AttachmentModel.id, EntryModel.uid)
            .outerjoin(EntryModel, AttachmentModel.entry_id == EntryModel.id)
            .order_by(AttachmentModel.id)
        )
    ).all()
    for attachment_id, entry_uid in rows:
        if entry_uid is None:
            raise damaged(f"Attachment #{attachment_id}")
        attachment = await session.get_one(AttachmentModel, attachment_id)
        metadata = open_attachment_metadata(old_key, attachment, entry_uid)
        content = open_attachment_content(old_key, attachment, entry_uid)
        seal_attachment(new_key, attachment, entry_uid, metadata, content)
        await session.flush()
        session.expunge(attachment)
