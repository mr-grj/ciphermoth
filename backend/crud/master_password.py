import hmac
import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import delete, select, update
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
    KEY_BYTES,
    RECOVERY_SEALED_BYTES,
    SEALED_OVERHEAD,
    DecryptionFailed,
    KdfParams,
    KeyMaterial,
    OpenedVault,
    RecoveryMaterial,
    SecurityKeySlot,
    UnsupportedKdf,
    VaultKey,
    create_key_material,
    create_recovery,
    escrow_factor_key,
    new_factor_key,
    open_escrowed_factor_key,
    open_recovery,
    open_vault,
    reseal_recovery,
    rewrap_key_material,
    unwrap_factor_key,
    wrap_factor_key,
    wrap_key_for_device,
)
from models import (
    AttachmentModel,
    EntryModel,
    RecoveryModel,
    SecurityKeyModel,
    VaultModel,
    utc_now,
)
from schemas import (
    Confirmation,
    MasterPasswordUpdate,
    SecurityKeyAssertion,
    SecurityKeyInfo,
)
from webauthn import (
    Challenges,
    Credential,
    VerificationFailed,
    client_challenge,
    counter_advanced,
    verify_assertion,
)

logger = logging.getLogger(__name__)

_INVALID_KEY = "Invalid or expired vault key. Unlock the vault again."

MAX_SECURITY_KEYS = 10
SECURITY_KEY_REQUIRED = (
    "This vault needs your security key as well as the master password. Use the "
    "web app, the desktop app or the CipherMoth 3.4 CLI or newer."
)
_FACTOR_ESCROW_BYTES = SEALED_OVERHEAD + KEY_BYTES
_MAX_CREDENTIAL_ID_BYTES = 1023
_MAX_PUBLIC_KEY_BYTES = 2048
_WRONG_SECRET = (
    "The security key answered, but its secret does not open this vault. If it "
    "asked for its PIN this time, try again without entering it, or use another "
    "registered key."
)
_RECOVERY_DAMAGED = (
    "The vault's recovery code record does not verify. Remove the recovery code "
    "in Settings and create a new one, or restore a snapshot (docs/UPDATING.md)."
)

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
    escrow = model.factor_key_escrow
    if escrow is not None and (
        not isinstance(escrow, bytes) or len(escrow) != _FACTOR_ESCROW_BYTES
    ):
        raise InvalidRequest(_DAMAGED)
    return KeyMaterial(
        params=KdfParams(model.kdf_memory_kib, model.kdf_iterations, model.kdf_lanes),
        salt=model.kdf_salt,
        password_check=model.password_check,
        wrapped_key=model.wrapped_key,
        key_check=model.key_check,
        second_factor=escrow is not None,
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


@dataclass(frozen=True, slots=True)
class StoredSecurityKey:
    id: int
    uid: bytes
    credential: Credential
    prf_salt: bytes
    sign_count: int
    wrapped_factor_key: bytes = field(repr=False)

    @property
    def slot(self) -> SecurityKeySlot:
        return SecurityKeySlot(
            uid=self.uid,
            credential_id=self.credential.credential_id,
            public_key=self.credential.public_key,
            rp_id=self.credential.rp_id,
            prf_salt=self.prf_salt,
        )


def _stored_key(model: SecurityKeyModel) -> StoredSecurityKey | None:
    """The row as plain values, or None if a value has the wrong type or size
    (which the factor key's associated data would refuse anyway)."""
    if not (
        isinstance(model.uid, bytes)
        and len(model.uid) == 16
        and isinstance(model.credential_id, bytes)
        and 0 < len(model.credential_id) <= _MAX_CREDENTIAL_ID_BYTES
        and isinstance(model.public_key, bytes)
        and 0 < len(model.public_key) <= _MAX_PUBLIC_KEY_BYTES
        and isinstance(model.rp_id, str)
        and 0 < len(model.rp_id) <= 253
        and isinstance(model.prf_salt, bytes)
        and len(model.prf_salt) == KEY_BYTES
        and type(model.sign_count) is int
        and 0 <= model.sign_count < 2**32
        and isinstance(model.wrapped_factor_key, bytes)
        and len(model.wrapped_factor_key) == _FACTOR_ESCROW_BYTES
    ):
        logger.warning("Ignoring the malformed security key row #%s.", model.id)
        return None
    return StoredSecurityKey(
        id=model.id,
        uid=model.uid,
        credential=Credential(model.credential_id, model.public_key, model.rp_id),
        prf_salt=model.prf_salt,
        sign_count=model.sign_count,
        wrapped_factor_key=model.wrapped_factor_key,
    )


def _recovery_material(model: RecoveryModel) -> RecoveryMaterial:
    for value, length in (
        (model.salt, 16),
        (model.public_key, 32),
        (model.sealed_key, RECOVERY_SEALED_BYTES),
        (model.binding, 32),
    ):
        if not isinstance(value, bytes) or len(value) != length:
            raise InvalidRequest(_RECOVERY_DAMAGED)
    return RecoveryMaterial(
        params=KdfParams(model.kdf_memory_kib, model.kdf_iterations, model.kdf_lanes),
        salt=model.salt,
        public_key=model.public_key,
        sealed_key=model.sealed_key,
        binding=model.binding,
    )


def _store_recovery(model: RecoveryModel, material: RecoveryMaterial) -> None:
    model.kdf_memory_kib = material.params.memory_kib
    model.kdf_iterations = material.params.iterations
    model.kdf_lanes = material.params.lanes
    model.salt = material.salt
    model.public_key = material.public_key
    model.sealed_key = material.sealed_key
    model.binding = material.binding


@dataclass(frozen=True, slots=True)
class VaultState:
    """Everything that turns credentials into the vault key, as one transaction
    saw it. Slow work (KDFs, a security key's answer) runs between transactions;
    a change that committed meanwhile makes ``revision`` differ."""

    material: KeyMaterial
    factor_key_escrow: bytes | None = field(repr=False)
    recovery: RecoveryModel | None = field(repr=False)
    security_keys: tuple[StoredSecurityKey, ...]

    @property
    def revision(self) -> tuple:
        recovery = self.recovery
        return (
            self.material,
            self.factor_key_escrow,
            None
            if recovery is None
            else (recovery.salt, recovery.public_key, recovery.sealed_key),
            tuple((key.id, key.wrapped_factor_key) for key in self.security_keys),
        )

    def recovery_material(self) -> RecoveryMaterial | None:
        return None if self.recovery is None else _recovery_material(self.recovery)


@dataclass(frozen=True, slots=True)
class FactorCheck:
    """Where a security key's answer must come from: a challenge this server
    issued for ``purpose`` (and, for a session's request, to that session)."""

    challenges: Challenges
    purpose: str
    binding: bytes | None = None


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

    async def _security_key_rows(self) -> list[SecurityKeyModel]:
        return list(
            (
                await self.session.scalars(
                    select(SecurityKeyModel)
                    .order_by(SecurityKeyModel.id)
                    .execution_options(populate_existing=True)
                )
            ).all()
        )

    async def _recovery_row(self) -> RecoveryModel | None:
        return (
            await self.session.execute(
                select(RecoveryModel)
                .where(RecoveryModel.id == 1)
                .execution_options(populate_existing=True)
            )
        ).scalar()

    async def state(self) -> VaultState:
        model = await self._get_model()
        material = key_material(model)
        keys = [_stored_key(row) for row in await self._security_key_rows()]
        return VaultState(
            material=material,
            factor_key_escrow=model.factor_key_escrow,
            recovery=await self._recovery_row(),
            security_keys=tuple(key for key in keys if key is not None),
        )

    async def _current(self, observed: VaultState) -> VaultModel:
        """The vault row, in the request's write transaction, if nothing that
        turns credentials into the vault key changed since ``observed``."""
        model = await self._get_model()
        current = await self.state()
        if current.material.key_check != observed.material.key_check:
            raise InvalidKey(_INVALID_KEY)
        if current.revision != observed.revision:
            raise InvalidRequest(
                "The vault's security settings changed meanwhile. Try again."
            )
        return model

    async def security_key_status(self) -> tuple[bool, bool]:
        """Whether unlocking needs a security key, and whether a recovery code
        exists. Public: the unlock screen needs both."""
        model = await fetch_vault(self.session)
        if model is None:
            return False, False
        return model.factor_key_escrow is not None, (
            await self._recovery_row() is not None
        )

    @staticmethod
    async def _open(
        master_password: str, material: KeyMaterial, factor_key: bytes | None = None
    ) -> OpenedVault | None:
        try:
            return await open_vault(master_password, material, factor_key)
        except UnsupportedKdf as error:
            raise InvalidRequest(str(error)) from None
        except DecryptionFailed:
            logger.error("The vault key record failed to verify.")
            raise InvalidRequest(_DAMAGED) from None

    async def _record_use(self, key: StoredSecurityKey, sign_count: int) -> None:
        """Store the key's new signature counter in a short write transaction of
        its own (the UPDATE is its first statement, so it waits for the write
        lock instead of failing on a stale snapshot). Two requests answering with
        the same counter cannot both pass."""
        result = await self.session.execute(
            update(SecurityKeyModel)
            .where(
                SecurityKeyModel.id == key.id,
                SecurityKeyModel.sign_count == key.sign_count,
            )
            .values(sign_count=sign_count, last_used=utc_now())
        )
        await self.session.commit()
        if getattr(result, "rowcount", 0) != 1:
            raise Forbidden(
                "This security key was used for another request at the same time. "
                "Try again."
            )

    async def _factor_key(
        self,
        observed: VaultState,
        answer: SecurityKeyAssertion | None,
        check: FactorCheck,
    ) -> bytes:
        """The factor key from a registered security key's verified answer. Runs
        outside any transaction except the short one recording the counter."""
        if answer is None:
            raise InvalidRequest(SECURITY_KEY_REQUIRED)
        credential_id = answer.raw("credential_id")
        key = next(
            (
                stored
                for stored in observed.security_keys
                if hmac.compare_digest(stored.credential.credential_id, credential_id)
            ),
            None,
        )
        if key is None:
            raise Forbidden("This security key is not registered with this vault.")
        client_data = answer.raw("client_data_json")
        try:
            challenge = client_challenge(client_data)
            check.challenges.consume(challenge, check.purpose, check.binding)
            sign_count = verify_assertion(
                key.credential,
                challenge,
                client_data,
                answer.raw("authenticator_data"),
                answer.raw("signature"),
            )
        except VerificationFailed as error:
            raise Forbidden(str(error)) from None
        if not counter_advanced(key.sign_count, sign_count):
            logger.warning(
                "Security key #%s answered with a counter that did not advance.",
                key.id,
            )
            raise Forbidden(
                "This security key's signature counter went backwards, which can "
                "mean it was cloned. Use another key or your recovery code."
            )
        await self._record_use(key, sign_count)
        try:
            return unwrap_factor_key(
                answer.raw("prf_output"), key.wrapped_factor_key, key.slot
            )
        except DecryptionFailed:
            raise Forbidden(_WRONG_SECRET) from None

    async def open_with(
        self,
        master_password: str,
        answer: SecurityKeyAssertion | None,
        check: FactorCheck,
    ) -> tuple[OpenedVault | None, VaultState]:
        """
        The raw vault key for the master password (and a security key's answer
        when the vault requires one), or None if the password is wrong. The
        transaction is ended first: the key's answer and the KDF run outside it,
        so they hold no connection and no lock. Callers that change anything must
        confirm, in their next transaction, that ``VaultState.revision`` still
        holds (``_current``).
        """
        observed = await self.state()
        await self.session.commit()
        factor_key = None
        if observed.material.second_factor:
            factor_key = await self._factor_key(observed, answer, check)
        opened = await self._open(master_password, observed.material, factor_key)
        return opened, observed

    async def confirm(
        self,
        master_password: str,
        answer: SecurityKeyAssertion | None,
        check: FactorCheck,
        wrong_password: str = "Incorrect master password.",
    ) -> tuple[OpenedVault, VaultState]:
        opened, observed = await self.open_with(master_password, answer, check)
        if opened is None:
            raise Forbidden(wrong_password)
        return opened, observed

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

    async def unlock(
        self,
        master_password: str,
        answer: SecurityKeyAssertion | None = None,
        check: FactorCheck | None = None,
    ) -> VaultKey | None:
        """
        Return the vault key for ``master_password`` (and the security key, when
        required), or None if the password is wrong.

        The key is then confirmed against the current key check, so a password
        that a concurrent change has just replaced is refused instead of opening
        a session every route would reject.
        """
        opened, _ = await self.open_with(
            master_password, answer, check or FactorCheck(Challenges(), "unlock")
        )
        if opened is None:
            return None
        key = opened.key
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
        material, opened = await create_key_material(master_password)

        if await self.is_initialized():
            raise Forbidden("Master password already exists.")

        # Rows a previous vault in this file left behind belong to its key.
        await self.session.execute(delete(SecurityKeyModel))
        await self.session.execute(delete(RecoveryModel))
        model = VaultModel(id=1)
        _store(model, material)
        self.session.add(model)
        await self.session.flush()
        return opened.key

    async def check_master_password(
        self,
        master_password: str,
        answer: SecurityKeyAssertion | None = None,
        check: FactorCheck | None = None,
    ) -> VaultKey:
        """
        Check the master password a backup asks for (with the security key when
        the vault requires one) and return the key it opens. The transaction is
        ended first, so the KDF never holds the write lock; ``confirm_same_key``
        must run afterwards, in the new transaction.
        """
        opened, _ = await self.confirm(
            master_password, answer, check or FactorCheck(Challenges(), "confirm")
        )
        return opened.key

    async def wrap_for_device(
        self,
        master_password: str,
        secret: bytes,
        credential_id: str,
        answer: SecurityKeyAssertion | None,
        check: FactorCheck,
    ) -> bytes:
        """
        The vault key wrapped for a biometric enrollment, which only the master
        password (with the security key, when required) can authorize. Like every
        slow step this runs outside any transaction; a change that committed
        meanwhile stops it.
        """
        opened, observed = await self.confirm(master_password, answer, check)
        wrapped = wrap_key_for_device(opened, secret, credential_id)
        await self._current(observed)
        return wrapped

    async def confirm_same_key(self, opened: VaultKey, key: VaultKey) -> None:
        """Check, in the request's new transaction, that the session's key is
        still the vault's and is the one the master password opened, so a
        master password change that committed meanwhile stops the request."""
        await self.verify_vault_key(key)
        if not opened.matches(key.check):
            raise InvalidKey(_INVALID_KEY)

    async def update_master_password(
        self,
        master_password: str,
        new_master_password: str,
        answer: SecurityKeyAssertion | None = None,
        check: FactorCheck | None = None,
    ) -> MasterPasswordUpdate:
        """
        Re-key the vault: a new random vault key and salt, every entry and
        attachment decrypted with the old keys and sealed again with the new
        ones, every name index recomputed. The KDFs run before the write lock
        is taken; the re-encryption then runs in one write transaction that
        first confirms the vault still holds the key record the KDFs used.
        Security keys keep working (the factor key is unchanged) and the
        recovery code too (the new vault key is sealed to the same public key).
        """
        old, observed = await self.confirm(
            master_password,
            answer,
            check or FactorCheck(Challenges(), "confirm"),
            wrong_password="Current master password is incorrect.",
        )
        # A new key record always uses the current default KDF parameters.
        material, new = await create_key_material(
            new_master_password, factor_key=old.factor_key
        )
        model = await self._current(observed)
        await self._rekey(model, observed, old, new, material)
        return MasterPasswordUpdate(
            updated=True, detail="Master password updated successfully."
        )

    async def _rekey(
        self,
        model: VaultModel,
        observed: VaultState,
        old: OpenedVault,
        new: OpenedVault,
        material: KeyMaterial,
        recovery: RecoveryMaterial | None = None,
    ) -> None:
        """Seal everything under ``new`` inside the current write transaction.
        ``recovery`` replaces the recovery code; otherwise an existing one is
        sealed again for the new key."""
        old_key, new_key = old.key, new.key
        await _reencrypt_entries(self.session, old_key, new_key)
        await _reencrypt_attachments(self.session, old_key, new_key)
        await self._reseal_security_key_names(old_key, new_key)
        if recovery is None and observed.recovery is not None:
            try:
                recovery = reseal_recovery(
                    old.raw, new.raw, _recovery_material(observed.recovery)
                )
            except DecryptionFailed:
                logger.error("The recovery code record failed to verify.")
                raise InvalidRequest(_RECOVERY_DAMAGED) from None
            await self._store_recovery_row(recovery, new_code=False)
        elif recovery is not None:
            await self._store_recovery_row(recovery, new_code=True)
        model.factor_key_escrow = (
            None
            if new.factor_key is None
            else escrow_factor_key(new.raw, new.factor_key)
        )
        _store(model, material)
        self.session.add(model)
        await self.session.flush()

    async def _store_recovery_row(
        self, recovery: RecoveryMaterial, *, new_code: bool
    ) -> None:
        row = await self._recovery_row()
        if row is None:
            row = RecoveryModel(id=1)
            self.session.add(row)
        _store_recovery(row, recovery)
        if new_code:
            row.created = utc_now()
        await self.session.flush()

    async def _reseal_security_key_names(
        self, old_key: VaultKey, new_key: VaultKey
    ) -> None:
        for row in await self._security_key_rows():
            row.name = new_key.seal_security_key_name(
                row.uid, _security_key_name(old_key, row)
            )
        await self.session.flush()

    # Security keys and the recovery code.

    async def security_keys(self, key: VaultKey) -> list[SecurityKeyInfo]:
        return [
            SecurityKeyInfo(
                id=row.id,
                name=_security_key_name(key, row),
                rp_id=row.rp_id,
                created=row.created,
                last_used=row.last_used,
            )
            for row in await self._security_key_rows()
            if _stored_key(row) is not None
        ]

    async def recovery_created(self) -> datetime | None:
        row = await self._recovery_row()
        return None if row is None else row.created

    async def add_security_key(
        self,
        key: VaultKey,
        confirmation: Confirmation,
        credential: Credential,
        prf_salt: bytes,
        prf_output: bytes,
        sign_count: int,
        name: str,
        check: FactorCheck,
    ) -> None:
        """
        Register a security key whose registration and first answer were already
        verified. The first key turns the second factor on: a new factor key
        joins the master password in the key record, under the same vault key, so
        open sessions, entries and biometric unlock are unaffected.
        """
        opened, observed = await self.confirm(
            confirmation.master_password, confirmation.security_key, check
        )
        if not opened.key.matches(key.check):
            raise InvalidKey(_INVALID_KEY)
        factor_key = opened.factor_key or new_factor_key()
        model = await self._current(observed)
        if len(observed.security_keys) >= MAX_SECURITY_KEYS:
            raise InvalidRequest(
                f"A vault can have at most {MAX_SECURITY_KEYS} security keys. "
                "Remove one first."
            )
        if any(
            hmac.compare_digest(
                stored.credential.credential_id, credential.credential_id
            )
            for stored in observed.security_keys
        ):
            raise InvalidRequest("This security key is already registered.")
        row = SecurityKeyModel(
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            rp_id=credential.rp_id,
            prf_salt=prf_salt,
            sign_count=sign_count,
        )
        slot = SecurityKeySlot(
            uid=row.uid,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            rp_id=credential.rp_id,
            prf_salt=prf_salt,
        )
        row.wrapped_factor_key = wrap_factor_key(prf_output, factor_key, slot)
        row.name = key.seal_security_key_name(row.uid, name)
        self.session.add(row)
        if not observed.material.second_factor:
            _store(model, rewrap_key_material(opened, observed.material, factor_key))
            model.factor_key_escrow = escrow_factor_key(opened.raw, factor_key)
            self.session.add(model)
        await self.session.flush()

    async def remove_security_key(
        self, key: VaultKey, key_id: int, confirmation: Confirmation, check: FactorCheck
    ) -> None:
        """Remove one key. Removing the last one turns the second factor off: the
        vault key is wrapped under the master password alone again."""
        opened, observed = await self.confirm(
            confirmation.master_password, confirmation.security_key, check
        )
        if not opened.key.matches(key.check):
            raise InvalidKey(_INVALID_KEY)
        model = await self._current(observed)
        row = await self.session.get(SecurityKeyModel, key_id)
        if row is None:
            raise NotFound("No such security key.")
        await self.session.delete(row)
        await self.session.flush()
        if not await self._security_key_rows():
            _store(model, rewrap_key_material(opened, observed.material, None))
            model.factor_key_escrow = None
            self.session.add(model)
            await self.session.flush()

    async def create_recovery_code(
        self, key: VaultKey, confirmation: Confirmation, check: FactorCheck
    ) -> str:
        """A new recovery code, replacing any previous one."""
        opened, observed = await self.confirm(
            confirmation.master_password, confirmation.security_key, check
        )
        if not opened.key.matches(key.check):
            raise InvalidKey(_INVALID_KEY)
        code, recovery = await create_recovery(opened.raw)
        await self._current(observed)
        await self._store_recovery_row(recovery, new_code=True)
        return code

    async def remove_recovery_code(
        self, key: VaultKey, confirmation: Confirmation, check: FactorCheck
    ) -> None:
        opened, observed = await self.confirm(
            confirmation.master_password, confirmation.security_key, check
        )
        if not opened.key.matches(key.check):
            raise InvalidKey(_INVALID_KEY)
        await self._current(observed)
        await self.session.execute(delete(RecoveryModel))
        await self.session.flush()

    async def recover(
        self, recovery_code: str, new_master_password: str, keep_security_keys: bool
    ) -> tuple[VaultKey, str, bool]:
        """
        Reset a forgotten master password with the recovery code: a full re-key
        like a master password change, and a new recovery code (the used one may
        have been seen). Registered security keys keep working unless the user
        lost them, in which case they are removed and the vault opens with the
        new master password alone. Returns the new key, the new code and whether
        a security key is still required.
        """
        observed = await self.state()
        await self.session.commit()
        recovery_material = observed.recovery_material()
        if recovery_material is None:
            raise InvalidRequest("This vault has no recovery code.")
        try:
            raw = await open_recovery(recovery_code, recovery_material)
        except UnsupportedKdf as error:
            raise InvalidRequest(str(error)) from None
        except DecryptionFailed:
            logger.error("The recovery code record failed to verify.")
            raise InvalidRequest(_RECOVERY_DAMAGED) from None
        if raw is None:
            raise Forbidden("Incorrect recovery code.")
        old_key = VaultKey(raw)
        if not old_key.matches(observed.material.key_check):
            # Sealed for a vault key that is gone: a restored or replaced vault.
            raise InvalidRequest(_RECOVERY_DAMAGED)
        factor_key = None
        if keep_security_keys and observed.factor_key_escrow is not None:
            try:
                factor_key = open_escrowed_factor_key(raw, observed.factor_key_escrow)
            except DecryptionFailed:
                raise InvalidRequest(_DAMAGED) from None
        material, new = await create_key_material(
            new_master_password, factor_key=factor_key
        )
        code, recovery = await create_recovery(new.raw)
        model = await self._current(observed)
        if factor_key is None:
            await self.session.execute(delete(SecurityKeyModel))
        old = OpenedVault(raw, b"", factor_key)
        await self._rekey(model, observed, old, new, material, recovery)
        return new.key, code, factor_key is not None


def _security_key_name(key: VaultKey, row: SecurityKeyModel) -> str:
    try:
        return key.open_security_key_name(row.uid, row.name)
    except (DecryptionFailed, UnicodeDecodeError, TypeError):
        raise damaged(f"Security key #{row.id}") from None


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
