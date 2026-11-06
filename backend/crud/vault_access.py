import base64
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from crud.base import BaseCRUD
from crud.engine import after_commit, after_rollback
from crud.master_password import FactorCheck, MasterPasswordCRUD, fetch_vault
from crud.settings import SettingsCRUD
from device_unlock import (
    MAX_ENROLLMENTS,
    DeviceUnlockStore,
    Enrollment,
    PasswordIntervalDays,
)
from errors import InvalidKey, InvalidRequest, NotFound, SessionRequired, UseHandoff
from helpers import DecryptionFailed, VaultKey, open_device_wrapped_key
from schemas import (
    Confirmation,
    DeviceEnrollmentInfo,
    DeviceEnrollRequest,
    DeviceUnlockRequest,
    DeviceUnlockResult,
    DeviceUnlockStatus,
    ExtensionSessionCreated,
    ExtensionSessionInfo,
    ExtensionUnlockPayload,
    MasterPasswordCreate,
    MasterPasswordUpdate,
    MasterPasswordUpdatePayload,
    RecoverPayload,
    RecoverResult,
    SecurityKeyChallenge,
    SecurityKeyDescriptor,
    VaultSessionStatus,
    VaultUnlock,
)
from vault_sessions import Scope, VaultSessions
from webauthn import TIMEOUT_MS, Challenges, session_binding

logger = logging.getLogger(__name__)

_SESSION_ENDED = "Your session expired or was locked. Unlock the vault again."


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True, slots=True)
class SessionToken:
    token: str = field(repr=False)


class VaultAccess(BaseCRUD):
    """
    Turns a master password into a vault session and a session back into the
    vault key, for one request. Every use of a session still checks its key
    against the vault's key check inside the request's transaction, so a session
    can never outlive the key it was opened with, whichever process changed it.
    """

    def __init__(
        self,
        session: AsyncSession,
        vault_sessions: VaultSessions,
        device_unlock: DeviceUnlockStore,
        challenges: Challenges | None = None,
    ) -> None:
        super().__init__(session)
        self.vault_sessions = vault_sessions
        self.device_unlock = device_unlock
        self.challenges = challenges or Challenges()
        self.master_password = MasterPasswordCRUD(session)

    def confirm_check(self, credential: SessionToken) -> FactorCheck:
        """Security key answers for a session's request must answer a challenge
        issued to that same session."""
        return FactorCheck(
            self.challenges, "confirm", session_binding(credential.token)
        )

    async def _challenge(
        self, purpose: str, binding: bytes | None
    ) -> SecurityKeyChallenge:
        state = await self.master_password.state()
        if not state.material.second_factor:
            raise InvalidRequest("This vault does not use a security key.")
        return SecurityKeyChallenge(
            challenge=_encode_base64url(self.challenges.issue(purpose, binding)),
            timeout_ms=TIMEOUT_MS,
            keys=[
                SecurityKeyDescriptor(
                    credential_id=_encode_base64url(key.credential.credential_id),
                    rp_id=key.credential.rp_id,
                    prf_salt=_encode_base64url(key.prf_salt),
                )
                for key in state.security_keys
            ],
        )

    async def unlock_challenge(self) -> SecurityKeyChallenge:
        return await self._challenge("unlock", None)

    async def confirm_challenge(self, credential: SessionToken) -> SecurityKeyChallenge:
        return await self._challenge("confirm", session_binding(credential.token))

    async def _refresh_idle_timeout(self) -> None:
        inactivity_ms = await SettingsCRUD(
            self.session, self.vault_sessions
        ).inactivity_ms()
        self.vault_sessions.set_idle_timeout(inactivity_ms)

    def _open(self, key: VaultKey) -> str:
        token = self.vault_sessions.open(key)
        after_rollback(self.session, lambda: self.vault_sessions.revoke(token))
        return token

    async def unlock(self, body: Confirmation) -> VaultUnlock:
        key = await self.master_password.unlock(
            body.master_password,
            body.security_key,
            FactorCheck(self.challenges, "unlock"),
        )
        if key is None:
            return VaultUnlock(valid=False)
        self.device_unlock.record_password_unlock()
        await self._refresh_idle_timeout()
        return VaultUnlock(
            valid=True,
            session_token=self._open(key),
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
        )

    async def create(self, master_password: str) -> MasterPasswordCreate:
        key = await self.master_password.create_master_password(master_password)
        after_commit(self.session, self.device_unlock.clear)
        await self._refresh_idle_timeout()
        return MasterPasswordCreate(
            created=True,
            detail="Master password created successfully.",
            session_token=self._open(key),
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
        )

    async def authorize(
        self,
        credential: SessionToken,
        *,
        refresh: bool = True,
        scope: Scope = Scope.FULL,
    ) -> VaultKey:
        key = self.vault_sessions.resolve(
            credential.token, refresh=refresh, scope=scope
        )
        try:
            return await self.master_password.verify_vault_key(key)
        except InvalidKey:
            self.vault_sessions.revoke(credential.token)
            raise SessionRequired(_SESSION_ENDED) from None

    async def unlock_extension(self, body: ExtensionUnlockPayload) -> VaultUnlock:
        """
        An extension session from the master password typed into the
        extension's popup. A vault that needs a security key is refused before
        any KDF runs: WebAuthn from an extension cannot answer for the vault's
        relying party, so the user unlocks in the web app and connects the
        extension from there (``connect_extension``).
        """
        model = await fetch_vault(self.session)
        if model is not None and model.factor_key_escrow is not None:
            raise UseHandoff(
                "This vault needs a security key. Unlock it in CipherMoth and "
                "connect the extension from there."
            )
        key = await self.master_password.unlock(body.master_password)
        if key is None:
            return VaultUnlock(valid=False)
        await self._refresh_idle_timeout()
        token, _ = self._open_extension(key, body.browser, body.client)
        return VaultUnlock(
            valid=True,
            session_token=token,
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
        )

    def _open_extension(
        self, key: VaultKey, browser: str, client: str | None
    ) -> tuple[str, str]:
        token, handle = self.vault_sessions.open_extension(key, browser, client)
        after_rollback(self.session, lambda: self.vault_sessions.revoke(token))
        return token, handle

    async def connect_extension(
        self, key: VaultKey, browser: str, client: str | None = None
    ) -> ExtensionSessionCreated:
        """An extension session for the handoff, opened from the key of an
        unlocked full session (already checked against the vault)."""
        await self._refresh_idle_timeout()
        token, handle = self._open_extension(key, browser, client)
        return ExtensionSessionCreated(
            session_token=token,
            id=handle,
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
        )

    def extension_sessions(self) -> list[ExtensionSessionInfo]:
        return [
            ExtensionSessionInfo(
                id=info.handle,
                browser=info.browser,
                created=_utc(info.created),
                last_used=_utc(info.last_used),
            )
            for info in self.vault_sessions.extension_sessions()
        ]

    def disconnect_extension(self, handle: str) -> None:
        if not self.vault_sessions.revoke_extension(handle):
            raise NotFound("No such browser extension session.")

    def extension_status(self, credential: SessionToken) -> VaultSessionStatus:
        info = self.vault_sessions.info(credential.token, scope=Scope.EXTENSION)
        return VaultSessionStatus(
            idle_timeout_ms=info.idle_timeout_ms, expires_in_ms=info.expires_in_ms
        )

    def status(self, credential: SessionToken) -> VaultSessionStatus:
        info = self.vault_sessions.info(credential.token)
        return VaultSessionStatus(
            idle_timeout_ms=info.idle_timeout_ms, expires_in_ms=info.expires_in_ms
        )

    async def change_master_password(
        self, credential: SessionToken, body: MasterPasswordUpdatePayload
    ) -> MasterPasswordUpdate:
        try:
            result = await self.master_password.update_master_password(
                body.master_password,
                body.new_master_password,
                body.security_key,
                self.confirm_check(credential),
            )
        except InvalidKey:
            self.vault_sessions.revoke(credential.token)
            raise SessionRequired(_SESSION_ENDED) from None
        after_commit(self.session, self.vault_sessions.revoke_all)
        after_commit(self.session, self.device_unlock.clear)
        return result

    async def device_status(self) -> DeviceUnlockStatus:
        state = self.device_unlock.read()
        initialized = await self.master_password.is_initialized()
        return DeviceUnlockStatus(
            enrollments=[
                DeviceEnrollmentInfo(
                    credential_id=enrollment.credential_id,
                    kind=enrollment.kind,
                    material=enrollment.material,
                )
                for enrollment in (state.enrollments if initialized else [])
            ],
            password_required=self.device_unlock.password_required(state),
            password_interval_days=state.password_interval_days,
        )

    async def enroll_device(
        self, request: DeviceEnrollRequest, credential: SessionToken
    ) -> None:
        if not self.device_unlock.has_room_for(request.credential_id):
            raise InvalidRequest(
                f"Biometric unlock can be on at most {MAX_ENROLLMENTS} devices. "
                "Turn it off on one first."
            )
        wrapped = await self.master_password.wrap_for_device(
            request.master_password,
            request.secret_bytes(),
            request.credential_id,
            request.security_key,
            self.confirm_check(credential),
        )
        self.device_unlock.add(
            Enrollment(
                credential_id=request.credential_id,
                kind=request.kind,
                material=request.material,
                wrapped_key=_encode_base64url(wrapped),
            )
        )

    async def unlock_with_device(
        self, request: DeviceUnlockRequest
    ) -> DeviceUnlockResult:
        """
        Open a session from an authenticator's secret. No KDF runs, so this stays
        in the request's read transaction, like the key check of a password unlock:
        the vault key is confirmed against the key check of one snapshot, and a
        master password change committed after it ends the session at first use.
        """
        if self.device_unlock.password_required():
            return DeviceUnlockResult(valid=False, password_required=True)
        enrollment = self.device_unlock.find(request.credential_id)
        if enrollment is None:
            return DeviceUnlockResult(valid=False)
        try:
            key = open_device_wrapped_key(
                request.secret_bytes(),
                enrollment.credential_id,
                _decode_base64url(enrollment.wrapped_key),
            )
        except (DecryptionFailed, ValueError):
            return DeviceUnlockResult(valid=False)
        vault = await fetch_vault(self.session)
        if vault is None or not key.matches(vault.key_check):
            # Opened with the right secret, so this is not a guess: the enrollment
            # belongs to a vault key that is gone.
            self.device_unlock.remove(enrollment.credential_id)
            return DeviceUnlockResult(valid=False, password_required=True)
        await self._refresh_idle_timeout()
        return DeviceUnlockResult(
            valid=True,
            session_token=self._open(key),
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
        )

    async def recover(self, body: RecoverPayload) -> RecoverResult:
        """
        A new master password from the recovery code. Every session ends and
        biometric unlock is turned off (it wrapped the old vault key); the new
        session is the only one.
        """
        key, code, security_key_required = await self.master_password.recover(
            body.recovery_code, body.new_master_password, body.keep_security_keys
        )
        logger.warning("The vault was recovered with its recovery code.")
        await self._refresh_idle_timeout()
        token = self._open(key)
        after_commit(self.session, lambda: self.vault_sessions.revoke_all(keep=token))
        after_commit(self.session, self.device_unlock.clear)
        return RecoverResult(
            detail="Master password reset. Save your new recovery code.",
            session_token=token,
            idle_timeout_ms=self.vault_sessions.idle_timeout_ms,
            recovery_code=code,
            security_key_required=security_key_required,
        )

    def forget_device(self, credential_id: str) -> None:
        self.device_unlock.remove(credential_id)

    def set_password_interval(self, days: PasswordIntervalDays) -> None:
        self.device_unlock.set_password_interval(days)
