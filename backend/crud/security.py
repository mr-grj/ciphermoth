import base64
import os

from crud.base import BaseCRUD
from crud.master_password import FactorCheck, MasterPasswordCRUD
from errors import InvalidRequest
from helpers import KEY_BYTES, VaultKey
from schemas import (
    Confirmation,
    RecoveryCodeResult,
    SecurityKeyAdd,
    SecurityKeyRegistrationOptions,
    SecurityStatus,
)
from webauthn import (
    ALGORITHMS,
    RP_NAME,
    TIMEOUT_MS,
    Challenges,
    VerificationFailed,
    client_challenge,
    registration_rp_id,
    verify_assertion,
    verify_registration,
)

# Security keys hold no account for a vault (the credential is not discoverable),
# so every vault can use the same user handle.
_USER_ID = b"ciphermoth-vault"


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class SecurityCRUD(BaseCRUD):
    """
    Security keys and the recovery code. Every change asks for the master
    password again, with a registered security key's answer once one is
    required: a session alone (an unattended unlocked browser) can change
    neither.
    """

    def __init__(self, session, challenges: Challenges, binding: bytes) -> None:
        super().__init__(session)
        self.challenges = challenges
        self.binding = binding
        self.master_password = MasterPasswordCRUD(session)

    @property
    def check(self) -> FactorCheck:
        return FactorCheck(self.challenges, "confirm", self.binding)

    async def status(self, key: VaultKey) -> SecurityStatus:
        required, _ = await self.master_password.security_key_status()
        recovery_created = await self.master_password.recovery_created()
        return SecurityStatus(
            security_keys=await self.master_password.security_keys(key),
            security_key_required=required,
            recovery_code=recovery_created is not None,
            recovery_code_created=recovery_created,
        )

    async def registration_options(self) -> SecurityKeyRegistrationOptions:
        state = await self.master_password.state()
        prf_salt = os.urandom(KEY_BYTES)
        return SecurityKeyRegistrationOptions(
            challenge=_encode(self.challenges.issue("register", self.binding)),
            secret_challenge=_encode(
                self.challenges.issue("register-secret", self.binding, prf_salt)
            ),
            prf_salt=_encode(prf_salt),
            user_id=_encode(_USER_ID),
            rp_name=RP_NAME,
            timeout_ms=TIMEOUT_MS,
            algorithms=list(ALGORITHMS),
            exclude_credentials=[
                _encode(stored.credential.credential_id)
                for stored in state.security_keys
            ],
        )

    async def add(self, key: VaultKey, body: SecurityKeyAdd) -> SecurityStatus:
        """
        Check the new key's registration and its first answer (which proves it
        can produce the PRF secret for the salt this server chose), then confirm
        the user and store it.
        """
        try:
            client_data = body.registration.raw("client_data_json")
            challenge = client_challenge(client_data)
            self.challenges.consume(challenge, "register", self.binding)
            credential = verify_registration(
                registration_rp_id(client_data),
                challenge,
                client_data,
                body.registration.raw("attestation_object"),
            )
            answer = body.assertion
            if answer.raw("credential_id") != credential.credential_id:
                raise VerificationFailed(
                    "The security key that answered is not the one just registered."
                )
            answer_data = answer.raw("client_data_json")
            secret_challenge = client_challenge(answer_data)
            prf_salt = self.challenges.consume(
                secret_challenge, "register-secret", self.binding
            )
            sign_count = verify_assertion(
                credential,
                secret_challenge,
                answer_data,
                answer.raw("authenticator_data"),
                answer.raw("signature"),
            )
        except VerificationFailed as error:
            raise InvalidRequest(str(error)) from None
        await self.master_password.add_security_key(
            key,
            body.confirmation,
            credential,
            prf_salt,
            answer.raw("prf_output"),
            sign_count,
            body.name,
            self.check,
        )
        return await self.status(key)

    async def remove(
        self, key: VaultKey, key_id: int, confirmation: Confirmation
    ) -> SecurityStatus:
        await self.master_password.remove_security_key(
            key, key_id, confirmation, self.check
        )
        return await self.status(key)

    async def create_recovery_code(
        self, key: VaultKey, confirmation: Confirmation
    ) -> RecoveryCodeResult:
        code = await self.master_password.create_recovery_code(
            key, confirmation, self.check
        )
        return RecoveryCodeResult(recovery_code=code, status=await self.status(key))

    async def remove_recovery_code(
        self, key: VaultKey, confirmation: Confirmation
    ) -> SecurityStatus:
        await self.master_password.remove_recovery_code(key, confirmation, self.check)
        return await self.status(key)
