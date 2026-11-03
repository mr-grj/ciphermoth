"""
FIDO2 security keys over WebAuthn, checked with Yubico's python-fido2.

A security key takes part in two independent ways. Its signature over a fresh,
single-use challenge from this server proves it is present now (checked here).
Its PRF output (CTAP2 ``hmac-secret``) is a secret only that key can produce
for a salt the vault stores; it unwraps the factor key that the master password
needs to open the vault (``helpers.unwrap_factor_key``). A copied vault file is
useless without the key, and a recorded PRF output still needs a fresh
signature to open a session.

Every client sends what WebAuthn defines: the browser's own client data and
authenticator data, or the same structures built by the CLI and the desktop app,
which talk to the key over USB (CTAP2) and use the origin ``https://<rp id>``.
"""

import hashlib
import logging
import os
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

# python-fido2 logs every credential id at INFO; ours stay out of the logs.
logging.getLogger("fido2").setLevel(logging.WARNING)

CHALLENGE_BYTES = 32
CHALLENGE_TTL_SECONDS = 300
MAX_PENDING_CHALLENGES = 64
TIMEOUT_MS = 120_000
RP_NAME = "CipherMoth"
# ES256, EdDSA, RS256: what security keys and browsers use in practice.
ALGORITHMS = (-7, -8, -257)
# Every use verifies the key's user (its PIN, or its fingerprint). Required, not
# preferred: a key's PRF secret differs with and without verification (CTAP2
# keeps one per mode), and browsers verify a key that has a PIN whenever PRF is
# asked for, so every client must verify to get the same secret. It also makes
# a stolen key useless without its PIN, which the key locks after 8 wrong tries.
USER_VERIFICATION = UserVerificationRequirement.REQUIRED

Purpose = str  # "unlock", "confirm", "register", "register-secret", "recover"


class VerificationFailed(Exception):
    """The security key's answer did not verify. The message is safe to show."""


@dataclass(frozen=True, slots=True)
class _Pending:
    purpose: Purpose
    binding: bytes | None
    data: bytes
    expires: float


class Challenges:
    """
    Single-use challenges in memory, each for one purpose and, for anything
    a session asks for, bound to that session. A restart forgets them, which
    only means touching the key again. Bounded: the oldest are dropped first.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._pending: OrderedDict[bytes, _Pending] = OrderedDict()

    def issue(
        self, purpose: Purpose, binding: bytes | None = None, data: bytes = b""
    ) -> bytes:
        now = self._clock()
        for challenge, pending in list(self._pending.items()):
            if pending.expires <= now:
                del self._pending[challenge]
        while len(self._pending) >= MAX_PENDING_CHALLENGES:
            self._pending.popitem(last=False)
        challenge = os.urandom(CHALLENGE_BYTES)
        self._pending[challenge] = _Pending(
            purpose, binding, data, now + CHALLENGE_TTL_SECONDS
        )
        return challenge

    def consume(
        self, challenge: bytes, purpose: Purpose, binding: bytes | None = None
    ) -> bytes:
        """Use up ``challenge`` and return the data issued with it; raises unless
        it was issued for this purpose and binding and has not expired. A failed
        attempt uses it up too."""
        pending = self._pending.pop(challenge, None)
        if (
            pending is None
            or pending.purpose != purpose
            or pending.binding != binding
            or pending.expires <= self._clock()
        ):
            raise VerificationFailed(
                "That security key request expired or was already used. Try again."
            )
        return pending.data

    def clear(self) -> None:
        self._pending.clear()


def session_binding(token: str) -> bytes:
    return hashlib.sha256(
        b"ciphermoth/security-key-challenge\x00" + token.encode()
    ).digest()


@dataclass(frozen=True, slots=True)
class Credential:
    credential_id: bytes
    public_key: bytes  # CBOR-encoded COSE key
    rp_id: str


def client_challenge(client_data_json: bytes) -> bytes:
    """The challenge the client signed, read before anything else is checked so
    the right pending challenge can be used up."""
    try:
        return CollectedClientData(client_data_json).challenge
    except (ValueError, KeyError, TypeError) as error:
        raise VerificationFailed("The security key's answer is malformed.") from error


def registration_rp_id(client_data_json: bytes) -> str:
    """The relying party a new credential belongs to: the host the client was
    on (browsers default the RP ID to it; native clients use https://<rp id>).
    ``Fido2Server`` then checks that origin and the authenticator's RP ID hash."""
    try:
        origin = CollectedClientData(client_data_json).origin
    except (ValueError, KeyError, TypeError) as error:
        raise VerificationFailed("The security key's answer is malformed.") from error
    host = urlparse(origin).hostname
    if not host:
        raise VerificationFailed("The security key's answer has no origin.")
    return host


def _server(rp_id: str) -> Fido2Server:
    return Fido2Server(
        PublicKeyCredentialRpEntity(name=RP_NAME, id=rp_id),
        attestation=AttestationConveyancePreference.NONE,
    )


def _state(challenge: bytes) -> dict:
    return {
        "challenge": websafe_encode(challenge),
        "user_verification": USER_VERIFICATION,
    }


def verify_registration(
    rp_id: str, challenge: bytes, client_data_json: bytes, attestation_object: bytes
) -> Credential:
    try:
        auth_data = _server(rp_id).register_complete(
            _state(challenge),
            {
                "id": "",
                "rawId": "",
                "type": "public-key",
                "response": {
                    "clientDataJSON": websafe_encode(client_data_json),
                    "attestationObject": websafe_encode(attestation_object),
                },
                "clientExtensionResults": {},
            },
        )
    except (ValueError, KeyError, TypeError) as error:
        raise VerificationFailed(
            "The security key's registration did not verify."
        ) from error
    credential = auth_data.credential_data
    if credential is None or credential.public_key.ALGORITHM not in ALGORITHMS:
        raise VerificationFailed("This security key uses an unsupported algorithm.")
    return Credential(
        credential_id=bytes(credential.credential_id),
        public_key=cbor.encode(dict(credential.public_key)),
        rp_id=rp_id,
    )


def verify_assertion(
    credential: Credential,
    challenge: bytes,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
) -> int:
    """Check one signed answer from ``credential``; returns its signature counter."""
    try:
        decoded = cbor.decode(credential.public_key)
        if not isinstance(decoded, Mapping):
            raise ValueError("not a COSE key")
        public_key = CoseKey.parse(cast(Mapping[int, Any], decoded))
        attested = AttestedCredentialData.create(
            bytes(Aaguid.NONE), credential.credential_id, public_key
        )
        encoded_id = websafe_encode(credential.credential_id)
        _server(credential.rp_id).authenticate_complete(
            _state(challenge),
            [attested],
            {
                "id": encoded_id,
                "rawId": encoded_id,
                "type": "public-key",
                "response": {
                    "clientDataJSON": websafe_encode(client_data_json),
                    "authenticatorData": websafe_encode(authenticator_data),
                    "signature": websafe_encode(signature),
                },
                "clientExtensionResults": {},
            },
        )
        return AuthenticatorData(authenticator_data).counter
    except (ValueError, KeyError, TypeError) as error:
        raise VerificationFailed("The security key's answer did not verify.") from error


def counter_advanced(stored: int, received: int) -> bool:
    """WebAuthn's clone check: a key that keeps a counter must move it forward.
    Keys without one report 0 every time."""
    return (stored == 0 and received == 0) or received > stored
