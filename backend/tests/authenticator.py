"""
A software FIDO2 security key for tests. It produces what a browser hands the
web app: client data, "none" attestation, authenticator data, ES256 signatures,
and PRF outputs computed like CTAP2 hmac-secret (HMAC-SHA256 under a per-
credential secret, of SHA-256("WebAuthn PRF" || 0x00 || salt)). The server
verifies them with python-fido2 exactly as it verifies a real key.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256

_UP = 0x01
_UV = 0x04
_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def prf_salt_input(salt: bytes) -> bytes:
    return hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest()


@dataclass
class SoftKey:
    rp_id: str = "localhost"
    origin: str = "http://localhost:3000"
    credential_id: bytes = field(default_factory=lambda: os.urandom(48))
    counter: int = 0
    user_present: bool = True
    # Every client verifies the key's user (its PIN); see webauthn.USER_VERIFICATION.
    user_verified: bool = True
    _private: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    _cred_random: bytes = field(default_factory=lambda: os.urandom(32))
    _cred_random_uv: bytes = field(default_factory=lambda: os.urandom(32))

    @property
    def id(self) -> str:
        return b64url(self.credential_id)

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def _flags(self) -> int:
        return (_UP if self.user_present else 0) | (_UV if self.user_verified else 0)

    def _auth_data(self, rp_id: str, extra_flags: int = 0, tail: bytes = b"") -> bytes:
        self.counter += 1
        return (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags() | extra_flags])
            + struct.pack(">I", self.counter)
            + tail
        )

    def cose_public_key(self) -> bytes:
        return cbor.encode(
            dict(ES256.from_cryptography_key(self._private.public_key()))
        )

    def register(
        self, challenge: str, *, origin: str | None = None, rp_id: str | None = None
    ) -> dict:
        public_key = ES256.from_cryptography_key(self._private.public_key())
        attested = (
            b"\x00" * 16
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + cbor.encode(dict(public_key))
        )
        auth_data = self._auth_data(rp_id or self.rp_id, _AT, attested)
        attestation = cbor.encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "client_data_json": b64url(
                self._client_data("webauthn.create", challenge, origin)
            ),
            "attestation_object": b64url(attestation),
        }

    def prf(self, salt: bytes) -> bytes:
        secret = self._cred_random_uv if self.user_verified else self._cred_random
        return hmac.new(secret, prf_salt_input(salt), hashlib.sha256).digest()

    def answer(
        self,
        challenge: str,
        prf_salt: str | bytes,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        kind: str = "webauthn.get",
    ) -> dict:
        salt = unb64url(prf_salt) if isinstance(prf_salt, str) else prf_salt
        client_data = self._client_data(kind, challenge, origin)
        auth_data = self._auth_data(rp_id or self.rp_id)
        signature = self._private.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "credential_id": self.id,
            "client_data_json": b64url(client_data),
            "authenticator_data": b64url(auth_data),
            "signature": b64url(signature),
            "prf_output": b64url(self.prf(salt)),
        }
