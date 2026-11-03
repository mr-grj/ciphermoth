"""
Every cryptographic construction of vault format 2 and backup format 2, in one
place so it can be reviewed as a whole. The specification is
docs/VAULT_FORMAT.md; the known-answer vectors are in testdata/vectors.

Primitives come from ``cryptography`` only: Argon2id, HKDF-SHA256,
AES-256-GCM, HMAC-SHA256 and X25519 (the recovery code).
"""

import asyncio
import base64
import hashlib
import hmac
import io
import os
import struct
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pyzipper
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 2
KDF_NAME = "argon2id"
KEY_BYTES = 32
SALT_BYTES = 16
UID_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
SEALED_OVERHEAD = 1 + NONCE_BYTES + TAG_BYTES

_SEALED_VERSION = b"\x02"
_DOCUMENT_BLOCK = 64
_FORMAT_LABEL = b"ciphermoth/v2"
_WRAP_LABEL = b"ciphermoth/v2/wrapped-vault-key"
_PASSWORD_COMMITMENT = "ciphermoth/v2/password-commitment"
_KEY_WRAPPING = "ciphermoth/v2/key-wrapping"
_RECORD_ENCRYPTION = "ciphermoth/v2/record-encryption"
_NAME_INDEX = "ciphermoth/v2/name-index"
_KEY_CHECK = "ciphermoth/v2/key-check"
_DEVICE_UNLOCK = "ciphermoth/v2/device-unlock"
_SECOND_FACTOR_WRAP_LABEL = b"ciphermoth/v2/wrapped-vault-key/second-factor"
_SECOND_FACTOR_COMMITMENT = "ciphermoth/v2/password-and-factor-commitment"
_SECOND_FACTOR_WRAPPING = "ciphermoth/v2/password-and-factor-key-wrapping"
_FACTOR_ESCROW = "ciphermoth/v2/factor-key-escrow"
_SECURITY_KEY_WRAPPING = "ciphermoth/v2/security-key-wrapping"
_RECOVERY_PRIVATE_KEY = "ciphermoth/v2/recovery-private-key"
_RECOVERY_SEALING = "ciphermoth/v2/recovery-sealing"
_RECOVERY_BINDING = "ciphermoth/v2/recovery-binding"
_BACKUP_COMMITMENT = "ciphermoth/backup/v2/key-commitment"
_BACKUP_FRAMES = "ciphermoth/backup/v2/frame-encryption"

_KDF_WORKERS = 2
_KDF_POOL = ThreadPoolExecutor(
    max_workers=_KDF_WORKERS, thread_name_prefix="ciphermoth-kdf"
)
_ARGON2_ALONE = threading.Lock()


class DecryptionFailed(Exception):
    """Authenticated decryption failed: the value was altered, moved to another
    record or role, truncated, or belongs to another key."""


class UnsupportedKdf(Exception):
    """KDF parameters outside the range this release accepts."""


@dataclass(frozen=True, slots=True)
class KdfParams:
    memory_kib: int = 65536
    iterations: int = 3
    lanes: int = 4

    MIN_MEMORY_KIB = 19456
    MAX_MEMORY_KIB = 262144
    MAX_ITERATIONS = 10
    MAX_LANES = 8

    def require_supported(self) -> None:
        """
        Refuse parameters before running the KDF, so a hostile vault or backup
        file cannot make the process allocate gigabytes or spin for minutes.
        """
        if not (
            all(
                type(value) is int
                for value in (self.memory_kib, self.iterations, self.lanes)
            )
            and self.MIN_MEMORY_KIB <= self.memory_kib <= self.MAX_MEMORY_KIB
            and 1 <= self.iterations <= self.MAX_ITERATIONS
            and 1 <= self.lanes <= self.MAX_LANES
            and self.memory_kib >= 8 * self.lanes
        ):
            raise UnsupportedKdf(
                "Unsupported key derivation parameters "
                f"(memory {self.memory_kib} KiB, {self.iterations} iterations, "
                f"{self.lanes} lanes)."
            )


DEFAULT_KDF = KdfParams()


def argon2id(password: str, salt: bytes, params: KdfParams = DEFAULT_KDF) -> bytes:
    params.require_supported()
    kdf = Argon2id(
        salt=salt,
        length=KEY_BYTES,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    with _ARGON2_ALONE:
        return kdf.derive(password.encode())


async def _off_the_event_loop[T](function: Callable[..., T], *args: object) -> T:
    """
    Run a deliberately slow KDF in a small dedicated pool, so other requests
    keep being served while it runs. Argon2id derivations still run one at a
    time (``_ARGON2_ALONE``): two at once deadlocked inside OpenSSL on x86_64
    Linux, and one at a time also keeps their memory bounded however many
    unlocks arrive together.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_KDF_POOL, function, *args)


async def derive(password: str, salt: bytes, params: KdfParams = DEFAULT_KDF) -> bytes:
    return await _off_the_event_loop(argon2id, password, salt, params)


def _hkdf(key: bytes, label: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=label.encode()
    ).derive(key)


def new_uid() -> bytes:
    return os.urandom(UID_BYTES)


def _associated_data(*parts: bytes) -> bytes:
    data = bytearray(_SEALED_VERSION + _FORMAT_LABEL)
    for part in parts:
        if not isinstance(part, bytes | bytearray | memoryview):
            raise DecryptionFailed
        part = bytes(part)
        data += struct.pack(">I", len(part)) + part
    return bytes(data)


def _seal(cipher: AESGCM, plaintext: bytes, associated_data: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return _SEALED_VERSION + nonce + cipher.encrypt(nonce, plaintext, associated_data)


def _open(cipher: AESGCM, sealed: object, associated_data: bytes) -> bytes:
    if not isinstance(sealed, bytes | bytearray | memoryview):
        raise DecryptionFailed
    sealed = bytes(sealed)
    if len(sealed) < SEALED_OVERHEAD or sealed[:1] != _SEALED_VERSION:
        raise DecryptionFailed
    try:
        return cipher.decrypt(
            sealed[1 : 1 + NONCE_BYTES], sealed[1 + NONCE_BYTES :], associated_data
        )
    except InvalidTag:
        raise DecryptionFailed from None


def _padded(document: bytes) -> bytes:
    return document + b" " * (-len(document) % _DOCUMENT_BLOCK)


class VaultKey:
    """
    The keys derived from one vault key. The raw vault key is not kept: a
    session holds this object, which can encrypt, decrypt and index records
    and prove which vault key it came from (``check``), and nothing else.
    """

    __slots__ = ("_records", "_index", "check")

    def __init__(self, raw: bytes) -> None:
        if len(raw) != KEY_BYTES:
            raise ValueError("A vault key is 32 bytes.")
        self._records = AESGCM(_hkdf(raw, _RECORD_ENCRYPTION))
        self._index = _hkdf(raw, _NAME_INDEX)
        self.check = _hkdf(raw, _KEY_CHECK)

    def __repr__(self) -> str:
        return "VaultKey(...)"

    def matches(self, key_check: bytes | None) -> bool:
        return isinstance(key_check, bytes) and hmac.compare_digest(
            self.check, key_check
        )

    def name_index(self, name: str) -> bytes:
        return hmac.new(self._index, name.encode(), hashlib.sha256).digest()

    def seal_entry(self, uid: bytes, document: bytes) -> bytes:
        return _seal(self._records, _padded(document), _associated_data(b"entry", uid))

    def open_entry(self, uid: bytes, sealed: bytes) -> bytes:
        return _open(self._records, sealed, _associated_data(b"entry", uid))

    def seal_attachment_metadata(
        self, uid: bytes, entry_uid: bytes, document: bytes
    ) -> bytes:
        return _seal(
            self._records,
            _padded(document),
            _associated_data(b"attachment-metadata", uid, entry_uid),
        )

    def open_attachment_metadata(
        self, uid: bytes, entry_uid: bytes, sealed: bytes
    ) -> bytes:
        return _open(
            self._records,
            sealed,
            _associated_data(b"attachment-metadata", uid, entry_uid),
        )

    def seal_attachment_content(
        self, uid: bytes, entry_uid: bytes, content: bytes
    ) -> bytes:
        return _seal(
            self._records,
            content,
            _associated_data(b"attachment-content", uid, entry_uid),
        )

    def seal_security_key_name(self, uid: bytes, name: str) -> bytes:
        return _seal(
            self._records,
            _padded(name.encode()),
            _associated_data(b"security-key-name", uid),
        )

    def open_security_key_name(self, uid: bytes, sealed: bytes) -> str:
        return (
            _open(self._records, sealed, _associated_data(b"security-key-name", uid))
            .decode()
            .rstrip(" ")
        )

    def open_attachment_content(
        self, uid: bytes, entry_uid: bytes, sealed: bytes
    ) -> bytes:
        return _open(
            self._records,
            sealed,
            _associated_data(b"attachment-content", uid, entry_uid),
        )


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    """
    What the vault row stores to turn a master password (and, with a second
    factor, a security key's secret) into the vault key.
    """

    params: KdfParams
    salt: bytes
    password_check: bytes
    wrapped_key: bytes = field(repr=False)
    key_check: bytes
    second_factor: bool = False


@dataclass(frozen=True, slots=True)
class OpenedVault:
    """
    The raw vault key, for the few operations that must wrap it again (a second
    factor, a recovery code, a biometric enrollment), with what opened it. Only
    the master password, together with the security key when one is required,
    or the recovery code yields one; a session never does. Never logged, never
    kept beyond the request.
    """

    raw: bytes = field(repr=False)
    derived: bytes = field(repr=False)
    factor_key: bytes | None = field(default=None, repr=False)

    @property
    def key(self) -> VaultKey:
        return VaultKey(self.raw)


def _wrap_associated_data(
    params: KdfParams, salt: bytes, second_factor: bool = False
) -> bytes:
    return (
        (_SECOND_FACTOR_WRAP_LABEL if second_factor else _WRAP_LABEL)
        + struct.pack(
            ">HIII", FORMAT_VERSION, params.memory_kib, params.iterations, params.lanes
        )
        + salt
    )


def _password_keys(derived: bytes, factor_key: bytes | None) -> tuple[bytes, AESGCM]:
    """
    The password commitment and the key-wrapping cipher. With a second factor
    both come from the master password's key and the factor key together, so the
    vault file alone does not even let anyone test a password guess.
    """
    if factor_key is None:
        return _hkdf(derived, _PASSWORD_COMMITMENT), AESGCM(
            _hkdf(derived, _KEY_WRAPPING)
        )
    if len(factor_key) != KEY_BYTES:
        raise DecryptionFailed
    combined = derived + factor_key
    return _hkdf(combined, _SECOND_FACTOR_COMMITMENT), AESGCM(
        _hkdf(combined, _SECOND_FACTOR_WRAPPING)
    )


def seal_key_material(
    derived: bytes,
    raw_key: bytes,
    params: KdfParams,
    salt: bytes,
    factor_key: bytes | None = None,
) -> KeyMaterial:
    second_factor = factor_key is not None
    commitment, cipher = _password_keys(derived, factor_key)
    return KeyMaterial(
        params=params,
        salt=salt,
        password_check=commitment,
        wrapped_key=_seal(
            cipher, raw_key, _wrap_associated_data(params, salt, second_factor)
        ),
        key_check=VaultKey(raw_key).check,
        second_factor=second_factor,
    )


def open_key_material(
    derived: bytes, material: KeyMaterial, factor_key: bytes | None = None
) -> VaultKey | None:
    """
    The vault key, or None if ``derived`` comes from a wrong password. The
    password commitment is compared first, so a crafted wrapped key cannot
    turn one unlock into a test of many passwords (AES-GCM is not
    key-committing). A matching commitment with a wrapped key or key check
    that does not verify raises DecryptionFailed: the row is damaged.
    """
    raw = _unwrap_raw_key(derived, material, factor_key)
    return None if raw is None else VaultKey(raw)


def _unwrap_raw_key(
    derived: bytes, material: KeyMaterial, factor_key: bytes | None = None
) -> bytes | None:
    if material.second_factor != (factor_key is not None):
        raise ValueError("The second factor does not match the key record.")
    commitment, cipher = _password_keys(derived, factor_key)
    if not hmac.compare_digest(commitment, bytes(material.password_check)):
        return None
    raw = _open(
        cipher,
        material.wrapped_key,
        _wrap_associated_data(material.params, material.salt, material.second_factor),
    )
    if len(raw) != KEY_BYTES or not VaultKey(raw).matches(material.key_check):
        raise DecryptionFailed
    return raw


async def create_key_material(
    password: str, params: KdfParams = DEFAULT_KDF, factor_key: bytes | None = None
) -> tuple[KeyMaterial, OpenedVault]:
    """A new random vault key and salt, wrapped under ``password`` (and the factor
    key, when the vault has a second factor)."""
    salt = os.urandom(SALT_BYTES)
    raw_key = os.urandom(KEY_BYTES)
    derived = await derive(password, salt, params)
    return (
        seal_key_material(derived, raw_key, params, salt, factor_key),
        OpenedVault(raw_key, derived, factor_key),
    )


async def open_vault(
    password: str, material: KeyMaterial, factor_key: bytes | None = None
) -> OpenedVault | None:
    """The raw vault key for ``password`` (and the factor key), or None if the
    password is wrong."""
    derived = await derive(password, material.salt, material.params)
    raw = _unwrap_raw_key(derived, material, factor_key)
    return None if raw is None else OpenedVault(raw, derived, factor_key)


async def unlock_key_material(
    password: str, material: KeyMaterial, factor_key: bytes | None = None
) -> VaultKey | None:
    opened = await open_vault(password, material, factor_key)
    return None if opened is None else opened.key


def rewrap_key_material(
    opened: OpenedVault, material: KeyMaterial, factor_key: bytes | None
) -> KeyMaterial:
    """The same vault key under the same password, with a second factor added
    (``factor_key``) or removed (None). Nothing else in the vault changes."""
    return seal_key_material(
        opened.derived, opened.raw, material.params, material.salt, factor_key
    )


# Second factor. A random 32-byte factor key joins the master password in the key
# record above. Each security key holds a copy wrapped under its own PRF secret, and
# the vault keeps one more under the vault key itself, so the recovery code (which
# opens the vault key) can keep the security keys working.


def new_factor_key() -> bytes:
    return os.urandom(KEY_BYTES)


def escrow_factor_key(raw_key: bytes, factor_key: bytes) -> bytes:
    return _seal(
        AESGCM(_hkdf(raw_key, _FACTOR_ESCROW)),
        factor_key,
        _associated_data(b"factor-key"),
    )


def open_escrowed_factor_key(raw_key: bytes, sealed: object) -> bytes:
    factor_key = _open(
        AESGCM(_hkdf(raw_key, _FACTOR_ESCROW)), sealed, _associated_data(b"factor-key")
    )
    if len(factor_key) != KEY_BYTES:
        raise DecryptionFailed
    return factor_key


@dataclass(frozen=True, slots=True)
class SecurityKeySlot:
    """
    What identifies one registered security key. All of it is associated data of
    the factor key wrapped for that key, so swapping a public key, credential,
    relying party or PRF salt in the file makes the slot fail to open.
    """

    uid: bytes
    credential_id: bytes
    public_key: bytes
    rp_id: str
    prf_salt: bytes

    def associated_data(self) -> bytes:
        return _associated_data(
            b"security-key",
            self.uid,
            self.credential_id,
            self.public_key,
            self.rp_id.encode(),
            self.prf_salt,
        )


def _security_key_cipher(prf_output: bytes) -> AESGCM:
    if len(prf_output) != KEY_BYTES:
        raise DecryptionFailed
    return AESGCM(_hkdf(prf_output, _SECURITY_KEY_WRAPPING))


def wrap_factor_key(
    prf_output: bytes, factor_key: bytes, slot: SecurityKeySlot
) -> bytes:
    return _seal(_security_key_cipher(prf_output), factor_key, slot.associated_data())


def unwrap_factor_key(
    prf_output: bytes, sealed: object, slot: SecurityKeySlot
) -> bytes:
    factor_key = _open(_security_key_cipher(prf_output), sealed, slot.associated_data())
    if len(factor_key) != KEY_BYTES:
        raise DecryptionFailed
    return factor_key


# Recovery code. 160 random bits shown once as eight groups of four Crockford
# base32 characters. Argon2id turns the code into an X25519 key pair; the vault
# stores only the public key and the vault key sealed to it. Sealing needs only
# the public key, so a master password change seals the new vault key to the same
# code without knowing it. The public key is bound to the vault key by a MAC, so
# someone who can write the file cannot substitute a key pair of their own.

RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
RECOVERY_CODE_CHARACTERS = 32
_RECOVERY_GROUP = 4
_RECOVERY_LOOKALIKES = str.maketrans({"O": "0", "I": "1", "L": "1"})
RECOVERY_SEALED_BYTES = 32 + SEALED_OVERHEAD + KEY_BYTES


def new_recovery_code() -> str:
    # 32 is a power of two, so each byte's low five bits are uniform.
    code = "".join(
        RECOVERY_ALPHABET[byte & 31] for byte in os.urandom(RECOVERY_CODE_CHARACTERS)
    )
    return "-".join(
        code[start : start + _RECOVERY_GROUP]
        for start in range(0, RECOVERY_CODE_CHARACTERS, _RECOVERY_GROUP)
    )


def canonical_recovery_code(text: str) -> str | None:
    """The code without separators, forgiving case and the look-alike letters
    O, I and L; None if it cannot be a recovery code."""
    cleaned = "".join(
        character for character in text.upper() if character not in " -\t\r\n"
    ).translate(_RECOVERY_LOOKALIKES)
    if len(cleaned) != RECOVERY_CODE_CHARACTERS or any(
        character not in RECOVERY_ALPHABET for character in cleaned
    ):
        return None
    return cleaned


@dataclass(frozen=True, slots=True)
class RecoveryMaterial:
    params: KdfParams
    salt: bytes
    public_key: bytes
    sealed_key: bytes = field(repr=False)
    binding: bytes


def _recovery_private_key(derived: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_hkdf(derived, _RECOVERY_PRIVATE_KEY))


def _recovery_binding(
    raw_key: bytes, params: KdfParams, salt: bytes, public_key: bytes
) -> bytes:
    return hmac.new(
        _hkdf(raw_key, _RECOVERY_BINDING),
        struct.pack(">III", params.memory_kib, params.iterations, params.lanes)
        + salt
        + public_key,
        hashlib.sha256,
    ).digest()


def _recovery_cipher(shared: bytes, ephemeral: bytes, recipient: bytes) -> AESGCM:
    return AESGCM(_hkdf(shared + ephemeral + recipient, _RECOVERY_SEALING))


def _seal_for_recovery(raw_key: bytes, public_key: bytes) -> bytes:
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public_key))
    except ValueError:
        raise DecryptionFailed from None
    return ephemeral_public + _seal(
        _recovery_cipher(shared, ephemeral_public, public_key),
        raw_key,
        _associated_data(b"recovery", ephemeral_public, public_key),
    )


def _recovery_material(
    raw_key: bytes, params: KdfParams, salt: bytes, public_key: bytes
) -> RecoveryMaterial:
    return RecoveryMaterial(
        params=params,
        salt=salt,
        public_key=public_key,
        sealed_key=_seal_for_recovery(raw_key, public_key),
        binding=_recovery_binding(raw_key, params, salt, public_key),
    )


async def create_recovery(
    raw_key: bytes, params: KdfParams = DEFAULT_KDF
) -> tuple[str, RecoveryMaterial]:
    """A new recovery code, and the vault key sealed to it."""
    code = new_recovery_code()
    salt = os.urandom(SALT_BYTES)
    derived = await derive(canonical_recovery_code(code) or "", salt, params)
    public_key = _recovery_private_key(derived).public_key().public_bytes_raw()
    return code, _recovery_material(raw_key, params, salt, public_key)


def reseal_recovery(
    old_raw_key: bytes, new_raw_key: bytes, material: RecoveryMaterial
) -> RecoveryMaterial:
    """The same recovery code for a new vault key. Refuses (DecryptionFailed) a
    public key the old vault key did not bind: it was not ours."""
    expected = _recovery_binding(
        old_raw_key, material.params, material.salt, material.public_key
    )
    if not hmac.compare_digest(expected, bytes(material.binding)):
        raise DecryptionFailed
    return _recovery_material(
        new_raw_key, material.params, material.salt, material.public_key
    )


async def open_recovery(code: str, material: RecoveryMaterial) -> bytes | None:
    """
    The raw vault key, or None if ``code`` is not this vault's recovery code.
    The public key derived from the code is compared first (the commitment); a
    match whose sealed key or binding does not verify raises DecryptionFailed.
    """
    canonical = canonical_recovery_code(code)
    if canonical is None:
        return None
    derived = await derive(canonical, material.salt, material.params)
    private_key = _recovery_private_key(derived)
    public_key = private_key.public_key().public_bytes_raw()
    if not hmac.compare_digest(public_key, bytes(material.public_key)):
        return None
    sealed = bytes(material.sealed_key)
    ephemeral_public = sealed[:32]
    try:
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_public)
        )
    except ValueError:
        raise DecryptionFailed from None
    raw = _open(
        _recovery_cipher(shared, ephemeral_public, public_key),
        sealed[32:],
        _associated_data(b"recovery", ephemeral_public, public_key),
    )
    if len(raw) != KEY_BYTES or not hmac.compare_digest(
        _recovery_binding(raw, material.params, material.salt, public_key),
        bytes(material.binding),
    ):
        raise DecryptionFailed
    return raw


def _device_cipher(secret: bytes) -> AESGCM:
    if len(secret) != KEY_BYTES:
        raise DecryptionFailed
    return AESGCM(_hkdf(secret, _DEVICE_UNLOCK))


def wrap_key_for_device(
    opened: OpenedVault, secret: bytes, credential_id: str
) -> bytes:
    """
    The vault key wrapped under a device's 32-byte secret. Only an opened vault
    (the master password, with the security key when one is required) can create
    this wrapping: a session does not hold the raw vault key.
    """
    return _seal(
        _device_cipher(secret),
        opened.raw,
        _associated_data(b"device-unlock", credential_id.encode()),
    )


def open_device_wrapped_key(
    secret: bytes, credential_id: str, wrapped: bytes
) -> VaultKey:
    raw = _open(
        _device_cipher(secret),
        wrapped,
        _associated_data(b"device-unlock", credential_id.encode()),
    )
    if len(raw) != KEY_BYTES:
        raise DecryptionFailed
    return VaultKey(raw)


BACKUP_MAGIC = b"CMBACKUP"
BACKUP_VERSION = 2
BACKUP_KDF_ARGON2ID = 1
_BACKUP_HEADER = struct.Struct(">8sHBIII16sI32s")
BACKUP_HEADER_BYTES = _BACKUP_HEADER.size


class BackupFormatError(Exception):
    """A file that is not a backup this release can read."""


@dataclass(frozen=True, slots=True)
class BackupHeader:
    params: KdfParams
    salt: bytes
    frames: int
    commitment: bytes

    def pack(self) -> bytes:
        return _BACKUP_HEADER.pack(
            BACKUP_MAGIC,
            BACKUP_VERSION,
            BACKUP_KDF_ARGON2ID,
            self.params.memory_kib,
            self.params.iterations,
            self.params.lanes,
            self.salt,
            self.frames,
            self.commitment,
        )

    @classmethod
    def parse(cls, data: bytes) -> "BackupHeader":
        if len(data) != BACKUP_HEADER_BYTES:
            raise BackupFormatError("The file is too short to be a backup.")
        magic, version, kdf, memory, iterations, lanes, salt, frames, commitment = (
            _BACKUP_HEADER.unpack(data)
        )
        if magic != BACKUP_MAGIC:
            raise BackupFormatError("The file is not a CipherMoth backup.")
        if version != BACKUP_VERSION:
            raise BackupFormatError(
                f"The backup has version {version}; this release reads version "
                f"{BACKUP_VERSION}. Update CipherMoth."
            )
        if kdf != BACKUP_KDF_ARGON2ID:
            raise BackupFormatError("The backup uses an unknown key derivation.")
        params = KdfParams(memory, iterations, lanes)
        try:
            params.require_supported()
        except UnsupportedKdf as error:
            raise BackupFormatError(str(error)) from None
        if frames < 1:
            raise BackupFormatError("The backup has no content.")
        return cls(params, salt, frames, commitment)


class BackupKey:
    """The keys of one backup, derived from its password and its own salt."""

    __slots__ = ("_frames", "commitment")

    def __init__(self, derived: bytes) -> None:
        self._frames = AESGCM(_hkdf(derived, _BACKUP_FRAMES))
        self.commitment = _hkdf(derived, _BACKUP_COMMITMENT)

    def __repr__(self) -> str:
        return "BackupKey(...)"

    def matches(self, header: BackupHeader) -> bool:
        return hmac.compare_digest(self.commitment, header.commitment)

    @staticmethod
    def _frame_associated_data(header: bytes, index: int, last: bool) -> bytes:
        return header + struct.pack(">IB", index, 1 if last else 0)

    def seal_frame(
        self, header: bytes, index: int, last: bool, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        return nonce, self._frames.encrypt(
            nonce, plaintext, self._frame_associated_data(header, index, last)
        )

    def open_frame(
        self, header: bytes, index: int, last: bool, nonce: bytes, ciphertext: bytes
    ) -> bytes:
        try:
            return self._frames.decrypt(
                nonce, ciphertext, self._frame_associated_data(header, index, last)
            )
        except InvalidTag:
            raise DecryptionFailed from None


async def new_backup_key(
    password: str, params: KdfParams = DEFAULT_KDF
) -> tuple[bytes, BackupKey]:
    salt = os.urandom(SALT_BYTES)
    return salt, BackupKey(await derive(password, salt, params))


async def backup_key_for(password: str, header: BackupHeader) -> BackupKey:
    return BackupKey(await derive(password, header.salt, header.params))


LEGACY_BACKUP_MEMBER = "ciphermoth_backup.json"


def read_legacy_backup(data: bytes, password: str, max_bytes: int) -> bytes:
    """
    The JSON of a backup ZIP written by CipherMoth 2.0.x or earlier (WinZip AES,
    PBKDF2-HMAC-SHA1 with 1000 iterations). Read-only: nothing writes this
    format any more. Raises DecryptionFailed for a wrong password or a damaged
    archive and BackupFormatError for anything else that is not such a backup.
    """
    try:
        with pyzipper.AESZipFile(io.BytesIO(data), "r") as archive:
            if LEGACY_BACKUP_MEMBER not in archive.namelist():
                raise BackupFormatError("The ZIP file is not a CipherMoth backup.")
            if not archive.getinfo(LEGACY_BACKUP_MEMBER).flag_bits & 0x1:
                raise BackupFormatError("The ZIP file is not encrypted.")
            archive.setpassword(password.encode())
            with archive.open(LEGACY_BACKUP_MEMBER) as member:
                content = member.read(max_bytes + 1)
    except BackupFormatError:
        raise
    except RuntimeError as error:
        raise DecryptionFailed from error
    except Exception as error:
        raise BackupFormatError("The ZIP file could not be read.") from error
    if len(content) > max_bytes:
        raise BackupFormatError("The backup content is too large.")
    return content


def generate_totp(secret: str, *, digits: int = 6, period: int = 30) -> str:
    """
    Return the current TOTP code for a base32 secret (RFC 6238, HMAC-SHA1).

    Used by the CLI so `password get` can show the live code. The web UI has its
    own Web Crypto implementation; both stay small and dependency-free so the
    two-factor path is easy to audit.
    """
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int(time.time()) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)
