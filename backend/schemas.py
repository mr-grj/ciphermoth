import base64
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from device_unlock import Kind as DeviceKind
from device_unlock import PasswordIntervalDays
from helpers import KEY_BYTES
from validators import (
    addressable_name,
    normalize_totp_secret,
    normalize_totp_secret_leniently,
    reject_nul,
    require_unicode_text,
    validate_master_password_strength,
)

_MAX_TAGS = 20
_MAX_TAG_LENGTH = 40
_MAX_CUSTOM_FIELDS = 30
_MAX_FIELD_LABEL = 100
_MAX_FIELD_VALUE = 4096
_MAX_FOLDER_LENGTH = 200
_MAX_DESCRIPTION_LENGTH = 10_000


class SimpleDetailSchema(BaseModel):
    detail: str


class MetaResponse(BaseModel):
    version: str
    features: list[str] = Field(default_factory=list)


class MasterPassword(BaseModel):
    master_password: str = Field(min_length=1, max_length=1024)

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)


def _decode_base64url_field(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


_B64 = r"^[A-Za-z0-9_-]+$"


class SecurityKeyAssertion(BaseModel):
    """One answer from a security key, as WebAuthn defines it (base64url), plus
    its PRF output for the salt the vault gave."""

    credential_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,1400}$")]
    client_data_json: Annotated[str, StringConstraints(pattern=_B64, max_length=8192)]
    authenticator_data: Annotated[str, StringConstraints(pattern=_B64, max_length=8192)]
    signature: Annotated[str, StringConstraints(pattern=_B64, max_length=2048)]
    prf_output: Annotated[str, StringConstraints(pattern=_B64, max_length=64)]

    model_config = ConfigDict(extra="forbid")

    @field_validator("prf_output")
    @classmethod
    def _is_a_key(cls, value: str) -> str:
        try:
            decoded = _decode_base64url_field(value)
        except ValueError:
            raise ValueError("must be base64url") from None
        if len(decoded) != KEY_BYTES:
            raise ValueError(f"must decode to {KEY_BYTES} bytes")
        return value

    def raw(self, name: str) -> bytes:
        return _decode_base64url_field(getattr(self, name))


class Confirmation(MasterPassword):
    """What sensitive changes ask for: the master password, and an answer from a
    registered security key when the vault requires one."""

    security_key: SecurityKeyAssertion | None = None


class MasterPasswordCreatePayload(MasterPassword):
    @field_validator("master_password")
    @classmethod
    def _strong(cls, value: str) -> str:
        return validate_master_password_strength(value)


class VaultUnlock(BaseModel):
    valid: bool
    session_token: str | None = None
    idle_timeout_ms: int | None = None


_CredentialId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,1400}$")]
_Base64Url = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]+$")]


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class DeviceUnlockRequest(BaseModel):
    credential_id: _CredentialId
    secret: _Base64Url = Field(max_length=64)

    @field_validator("secret")
    @classmethod
    def _is_a_key(cls, value: str) -> str:
        try:
            decoded = _decode_base64url(value)
        except ValueError:
            raise ValueError("must be base64url") from None
        if len(decoded) != KEY_BYTES:
            raise ValueError(f"must decode to {KEY_BYTES} bytes")
        return value

    def secret_bytes(self) -> bytes:
        return _decode_base64url(self.secret)


class DeviceEnrollRequest(DeviceUnlockRequest, Confirmation):
    kind: DeviceKind
    material: _Base64Url = Field(max_length=4096)


class DeviceEnrollmentInfo(BaseModel):
    credential_id: str
    kind: DeviceKind
    material: str


class DeviceUnlockStatus(BaseModel):
    enrollments: list[DeviceEnrollmentInfo]
    password_required: bool
    password_interval_days: PasswordIntervalDays


class DeviceUnlockSettings(BaseModel):
    password_interval_days: PasswordIntervalDays


class DeviceUnlockResult(VaultUnlock):
    password_required: bool = False


class MasterPasswordCreate(BaseModel):
    created: bool
    detail: str
    session_token: str
    idle_timeout_ms: int


class VaultSessionStatus(BaseModel):
    idle_timeout_ms: int
    expires_in_ms: int


class VaultLock(BaseModel):
    locked: bool


class MasterPasswordUpdate(BaseModel):
    updated: bool
    detail: str


class MasterPasswordUpdatePayload(BaseModel):
    master_password: str = Field(min_length=1, max_length=1024)
    new_master_password: str = Field(min_length=1, max_length=1024)
    security_key: SecurityKeyAssertion | None = None

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)

    @field_validator("new_master_password")
    @classmethod
    def _strong(cls, value: str) -> str:
        return validate_master_password_strength(value)


class MasterPasswordStatus(BaseModel):
    initialized: bool
    security_key_required: bool = False
    recovery_code: bool = False


class SecurityKeyDescriptor(BaseModel):
    credential_id: str
    rp_id: str
    prf_salt: str


class SecurityKeyChallenge(BaseModel):
    """What a client needs to ask a registered security key for its answer."""

    challenge: str
    timeout_ms: int
    keys: list[SecurityKeyDescriptor]


class SecurityKeyRegistrationOptions(BaseModel):
    """The two requests that register a security key: create a credential
    (``challenge``), then ask it once for its PRF output for ``prf_salt``
    (``secret_challenge``), which is what proves it can protect the vault."""

    challenge: str
    secret_challenge: str
    prf_salt: str
    user_id: str
    rp_name: str
    timeout_ms: int
    algorithms: list[int]
    exclude_credentials: list[str]


class SecurityKeyRegistration(BaseModel):
    client_data_json: Annotated[str, StringConstraints(pattern=_B64, max_length=8192)]
    attestation_object: Annotated[
        str, StringConstraints(pattern=_B64, max_length=16384)
    ]

    model_config = ConfigDict(extra="forbid")

    def raw(self, name: str) -> bytes:
        return _decode_base64url_field(getattr(self, name))


_MAX_SECURITY_KEY_NAME = 64


class SecurityKeyName(BaseModel):
    name: str = Field(min_length=1, max_length=_MAX_SECURITY_KEY_NAME)

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("name")
    @classmethod
    def _text(cls, value: str) -> str:
        require_unicode_text(value)
        reject_nul(value)
        return value


class SecurityKeyAdd(SecurityKeyName):
    confirmation: Confirmation
    registration: SecurityKeyRegistration
    assertion: SecurityKeyAssertion

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecurityKeyInfo(BaseModel):
    id: int
    name: str
    rp_id: str
    created: datetime
    last_used: datetime | None


class SecurityStatus(BaseModel):
    security_keys: list[SecurityKeyInfo]
    security_key_required: bool
    recovery_code: bool
    recovery_code_created: datetime | None


class RecoveryCodeResult(BaseModel):
    recovery_code: str
    status: SecurityStatus


class RecoverPayload(BaseModel):
    recovery_code: str = Field(min_length=1, max_length=128)
    new_master_password: str = Field(min_length=1, max_length=1024)
    keep_security_keys: bool = True

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("recovery_code", "new_master_password")
    @classmethod
    def _unicode(cls, value: str) -> str:
        require_unicode_text(value)
        return value

    @field_validator("new_master_password")
    @classmethod
    def _strong(cls, value: str) -> str:
        return validate_master_password_strength(value)


class RecoverResult(BaseModel):
    detail: str
    session_token: str
    idle_timeout_ms: int
    recovery_code: str
    security_key_required: bool


class CustomField(BaseModel):
    label: str = Field(default="", max_length=_MAX_FIELD_LABEL)
    value: str = Field(default="", max_length=_MAX_FIELD_VALUE)
    hidden: bool = False

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)


class Password(BaseModel):
    password_name: str = Field(min_length=1, max_length=255)
    kind: str = Field(default="login")
    username: str | None = Field(default=None, max_length=255)
    password_value: Annotated[
        str, StringConstraints(strip_whitespace=False, min_length=1)
    ]
    url: str | None = Field(default=None, max_length=2048)
    totp_secret: str | None = Field(default=None, max_length=512)
    description: str | None = Field(default=None, max_length=_MAX_DESCRIPTION_LENGTH)
    tags: list[str] = Field(default_factory=list, max_length=_MAX_TAGS)
    custom_fields: list[CustomField] = Field(
        default_factory=list, max_length=_MAX_CUSTOM_FIELDS
    )
    folder: str | None = Field(default=None, max_length=_MAX_FOLDER_LENGTH)
    favorite: bool = False

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)

    @field_validator("password_name", "username", "description")
    @classmethod
    def _storable_as_text(cls, value: str | None) -> str | None:
        return reject_nul(value)

    @field_validator("password_name")
    @classmethod
    def _addressable(cls, value: str | None) -> str | None:
        return addressable_name(value)

    @field_validator("totp_secret")
    @classmethod
    def _normalize_totp(cls, value: str | None) -> str | None:
        return normalize_totp_secret(value)

    @field_validator("folder")
    @classmethod
    def _clean_folder(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("kind")
    @classmethod
    def _clean_kind(cls, value: str) -> str:
        return value if value in ("login", "note") else "login"

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for tag in value:
            tag = tag.strip()[:_MAX_TAG_LENGTH].strip()
            if tag and tag not in cleaned:
                cleaned.append(tag)
        return cleaned

    @field_validator("custom_fields")
    @classmethod
    def _clean_custom_fields(cls, value: list[CustomField]) -> list[CustomField]:
        return [field for field in value if field.label]


class PasswordHistoryEntry(BaseModel):
    value: str
    changed_at: datetime


class StoredCustomField(BaseModel):
    label: str
    value: str = ""
    hidden: bool = False

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)


class RestoredPassword(BaseModel):
    """
    An entry from a CipherMoth backup, restored exactly as the vault held it.

    A backup must restore whatever the vault it came from could hold, and
    vaults written by imports before v1.4.7 can hold values over the input
    limits, untrimmed names, invalid 2FA secrets and names such as '.' that new
    entries may not use, so only what the database cannot store is refused.
    Reads tolerate the rest, and editing the entry applies the normal rules.
    """

    password_name: str = Field(min_length=1)
    kind: str = "login"
    username: str | None = None
    password_value: str = Field(min_length=1)
    url: str | None = None
    totp_secret: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    custom_fields: list[StoredCustomField] = Field(default_factory=list)
    folder: str | None = None
    favorite: bool = False

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)

    @field_validator("password_name", "username", "description")
    @classmethod
    def _storable_as_text(cls, value: str | None) -> str | None:
        return reject_nul(value)

    @field_validator("totp_secret")
    @classmethod
    def _normalize_totp(cls, value: str | None) -> str | None:
        return normalize_totp_secret_leniently(value)

    @field_validator("folder")
    @classmethod
    def _clean_folder(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("kind")
    @classmethod
    def _clean_kind(cls, value: str) -> str:
        return value if value in ("login", "note") else "login"


class PasswordResponse(BaseModel):
    id: int
    password_name: str
    kind: str = "login"
    username: str | None = None
    password_value: str
    url: str | None = None
    totp_secret: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    custom_fields: list[StoredCustomField] = Field(default_factory=list)
    folder: str | None = None
    favorite: bool = False
    backed_up: bool
    updated: datetime
    deleted: datetime | None = None
    password_history: list[PasswordHistoryEntry] = Field(default_factory=list)
    attachment_count: int = 0


class AttachmentResponse(BaseModel):
    id: int
    filename: str
    content_type: str | None = None
    size_bytes: int
    created: datetime


class FavoriteUpdatePayload(BaseModel):
    favorite: bool


class PasswordCreate(BaseModel):
    created: bool
    detail: str


class PasswordUpdate(BaseModel):
    updated: bool
    detail: str


class PasswordDelete(BaseModel):
    deleted: bool
    detail: str


class PasswordRef(BaseModel):
    password_name: str = Field(min_length=1)

    @field_validator("*")
    @classmethod
    def _unicode(cls, value: object) -> object:
        return require_unicode_text(value)

    @field_validator("password_name")
    @classmethod
    def _storable_as_text(cls, value: str | None) -> str | None:
        return reject_nul(value)


class PasswordUpdatePayload(BaseModel):
    password: PasswordRef
    new_password: Password


MAX_BULK_ENTRIES = 10_000


class TrashedEntryRef(PasswordRef):
    entry_id: int = Field(gt=0)


class BulkTrashPayload(BaseModel):
    """Active entries to move to the trash together, by name."""

    entries: list[PasswordRef] = Field(min_length=1, max_length=MAX_BULK_ENTRIES)

    @model_validator(mode="after")
    def _distinct(self) -> "BulkTrashPayload":
        if len({e.password_name for e in self.entries}) != len(self.entries):
            raise ValueError("Each entry may be listed only once.")
        return self


class BulkTrashedPayload(BaseModel):
    """Trashed entries to restore or delete together, by name and id."""

    entries: list[TrashedEntryRef] = Field(min_length=1, max_length=MAX_BULK_ENTRIES)

    @model_validator(mode="after")
    def _distinct(self) -> "BulkTrashedPayload":
        if len({e.entry_id for e in self.entries}) != len(self.entries):
            raise ValueError("Each entry may be listed only once.")
        return self


class BulkResult(BaseModel):
    count: int
    detail: str


class SettingsResponse(BaseModel):
    inactivity_ms: int
    warn_before_ms: int
    hidden_ms: int
    debounce_ms: int
    clipboard_clear_ms: int
    update_check_enabled: bool


class SettingsUpdate(BaseModel):
    inactivity_ms: int = Field(ge=30_000, le=3_600_000)
    warn_before_ms: int = Field(ge=5_000, le=600_000)
    hidden_ms: int = Field(ge=10_000, le=3_600_000)
    debounce_ms: int = Field(ge=100, le=10_000)
    clipboard_clear_ms: int = Field(ge=5_000, le=600_000)
    update_check_enabled: bool

    @model_validator(mode="after")
    def _warning_comes_before_the_lock(self) -> "SettingsUpdate":
        if self.warn_before_ms >= self.inactivity_ms:
            raise ValueError("warn_before_ms must be shorter than inactivity_ms.")
        return self


class OnConflict(StrEnum):
    skip = "skip"
    overwrite = "overwrite"


class ImportRowReport(BaseModel):
    where: str
    name: str | None = None
    reason: str


class PasswordImportResult(BaseModel):
    imported: int
    skipped: int
    overwritten: int
    total: int
    ignored: int = 0
    ignored_rows: list[ImportRowReport] = Field(default_factory=list)
    renamed: int = 0
    renamed_rows: list[ImportRowReport] = Field(default_factory=list)
    trashed: int = 0
    attachments: int = 0
    settings_restored: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str
    schema_state: str = Field(serialization_alias="schema")


class DamagedRows(BaseModel):
    entries: list[int]
    attachments: list[int]
