"""
Biometric unlock enrollments, in a small file of their own next to the vault.

An enrollment holds the vault key wrapped under a 32-byte secret that only the
device's authenticator can produce: a passkey's PRF output in a browser, a
Secure Enclave key agreement in the macOS app. The authenticator is what asks
for the fingerprint, and the secret never rests anywhere.

This file stays out of the vault on purpose. Snapshots and backups are portable
and an enrollment is not, and the vault's schema and format stay unchanged. A
stale enrollment (a restored vault, a vault moved aside) is harmless: its key no
longer matches the vault's key check, so it opens nothing and is removed.

The password reminder asks for the master password every so often so it is not
forgotten. It is a habit, not a boundary: whoever can rewrite this file already
controls the account holding the vault.
"""

import logging
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

logger = logging.getLogger(__name__)

DEVICE_UNLOCK_FILE = "device-unlock.json"
MAX_ENROLLMENTS = 8
DEFAULT_PASSWORD_INTERVAL_DAYS = 14
_DAY_SECONDS = 86_400
# A clock moved back further than this cannot postpone the reminder.
_CLOCK_TOLERANCE_SECONDS = 300

Kind = Literal["passkey", "secure-enclave"]
PasswordIntervalDays = Literal[7, 14, 30]


class Enrollment(BaseModel):
    credential_id: str
    kind: Kind
    # What the authenticator needs to reproduce the secret: a PRF salt or a Secure
    # Enclave key blob, which is useless on any other device. Not secret.
    material: str
    wrapped_key: str

    model_config = ConfigDict(extra="forbid")


class DeviceUnlockState(BaseModel):
    version: Literal[1] = 1
    password_interval_days: PasswordIntervalDays = DEFAULT_PASSWORD_INTERVAL_DAYS
    last_password_at: float = 0.0
    enrollments: list[Enrollment] = []

    model_config = ConfigDict(extra="forbid")


class DeviceUnlockStore:
    """
    The enrollment file of one vault folder. One process serves a vault folder
    (``storage.VaultLock``) and every change is synchronous, so changes cannot
    interleave; each replaces the whole file atomically.
    """

    def __init__(self, data_dir: Path, clock: Callable[[], float] = time.time) -> None:
        self.path = data_dir / DEVICE_UNLOCK_FILE
        self.clock = clock

    def read(self) -> DeviceUnlockState:
        try:
            return DeviceUnlockState.model_validate_json(self.path.read_bytes())
        except FileNotFoundError:
            return DeviceUnlockState()
        except (OSError, ValidationError) as error:
            # Biometric unlock is a convenience: the master password still works.
            logger.warning(
                "Ignoring the biometric unlock file: %s.", type(error).__name__
            )
            return DeviceUnlockState()

    def _write(self, state: DeviceUnlockState) -> None:
        if not state.enrollments:
            self.clear()
            return
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{DEVICE_UNLOCK_FILE}.", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(state.model_dump_json().encode())
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def clear(self) -> None:
        """A file left behind opens nothing: its wrapped keys fail the key check."""
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            logger.warning(
                "Could not remove the biometric unlock file: %s.", type(error).__name__
            )

    def find(self, credential_id: str) -> Enrollment | None:
        return next(
            (
                enrollment
                for enrollment in self.read().enrollments
                if enrollment.credential_id == credential_id
            ),
            None,
        )

    def add(self, enrollment: Enrollment) -> None:
        state = self.read()
        others = [
            existing
            for existing in state.enrollments
            if existing.credential_id != enrollment.credential_id
        ]
        state.enrollments = [*others, enrollment]
        state.last_password_at = self.clock()
        self._write(state)

    def remove(self, credential_id: str) -> None:
        state = self.read()
        state.enrollments = [
            enrollment
            for enrollment in state.enrollments
            if enrollment.credential_id != credential_id
        ]
        self._write(state)

    def set_password_interval(self, days: PasswordIntervalDays) -> None:
        state = self.read()
        state.password_interval_days = days
        self._write(state)

    def has_room_for(self, credential_id: str) -> bool:
        enrollments = self.read().enrollments
        return len(enrollments) < MAX_ENROLLMENTS or any(
            enrollment.credential_id == credential_id for enrollment in enrollments
        )

    def record_password_unlock(self) -> None:
        """A failed write only means the reminder comes back sooner."""
        state = self.read()
        if not state.enrollments:
            return
        state.last_password_at = self.clock()
        try:
            self._write(state)
        except OSError as error:
            logger.warning(
                "Could not update the biometric unlock file: %s.", type(error).__name__
            )

    def password_required(self, state: DeviceUnlockState | None = None) -> bool:
        state = state or self.read()
        if not state.enrollments:
            return False
        elapsed = self.clock() - state.last_password_at
        return (
            elapsed < -_CLOCK_TOLERANCE_SECONDS
            or elapsed >= state.password_interval_days * _DAY_SECONDS
        )
