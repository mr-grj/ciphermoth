"""
A FIDO2 client for the CLI and the desktop app, which talk to the security key
over USB (CTAP2) instead of through a browser. It returns exactly what a
browser's WebAuthn API returns, built with the origin ``https://<rp id>``, plus
the key's PRF output (CTAP2 hmac-secret), so the server checks every client the
same way (``webauthn.py``).

The key always verifies its user (its PIN, or a fingerprint on keys that have
one), like browsers do: its PRF output differs between uses with and without
verification, so every client must ask the same way.
"""

import base64
import sys
import time
from collections.abc import Callable, Iterable
from threading import Event

from fido2.client import (
    ClientError,
    DefaultClientDataCollector,
    Fido2Client,
    PinRequiredError,
    UserInteraction,
)
from fido2.ctap import CtapError
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# The desktop app has no web origin; its keys belong to this relying party.
DESKTOP_RP_ID = "localhost"
_WAIT_FOR_KEY_SECONDS = 60
_POLL_SECONDS = 0.25


class SecurityKeyError(Exception):
    """A message meant for the user."""


class SecurityKeyCancelled(SecurityKeyError):
    pass


class SecurityKeyPinInvalid(SecurityKeyError):
    pass


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class _Prompt(UserInteraction):
    def __init__(
        self, on_touch: Callable[[], None], get_pin: Callable[[], str | None]
    ) -> None:
        self._on_touch = on_touch
        self._get_pin = get_pin

    def prompt_up(self) -> None:
        self._on_touch()

    def request_pin(self, permissions, rp_id) -> str | None:
        return self._get_pin()

    def request_uv(self, permissions, rp_id) -> bool:
        return True


def _windows_client(origin: str, prompt: _Prompt):
    """Windows only lets administrators talk to FIDO keys directly; everyone
    else goes through the system's WebAuthn API, which supports PRF."""
    if sys.platform != "win32":
        return None
    from fido2.client.windows import WindowsClient

    if not WindowsClient.is_available():
        return None
    return WindowsClient(DefaultClientDataCollector(origin))


def _devices() -> list:
    from fido2.hid import CtapHidDevice

    return list(CtapHidDevice.list_devices())


def _clients(origin: str, prompt: _Prompt, event: Event) -> Iterable:
    windows = _windows_client(origin, prompt)
    if windows is not None:
        yield windows
        return
    deadline = time.monotonic() + _WAIT_FOR_KEY_SECONDS
    devices = _devices()
    while not devices:
        if event.is_set():
            raise SecurityKeyCancelled("Cancelled.")
        if time.monotonic() > deadline:
            raise SecurityKeyError("No security key found. Insert it and try again.")
        time.sleep(_POLL_SECONDS)
        devices = _devices()
    for device in devices:
        yield Fido2Client(
            device,
            client_data_collector=DefaultClientDataCollector(origin),
            user_interaction=prompt,
        )


def _failure(error: ClientError) -> SecurityKeyError:
    cause = getattr(error, "cause", None)
    code = getattr(cause, "code", None)
    if code == CtapError.ERR.PIN_INVALID:
        return SecurityKeyPinInvalid("That PIN is not right. Try again.")
    if code in (CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
        return SecurityKeyError(
            "The security key's PIN is blocked. Remove and reinsert the key, or "
            "reset it (that also removes its registrations)."
        )
    if code == CtapError.ERR.PIN_NOT_SET:
        return SecurityKeyError(
            "Set a PIN on this security key first (for example with YubiKey "
            "Manager, or by registering it once in Chrome)."
        )
    if error.code == ClientError.ERR.TIMEOUT:
        return SecurityKeyCancelled("The security key was not touched in time.")
    if error.code == ClientError.ERR.DEVICE_INELIGIBLE:
        return SecurityKeyError(
            "This security key is not registered here, or is already registered."
        )
    return SecurityKeyError("The security key could not be used. Try again.")


def register(
    options: dict,
    rp_id: str,
    on_touch: Callable[[], None] = lambda: None,
    get_pin: Callable[[], str | None] = lambda: None,
    event: Event | None = None,
) -> dict:
    """Create a credential from the server's registration options; returns
    ``{"credential_id", "registration"}``."""
    event = event or Event()
    origin = f"https://{rp_id}"
    creation = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name=options["rp_name"], id=rp_id),
        user=PublicKeyCredentialUserEntity(
            name="CipherMoth vault",
            id=_decode(options["user_id"]),
            display_name="CipherMoth vault",
        ),
        challenge=_decode(options["challenge"]),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg
            )
            for alg in options["algorithms"]
        ],
        timeout=options["timeout_ms"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY, id=_decode(credential)
            )
            for credential in options["exclude_credentials"]
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
        extensions={"prf": {}},
    )
    last: SecurityKeyError | None = None
    for client in _clients(origin, _Prompt(on_touch, get_pin), event):
        try:
            result = client.make_credential(creation, event=event)
        except PinRequiredError:
            raise SecurityKeyError("The security key's PIN is needed.") from None
        except ClientError as error:
            last = _failure(error)
            if isinstance(last, SecurityKeyPinInvalid | SecurityKeyCancelled):
                raise last from None
            continue
        prf = (result.client_extension_results or {}).get("prf") or {}
        if not prf.get("enabled"):
            raise SecurityKeyError(
                "This security key cannot derive an encryption key (it lacks the "
                "FIDO2 hmac-secret extension). Use a FIDO2 key such as a YubiKey 5."
            )
        return {
            "credential_id": _encode(result.raw_id),
            "registration": {
                "client_data_json": _encode(result.response.client_data),
                "attestation_object": _encode(
                    bytes(result.response.attestation_object)
                ),
            },
        }
    raise last or SecurityKeyError("No security key answered.")


def answer(
    challenge: dict,
    on_touch: Callable[[], None] = lambda: None,
    get_pin: Callable[[], str | None] = lambda: None,
    event: Event | None = None,
) -> dict:
    """Answer a challenge from the server (``SecurityKeyChallenge``) with any
    registered key that is plugged in; returns a ``SecurityKeyAssertion``."""
    event = event or Event()
    keys = challenge["keys"]
    if not keys:
        raise SecurityKeyError("This vault has no security keys.")
    rp_id = keys[0]["rp_id"]
    group = [key for key in keys if key["rp_id"] == rp_id]
    request = PublicKeyCredentialRequestOptions(
        challenge=_decode(challenge["challenge"]),
        timeout=challenge["timeout_ms"],
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=_decode(key["credential_id"]),
            )
            for key in group
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        extensions={
            "prf": {
                "evalByCredential": {
                    key["credential_id"]: {"first": key["prf_salt"]} for key in group
                }
            }
        },
    )
    last: SecurityKeyError | None = None
    for client in _clients(f"https://{rp_id}", _Prompt(on_touch, get_pin), event):
        try:
            response = client.get_assertion(request, event=event).get_response(0)
        except PinRequiredError:
            raise SecurityKeyError("The security key's PIN is needed.") from None
        except ClientError as error:
            last = _failure(error)
            if isinstance(last, SecurityKeyPinInvalid | SecurityKeyCancelled):
                raise last from None
            continue
        prf = (response.client_extension_results or {}).get("prf") or {}
        first = (prf.get("results") or {}).get("first")
        if not first:
            raise SecurityKeyError("The security key did not return its secret.")
        secret = first if isinstance(first, bytes) else _decode(first)
        return {
            "credential_id": _encode(response.raw_id),
            "client_data_json": _encode(response.response.client_data),
            "authenticator_data": _encode(bytes(response.response.authenticator_data)),
            "signature": _encode(response.response.signature),
            "prf_output": _encode(secret),
        }
    raise last or SecurityKeyError("No registered security key answered.")
