from urllib.parse import parse_qs

from url_parse import split_url

_MIN_MASTER_PASSWORD_LENGTH = 12
_MIN_CHARACTER_CLASSES = 2

_BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _character_classes(password: str) -> int:
    return sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )


def validate_master_password_strength(password: str) -> str:
    """
    Return the password unchanged, or raise ValueError if it is too weak.
    """
    if len(password) < _MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(
            f"Master password must be at least {_MIN_MASTER_PASSWORD_LENGTH} "
            "characters long."
        )

    if _character_classes(password) < _MIN_CHARACTER_CLASSES:
        raise ValueError(
            "Master password must mix at least two of: lowercase, uppercase, "
            "numbers, symbols."
        )

    return password


def require_unicode_text(value: object) -> object:
    """
    Reject strings that cannot be encoded as UTF-8. JSON allows unpaired
    surrogate escapes such as ``"\\ud800"``, which decode to Python strings that
    every encrypt, hash and database call would fail on.
    """
    for text in value if isinstance(value, list) else (value,):
        if isinstance(text, str):
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError(
                    "must be valid Unicode text (no unpaired surrogates)"
                ) from None
    return value


def reject_nul(value: str | None) -> str | None:
    if value is not None and "\x00" in value:
        raise ValueError("must not contain NUL characters")
    return value


def addressable_name(value: str | None) -> str | None:
    """
    Refuse names a URL cannot address. Browsers resolve '.' and '..' path
    segments (also when percent-encoded) before sending a request, and
    GET /passwords/trash is the trash listing, not an entry.
    """
    if value in (".", ".."):
        raise ValueError("cannot be '.' or '..'")
    if value == "trash":
        raise ValueError("'trash' is reserved, choose another name")
    return value


def normalize_totp_secret_leniently(raw: str | None) -> str | None:
    """Normalize a stored secret when possible, otherwise return it unchanged."""
    try:
        return normalize_totp_secret(raw)
    except ValueError:
        return raw


def normalize_totp_secret(raw: str | None) -> str | None:
    """
    Normalize a two-factor secret to bare base32, or raise ValueError.

    Accepts either a raw base32 secret (as shown next to most "enable 2FA" QR
    codes) or a full ``otpauth://`` URI, since users commonly paste either.
    Spaces and padding are stripped and the result is upper-cased so the same
    secret always encrypts to a comparable value. Returns None for empty input.
    """
    if not raw:
        return None

    value = raw.strip()
    if value.lower().startswith("otpauth://"):
        secret = parse_qs(split_url(value).query).get("secret", [""])[0]
        value = secret

    value = value.replace(" ", "").upper().rstrip("=")
    if not value:
        return None

    if any(c not in _BASE32_ALPHABET for c in value):
        raise ValueError("TOTP secret must be valid base32 or an otpauth:// URI.")

    return value
