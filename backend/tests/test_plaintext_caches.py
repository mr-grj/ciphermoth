import json
import secrets
import sys
from typing import Protocol, cast
from urllib.parse import urlsplit

import pytest

from crud.backup import BackupEntry, BackupField
from tests.support import backup_entry
from url_match import normalize
from validators import normalize_totp_secret


class _CachedParser(Protocol):
    def cache_info(self) -> object: ...


@pytest.mark.parametrize(
    "url",
    [
        "https://cache-canary.example.test/private-vault-path",
        "https://cache-canary.example.test:99999/private-vault-path",
    ],
)
def test_saved_urls_do_not_enter_the_stdlib_parser_cache(url: str) -> None:
    cache_info = cast(_CachedParser, urlsplit).cache_info
    before = cache_info()
    normalize(url)
    assert cache_info() == before


def test_totp_setup_uri_does_not_enter_the_stdlib_parser_cache() -> None:
    cache_info = cast(_CachedParser, urlsplit).cache_info
    before = cache_info()
    assert (
        normalize_totp_secret(
            "otpauth://totp/cache-canary?secret=JBSWY3DPEHPK3PXP&issuer=Audit"
        )
        == "JBSWY3DPEHPK3PXP"
    )
    assert cache_info() == before


def test_backup_password_is_released_when_its_model_is_dropped() -> None:
    raw = json.dumps(backup_entry("cache canary", secrets.token_hex(16))).encode()
    parsed = BackupEntry.model_validate_json(raw, strict=True)
    plaintext = parsed.value
    del parsed
    # Only this local variable and getrefcount's argument may retain the string.
    # A parser cache would keep an extra reference beyond the operation.
    assert sys.getrefcount(plaintext) == 2


def test_backup_custom_field_is_released_when_its_model_is_dropped() -> None:
    raw = json.dumps(
        {"label": "cache canary", "value": secrets.token_hex(16), "hidden": True}
    ).encode()
    parsed = BackupField.model_validate_json(raw, strict=True)
    plaintext = parsed.value
    del parsed
    assert sys.getrefcount(plaintext) == 2
