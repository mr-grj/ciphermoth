"""Exhaustive mutations of small synthetic records, without changing vectors."""

from dataclasses import replace

import pytest

import helpers


@pytest.mark.parametrize("role", ["entry", "metadata", "content"])
def test_every_record_bit_flip_and_truncation_is_refused(role: str) -> None:
    key = helpers.VaultKey(bytes(range(32)))
    uid, parent = b"e" * 16, b"p" * 16
    if role == "entry":
        sealed = key.seal_entry(uid, b'{"synthetic":true}')

        def open_record(value: bytes) -> bytes:
            return key.open_entry(uid, value)

    elif role == "metadata":
        sealed = key.seal_attachment_metadata(uid, parent, b'{"synthetic":true}')

        def open_record(value: bytes) -> bytes:
            return key.open_attachment_metadata(uid, parent, value)

    else:
        sealed = key.seal_attachment_content(uid, parent, b"synthetic content")

        def open_record(value: bytes) -> bytes:
            return key.open_attachment_content(uid, parent, value)

    assert open_record(sealed).rstrip(b" ") in (
        b'{"synthetic":true}',
        b"synthetic content",
    )
    for length in range(len(sealed)):
        with pytest.raises(helpers.DecryptionFailed):
            open_record(sealed[:length])
    for offset in range(len(sealed)):
        for bit in range(8):
            altered = bytearray(sealed)
            altered[offset] ^= 1 << bit
            with pytest.raises(helpers.DecryptionFailed):
                open_record(bytes(altered))
    with pytest.raises(helpers.DecryptionFailed):
        open_record(sealed + b"\x00")


def test_a_wrong_commitment_never_attempts_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived = b"d" * 32
    material = helpers.seal_key_material(
        derived, b"k" * 32, helpers.DEFAULT_KDF, b"s" * 16
    )

    def forbidden_unwrap(*args: object) -> bytes:
        pytest.fail("Unwrap ran before the password commitment matched")

    monkeypatch.setattr(helpers, "_open", forbidden_unwrap)
    assert helpers.open_key_material(b"x" * 32, material) is None
    assert (
        helpers.open_key_material(derived, replace(material, password_check=b"x" * 32))
        is None
    )
