"""
Write the frozen cryptographic test vectors in testdata/vectors.

The vectors are generated once and committed; tests only ever read them. Every
expected value is computed from the primitive libraries following the
construction documented in testdata/vectors/README.md, not from helpers.py,
so the tests check the application against an independent derivation.

Run from backend/: uv run python -m tests.tools.generate_vectors --only NAME...
(new files only; --force overwrites frozen ones and is never needed).
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import struct
import sys
import unicodedata
from pathlib import Path

import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OUT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"
FORMAT = "ciphermoth-test-vectors/1"


def argon2id_key(password: str, salt: bytes) -> str:
    raw = Argon2id(
        salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536
    ).derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw).decode()


def raw_argon2id(password: str, salt: bytes) -> bytes:
    return Argon2id(
        salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536
    ).derive(password.encode("utf-8"))


def hkdf(key: bytes, label: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()
    ).derive(key)


def seal(key: bytes, nonce: bytes, plaintext: bytes, associated: bytes) -> bytes:
    return b"\x02" + nonce + AESGCM(key).encrypt(nonce, plaintext, associated)


def record_associated_data(*parts: bytes) -> bytes:
    data = b"\x02ciphermoth/v2"
    for part in parts:
        data += struct.pack(">I", len(part)) + part
    return data


def padded(document: bytes) -> bytes:
    return document + b" " * (-len(document) % 64)


def wrap_associated_data(salt: bytes) -> bytes:
    return (
        b"ciphermoth/v2/wrapped-vault-key" + struct.pack(">HIII", 2, 65536, 3, 4) + salt
    )


def fixed(byte: int, length: int) -> bytes:
    return bytes((byte + n) % 256 for n in range(length))


def doc(name: str, description: str, **sections: object) -> dict:
    return {"format": FORMAT, "name": name, "description": description, **sections}


ARGON2_PASSWORDS = [
    ("Moth-Test-Vault-2026!", "00" * 16, "ASCII"),
    ("correct horse battery staple", "ff" * 16, "spaces inside"),
    ("Mölle-Stern-2026", "a1b2c3d4e5f60718293a4b5c6d7e8f90", "NFC"),
    (
        unicodedata.normalize("NFD", "Mölle-Stern-2026"),
        "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "NFD form of the previous vector: no Unicode normalization, different key",
    ),
    ("ключ-вольта-2026", "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "Cyrillic"),
    ("パスワード2026!", "13579bdf02468ace13579bdf02468ace", "Japanese"),
    ("🦋 moth 🦋 2026", "deadbeefdeadbeefdeadbeefdeadbeef", "emoji, 4-byte UTF-8"),
    ("סיסמה-2026-ok", "0123456789abcdeffedcba9876543210", "right-to-left"),
    ("two  spaces\tand\ttabs 2026", "55" * 16, "inner whitespace is kept"),
    ("x" * 1023 + "!", "77" * 16, "1024 characters, the API maximum"),
]

STRIP_CASES = [
    ("  Moth-Test-Vault-2026!  ", "Moth-Test-Vault-2026!"),
    ("\tMoth-Test-Vault-2026!\n", "Moth-Test-Vault-2026!"),
    (" Moth-Test-Vault-2026!　", "Moth-Test-Vault-2026!"),
    ("​Moth-Test-Vault-2026!", "​Moth-Test-Vault-2026!"),
    ("\x1cMoth-Test-Vault-2026!", "\x1cMoth-Test-Vault-2026!"),
    ("Moth Test Vault 2026!", "Moth Test Vault 2026!"),
]


def argon2id_vectors() -> dict:
    vectors = [
        {
            "password": password,
            "password_utf8_hex": password.encode().hex(),
            "salt_hex": salt,
            "key": argon2id_key(password, bytes.fromhex(salt)),
            "note": note,
        }
        for password, salt, note in ARGON2_PASSWORDS
    ]
    return doc(
        "argon2id",
        "Vault key derivation. key = base64url(Argon2id(password_utf8, salt, "
        "m=65536 KiB, t=3, p=4, length=32, version 0x13, no secret, no "
        "associated data)), 44 characters with '=' padding. The result is used "
        "directly as a Fernet key. No Unicode normalization is applied.",
        parameters={
            "memory_cost_kib": 65536,
            "iterations": 3,
            "lanes": 4,
            "length": 32,
            "salt_length": 16,
            "version": 19,
        },
        vectors=vectors,
        api_input={
            "description": "The API strips the master password with pydantic's "
            "str_strip_whitespace (Unicode White_Space) before hashing and "
            "derivation. Characters such as U+200B or U+001C are not stripped, "
            "unlike Python's str.strip(). kdf_input is what reaches Argon2id "
            "and bcrypt.",
            "cases": [
                {"submitted": submitted, "kdf_input": kdf_input}
                for submitted, kdf_input in STRIP_CASES
            ],
        },
    )


def backup_entries() -> list[dict]:
    return [
        {
            "name": "GitHub #work",
            "kind": "login",
            "username": "moth@example.com",
            "value": "gh-Secret-1",
            "url": "https://github.com",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "description": "work account",
            "tags": ["dev", "ops"],
            "custom_fields": [{"label": "Recovery", "value": "abcd", "hidden": True}],
            "folder": "Work",
            "favorite": True,
        },
        {
            "name": "Wi-Fi ключ",
            "kind": "note",
            "username": None,
            "value": "  line one\n\tline two\n\n",
            "url": None,
            "totp_secret": None,
            "description": None,
            "tags": [],
            "custom_fields": [],
            "folder": None,
            "favorite": False,
        },
    ]


def backup_vectors() -> tuple[dict, bytes]:
    password = "Mölle-Stern-2026"
    payload = json.dumps(
        {"exported_at": "2026-10-10T12:00:00+00:00", "passwords": backup_entries()},
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr("ciphermoth_backup.json", payload)
    return (
        doc(
            "backup_zip",
            "Backup format v1: a ZIP with one member, ciphermoth_backup.json, "
            "deflate-compressed and encrypted with WinZip AES-256 (AE-2, "
            "PBKDF2-HMAC-SHA1 with 1000 iterations and a 16-byte salt, as "
            "written by pyzipper) under the UTF-8 master password as submitted "
            "after whitespace stripping. The JSON is {exported_at, passwords: "
            "[{name, kind, username, value, url, totp_secret, description, "
            "tags, custom_fields, folder, favorite}]}; releases before v1.4.0 "
            "wrote only name, username, value, url, totp_secret, description, "
            "tags and favorite. History, trash, attachments, settings and "
            "timestamps are not included.",
            file="backup-v1.zip",
            password=password,
            member="ciphermoth_backup.json",
            json=json.loads(payload),
        ),
        buffer.getvalue(),
    )


VAULTS = [
    ("Moth-Test-Vault-2026!", fixed(0x10, 16), fixed(0x40, 32), fixed(0x90, 12)),
    ("Mölle-Stern-2026 🦋", fixed(0xA0, 16), fixed(0xC0, 32), fixed(0xE0, 12)),
]
NAMES = [
    ("GitHub", "ASCII"),
    ("github", "case matters"),
    (" GitHub", "leading space matters (the API strips new names)"),
    ("Mölle", "NFC"),
    (unicodedata.normalize("NFD", "Mölle"), "NFD: a different name"),
    ("a/b", "slash"),
    ("x/purge", "a name that looks like a route"),
    ("..", "dot segment (restored entries may hold it)"),
    ("Wi-Fi ключ 🦋", "multi-byte UTF-8"),
]


def _document(**fields: object) -> bytes:
    base = {
        "name": "GitHub",
        "kind": "login",
        "username": "moth@example.com",
        "value": "gh-Secret-1",
        "url": "https://github.com",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "description": "work account",
        "tags": ["dev", "ops"],
        "custom_fields": [{"label": "PIN", "value": "1234", "hidden": True}],
        "folder": "Work",
        "favorite": True,
        "history": [
            {"value": "old-Secret-0", "changed_at": "2026-01-01T00:00:00+00:00"}
        ],
    }
    base.update(fields)
    return json.dumps(base, ensure_ascii=False).encode("utf-8")


def vault_v2_vectors() -> dict:
    vaults = []
    for password, salt, vault_key, nonce in VAULTS:
        derived = raw_argon2id(password, salt)
        wrapping = hkdf(derived, "ciphermoth/v2/key-wrapping")
        vaults.append(
            {
                "password": password,
                "salt_hex": salt.hex(),
                "derived_hex": derived.hex(),
                "password_check_hex": hkdf(
                    derived, "ciphermoth/v2/password-commitment"
                ).hex(),
                "key_wrapping_key_hex": wrapping.hex(),
                "vault_key_hex": vault_key.hex(),
                "wrap_associated_data_hex": wrap_associated_data(salt).hex(),
                "wrapped_key_hex": seal(
                    wrapping, nonce, vault_key, wrap_associated_data(salt)
                ).hex(),
                "key_check_hex": hkdf(vault_key, "ciphermoth/v2/key-check").hex(),
                "record_key_hex": hkdf(
                    vault_key, "ciphermoth/v2/record-encryption"
                ).hex(),
                "name_index_key_hex": hkdf(vault_key, "ciphermoth/v2/name-index").hex(),
            }
        )
    vault_key = VAULTS[0][2]
    record_key = hkdf(vault_key, "ciphermoth/v2/record-encryption")
    index_key = hkdf(vault_key, "ciphermoth/v2/name-index")
    entry_uid, attachment_uid = fixed(0x01, 16), fixed(0x21, 16)
    content = bytes(range(256)) + b"\xff\xfe\x00\x80"
    plain_records = [
        ("entry", (b"entry", entry_uid), padded(_document()), "a login"),
        (
            "entry",
            (b"entry", entry_uid),
            padded(
                _document(
                    name="Wi-Fi ключ 🦋",
                    kind="note",
                    username=None,
                    value="  line one\n\tline two\n\n",
                    url=None,
                    totp_secret=None,
                    description=None,
                    tags=[],
                    custom_fields=[],
                    folder=None,
                    favorite=False,
                    history=[],
                )
            ),
            "a secure note",
        ),
        (
            "attachment-metadata",
            (b"attachment-metadata", attachment_uid, entry_uid),
            padded(
                json.dumps(
                    {"filename": "Preț ünïcode.bin", "content_type": "x/test"},
                    ensure_ascii=False,
                ).encode()
            ),
            "attachment name and type",
        ),
        (
            "attachment-content",
            (b"attachment-content", attachment_uid, entry_uid),
            content,
            "attachment bytes, not UTF-8, not padded",
        ),
    ]
    records = []
    for index, (role, parts, plaintext, note) in enumerate(plain_records):
        nonce = fixed(0x60 + index, 12)
        associated = record_associated_data(*parts)
        records.append(
            {
                "role": role,
                "parts_hex": [part.hex() for part in parts],
                "associated_data_hex": associated.hex(),
                "nonce_hex": nonce.hex(),
                "plaintext_hex": plaintext.hex(),
                "sealed_hex": seal(record_key, nonce, plaintext, associated).hex(),
                "note": note,
            }
        )
    login = bytes.fromhex(str(records[0]["sealed_hex"]))
    rejected = [
        {
            "sealed_hex": login[:-1].hex(),
            "parts_hex": records[0]["parts_hex"],
            "note": "truncated tag",
        },
        {
            "sealed_hex": (login[:20] + bytes([login[20] ^ 1]) + login[21:]).hex(),
            "parts_hex": records[0]["parts_hex"],
            "note": "one ciphertext bit flipped",
        },
        {
            "sealed_hex": (b"\x03" + login[1:]).hex(),
            "parts_hex": records[0]["parts_hex"],
            "note": "unknown version byte",
        },
        {
            "sealed_hex": login.hex(),
            "parts_hex": [b"entry".hex(), fixed(0x02, 16).hex()],
            "note": "moved to another entry (other uid)",
        },
        {
            "sealed_hex": login.hex(),
            "parts_hex": [
                b"attachment-metadata".hex(),
                fixed(0x01, 16).hex(),
                entry_uid.hex(),
            ],
            "note": "moved to another role",
        },
        {
            "sealed_hex": records[3]["sealed_hex"],
            "parts_hex": [
                b"attachment-content".hex(),
                attachment_uid.hex(),
                fixed(0x02, 16).hex(),
            ],
            "note": "attachment moved to another entry",
        },
    ]
    return doc(
        "vault_v2",
        "Vault format 2 (docs/VAULT_FORMAT.md). derived = Argon2id(password, "
        "salt, m=65536 KiB, t=3, p=4, 32 bytes); password_check = HKDF-SHA256("
        "derived, info='ciphermoth/v2/password-commitment'); key_wrapping_key = "
        "HKDF(derived, 'ciphermoth/v2/key-wrapping'); wrapped_key = 0x02 || nonce "
        "|| AES-256-GCM(key_wrapping_key, nonce, vault_key, wrap_associated_data); "
        "key_check, record_key and name_index_key = HKDF(vault_key, "
        "'ciphermoth/v2/key-check' | 'ciphermoth/v2/record-encryption' | "
        "'ciphermoth/v2/name-index'). HKDF uses no salt and 32-byte output. A "
        "sealed record = 0x02 || nonce || AES-256-GCM(record_key, nonce, "
        "plaintext, 0x02 || 'ciphermoth/v2' || (u32 BE length || part)...). Name "
        "index = HMAC-SHA256(name_index_key, UTF-8 name). Documents are JSON "
        "padded with spaces to a multiple of 64 bytes.",
        vaults=vaults,
        wrong_passwords=[
            {"password": "Moth-Test-Vault-2026?", "vault": 0, "note": "one character"},
            {
                "password": unicodedata.normalize("NFD", "Mölle-Stern-2026 🦋"),
                "vault": 1,
                "note": "NFD form: no normalization",
            },
        ],
        name_index=[
            {
                "name": name,
                "index_hex": hmac.new(
                    index_key, name.encode("utf-8"), hashlib.sha256
                ).hexdigest(),
                "note": note,
            }
            for name, note in NAMES
        ],
        records=records,
        rejected=rejected,
    )


def backup_v2_manifest(content: bytes) -> dict:
    return {
        "format": "ciphermoth-backup",
        "version": 2,
        "exported_at": "2026-10-15T12:00:00+00:00",
        "app_version": "vectors",
        "settings": {
            "inactivity_ms": 300000,
            "warn_before_ms": 30000,
            "hidden_ms": 120000,
            "debounce_ms": 500,
            "clipboard_clear_ms": 15000,
            "update_check_enabled": False,
        },
        "entries_count": 2,
    }


def backup_v2_entries(content: bytes) -> list[dict]:
    entry = json.loads(_document())
    return [
        {
            **entry,
            "created": "2026-01-01T00:00:00.000001+00:00",
            "updated": "2026-02-01T00:00:00.000002+00:00",
            "deleted": None,
            "attachments": [
                {
                    "filename": "Preț ünïcode.bin",
                    "content_type": "x/test",
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "created": "2026-01-02T00:00:00.000003+00:00",
                }
            ],
        },
        {
            **json.loads(
                _document(
                    name="GitHub",
                    value="older-Secret",
                    favorite=False,
                    history=[],
                )
            ),
            "created": "2025-06-01T00:00:00+00:00",
            "updated": "2025-07-01T00:00:00+00:00",
            "deleted": "2025-12-24T18:00:00.123456+00:00",
            "attachments": [],
        },
    ]


def backup_v2_vectors() -> tuple[dict, bytes]:
    password = "Mölle-Stern-2026 🦋"
    salt = fixed(0x33, 16)
    content = bytes(range(256)) * 4 + b"\x00\xff"
    manifest = json.dumps(backup_v2_manifest(content), ensure_ascii=False).encode()
    entries = backup_v2_entries(content)
    plaintext_frames = [
        manifest,
        json.dumps(entries[0], ensure_ascii=False).encode(),
        content,
        json.dumps(entries[1], ensure_ascii=False).encode(),
    ]
    derived = raw_argon2id(password, salt)
    frame_key = hkdf(derived, "ciphermoth/backup/v2/frame-encryption")
    commitment = hkdf(derived, "ciphermoth/backup/v2/key-commitment")
    header = struct.pack(
        ">8sHBIII16sI32s",
        b"CMBACKUP",
        2,
        1,
        65536,
        3,
        4,
        salt,
        len(plaintext_frames),
        commitment,
    )
    out = bytearray(header)
    frames = []
    for index, plaintext in enumerate(plaintext_frames):
        nonce = fixed(0x70 + index, 12)
        last = index == len(plaintext_frames) - 1
        associated = header + struct.pack(">IB", index, 1 if last else 0)
        ciphertext = AESGCM(frame_key).encrypt(nonce, plaintext, associated)
        out += struct.pack(">I", len(ciphertext)) + nonce + ciphertext
        frames.append(
            {
                "index": index,
                "last": last,
                "nonce_hex": nonce.hex(),
                "associated_data_hex": associated.hex(),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            }
        )
    data = bytes(out)
    return (
        doc(
            "backup_v2",
            "Backup format 2 (docs/VAULT_FORMAT.md section 5). derived = "
            "Argon2id(password, salt, header parameters); frame_key = HKDF(derived, "
            "'ciphermoth/backup/v2/frame-encryption'); commitment = HKDF(derived, "
            "'ciphermoth/backup/v2/key-commitment'). Header (75 bytes) = 'CMBACKUP' "
            "|| u16 version 2 || u8 kdf 1 || u32 memory KiB || u32 iterations || "
            "u32 lanes || salt(16) || u32 frames || commitment(32). Each frame = "
            "u32 length || nonce(12) || AES-256-GCM(frame_key, nonce, plaintext, "
            "header || u32 index || u8 last). Frame 0 contains settings and the "
            "entry count; each entry has its own JSON frame followed by its "
            "attachment frames.",
            file="backup-v2.cmbackup",
            file_sha256=hashlib.sha256(data).hexdigest(),
            password=password,
            salt_hex=salt.hex(),
            derived_hex=derived.hex(),
            frame_key_hex=frame_key.hex(),
            commitment_hex=commitment.hex(),
            header_hex=header.hex(),
            frames=frames,
            manifest=json.loads(manifest),
            entries=entries,
            attachment_hex=content.hex(),
        ),
        data,
    )


# The browser extension's desktop channel (docs/EXTENSION.md, "Desktop mode"):
# X25519 pairing with a commitment and a 6-digit short authentication string,
# then one AES-256-GCM key per connection with counter nonces.

CHANNEL = "ciphermoth/extension/v1"
TO_APP = 0x01
TO_EXTENSION = 0x02


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def lp(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def x25519_public(private: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(private)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def hkdf_salted(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info.encode()
    ).derive(ikm)


def channel_seal(key: bytes, direction: int, counter: int, plaintext: bytes) -> bytes:
    nonce = bytes([direction, 0, 0, 0]) + struct.pack(">Q", counter)
    associated = bytes([direction]) + struct.pack(">Q", counter)
    return AESGCM(key).encrypt(nonce, plaintext, associated)


CHANNEL_MESSAGES = [
    (TO_APP, 0, '{"id":1,"op":"status"}'),
    (TO_EXTENSION, 0, '{"id":1,"ok":true,"value":{"state":"unlocked"}}'),
    (
        TO_APP,
        1,
        '{"id":2,"op":"api","route":"matches",'
        '"body":{"origin":"https://github.com","subdomains":false}}',
    ),
    (TO_EXTENSION, 1, '{"id":2,"ok":true,"value":{"logins":[],"truncated":false}}'),
]


def channel_case(
    name: str, ext_private: bytes, app_private: bytes, browser: str, seed: int
) -> dict:
    ext_public = x25519_public(ext_private)
    app_public = x25519_public(app_private)
    ext_nonce = fixed(seed, 16)
    app_nonce = fixed(seed + 0x40, 16)
    commit = hashlib.sha256(
        lp(f"{CHANNEL}/commit".encode()) + ext_public + ext_nonce
    ).digest()
    transcript = hashlib.sha256(
        lp(f"{CHANNEL}/pair".encode())
        + lp(browser.encode())
        + ext_public
        + ext_nonce
        + app_public
        + app_nonce
    ).digest()
    shared = X25519PrivateKey.from_private_bytes(ext_private).exchange(
        X25519PublicKey.from_public_bytes(app_public)
    )
    sas_raw = hkdf_salted(shared, transcript, f"{CHANNEL}/sas", 4)
    pairing_key = hkdf_salted(shared, transcript, f"{CHANNEL}/channel", 32)
    pairing_id = fixed(seed + 0x80, 16)
    hello_ext = fixed(seed + 0xA0, 16)
    hello_app = fixed(seed + 0xC0, 16)
    connection_salt = hashlib.sha256(
        lp(f"{CHANNEL}/connection".encode()) + pairing_id + hello_ext + hello_app
    ).digest()
    connection_key = hkdf_salted(
        pairing_key, connection_salt, f"{CHANNEL}/connection", 32
    )
    return {
        "name": name,
        "browser": browser,
        "extension_private_hex": ext_private.hex(),
        "app_private_hex": app_private.hex(),
        "extension_public": b64url(ext_public),
        "app_public": b64url(app_public),
        "extension_nonce": b64url(ext_nonce),
        "app_nonce": b64url(app_nonce),
        "commit": b64url(commit),
        "transcript_hex": transcript.hex(),
        "shared_hex": shared.hex(),
        "sas": f"{int.from_bytes(sas_raw, 'big') % 1_000_000:06d}",
        "pairing_key_hex": pairing_key.hex(),
        "pairing_id": b64url(pairing_id),
        "hello_extension_nonce": b64url(hello_ext),
        "hello_app_nonce": b64url(hello_app),
        "connection_key_hex": connection_key.hex(),
        "messages": [
            {
                "direction": direction,
                "counter": counter,
                "plaintext": text,
                "ciphertext": b64url(
                    channel_seal(connection_key, direction, counter, text.encode())
                ),
            }
            for direction, counter, text in CHANNEL_MESSAGES
        ],
    }


def extension_channel_vectors() -> dict:
    cases = [
        channel_case("chrome", fixed(0x10, 32), fixed(0x50, 32), "Chrome", 0x01),
        channel_case("firefox", fixed(0x90, 32), fixed(0xD0, 32), "Firefox", 0x33),
    ]
    first = cases[0]["messages"][0]
    sealed = base64.urlsafe_b64decode(first["ciphertext"] + "==")
    flipped = bytes([sealed[0] ^ 0x01]) + sealed[1:]
    other_key = bytes.fromhex(cases[1]["connection_key_hex"])
    refused = [
        {
            "reason": "a flipped ciphertext bit",
            "direction": TO_APP,
            "counter": 0,
            "ciphertext": b64url(flipped),
        },
        {
            "reason": "a replay: sealed as message 0, read as message 1",
            "direction": TO_APP,
            "counter": 1,
            "ciphertext": first["ciphertext"],
        },
        {
            "reason": "a reflection: sealed toward the app, "
            "read as toward the extension",
            "direction": TO_EXTENSION,
            "counter": 0,
            "ciphertext": first["ciphertext"],
        },
        {
            "reason": "sealed with another connection's key",
            "direction": TO_APP,
            "counter": 0,
            "ciphertext": b64url(
                channel_seal(other_key, TO_APP, 0, first["plaintext"].encode())
            ),
        },
    ]
    return doc(
        "extension-channel",
        "The desktop channel between the browser extension and the CipherMoth app "
        "(docs/EXTENSION.md). lp(x) = u16be(len(x)) || x. Pairing: the extension "
        "sends commit = SHA-256(lp('ciphermoth/extension/v1/commit') || E_x || N_x) "
        "before it learns the app's key, the app answers E_a and N_a, the extension "
        "reveals E_x and N_x. T = SHA-256(lp('ciphermoth/extension/v1/pair') || "
        "lp(browser) || E_x || N_x || E_a || N_a); Z = X25519(own private, peer "
        "public), refused when all zero (low-order points); sas = "
        "u32be(HKDF-SHA256(salt=T, ikm=Z, info='ciphermoth/extension/v1/sas', L=4)) "
        "mod 1000000 as six digits; pairing key = HKDF-SHA256(salt=T, ikm=Z, "
        "info='ciphermoth/extension/v1/channel', L=32). Each connection: the "
        "extension sends the pairing id and M_x, the app answers M_a; C = "
        "SHA-256(lp('ciphermoth/extension/v1/connection') || id || M_x || M_a); "
        "connection key = HKDF-SHA256(salt=C, ikm=pairing key, "
        "info='ciphermoth/extension/v1/connection', L=32). Message n in direction d "
        "(1 = to the app, 2 = to the extension) is AES-256-GCM with nonce d || "
        "000000 || u64be(n) and associated data d || u64be(n); each direction counts "
        "from 0 per connection and a message is read only with the next counter. "
        "Keys, nonces, ids and ciphertexts are unpadded base64url; private keys and "
        "derived secrets are hex.",
        cases=cases,
        refused=refused,
        low_order_points=[
            b64url(bytes(32)),
            b64url(bytes([1]) + bytes(31)),
            b64url(
                bytes.fromhex(
                    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
                )
            ),
        ],
        framing={
            "description": "Native messaging and the local socket: a u32 length in "
            "the platform's byte order (little-endian on every supported target), "
            "then 1 to 65536 bytes of a UTF-8 JSON object.",
            "max_bytes": 65536,
        },
    )


def outputs() -> tuple[dict[str, dict], dict[str, bytes]]:
    backup_doc, backup_zip = backup_vectors()
    backup_v2_doc, backup_v2_file = backup_v2_vectors()
    return (
        {
            "argon2id.json": argon2id_vectors(),
            "backup_zip.json": backup_doc,
            "vault-v2.json": vault_v2_vectors(),
            "backup-v2.json": backup_v2_doc,
            "extension-channel.json": extension_channel_vectors(),
        },
        {"backup-v1.zip": backup_zip, "backup-v2.cmbackup": backup_v2_file},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="Write only these files (new vectors), leaving the others alone.",
    )
    args = parser.parse_args()
    documents, binaries = outputs()
    selected = set(args.only) if args.only is not None else None
    names = [*documents, *binaries]
    wanted = [n for n in names if selected is None or n in selected]
    existing = [name for name in wanted if (OUT / name).exists()]
    if existing and not args.force:
        print(f"Refusing to overwrite frozen vectors: {existing}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in documents.items():
        if name in wanted:
            (OUT / name).write_text(
                json.dumps(content, indent=2, ensure_ascii=False) + "\n"
            )
    for name, data in binaries.items():
        if name in wanted and name != "backup-v1.zip":
            (OUT / name).write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
