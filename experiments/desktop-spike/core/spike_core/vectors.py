import base64
import hashlib
import hmac
import io
import json
import platform
import sqlite3
import struct
import sys
import types
from pathlib import Path

import helpers
import pyzipper
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from schemas import MasterPassword


class Runner:
    def __init__(self) -> None:
        self.passed = 0
        self.failures: list[str] = []
        self.outputs: list[object] = []

    def check(self, name: str, condition: bool) -> None:
        if condition:
            self.passed += 1
        else:
            self.failures.append(name)

    def record(self, value: object) -> None:
        self.outputs.append(value)


def _load(directory: Path, name: str) -> dict:
    data = json.loads((directory / name).read_text(encoding="utf-8"))
    assert data["format"] == "ciphermoth-test-vectors/1"
    return data


def _reference_decrypt(key: str, token: bytes) -> bytes:
    raw_key = base64.urlsafe_b64decode(key)
    data = base64.urlsafe_b64decode(token)
    body, mac = data[:-32], data[-32:]
    if not hmac.compare_digest(
        mac, hmac.new(raw_key[:16], body, hashlib.sha256).digest()
    ):
        raise ValueError("hmac")
    iv, ciphertext = body[9:25], body[25:]
    decryptor = Cipher(algorithms.AES(raw_key[16:]), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _argon2(run: Runner, directory: Path) -> None:
    data = _load(directory, "argon2id.json")
    keys = {}
    for vector in data["vectors"]:
        key = helpers.generate_key_derivation(
            bytes.fromhex(vector["salt_hex"]), vector["password"]
        ).decode()
        run.record(["argon2id", vector["note"], key])
        run.check(f"argon2id {vector['note']}", key == vector["key"])
        run.check(
            f"argon2id utf8 {vector['note']}",
            vector["password"].encode().hex() == vector["password_utf8_hex"],
        )
        keys[vector["note"].split(" ")[0]] = key
    run.check("argon2id no normalization", keys.get("NFC") != keys.get("NFD"))
    for case in data["api_input"]["cases"]:
        submitted = MasterPassword.model_validate(
            {"master_password": case["submitted"]}
        )
        run.record(["api_input", submitted.master_password])
        run.check(
            f"api_input {case['submitted']!r}",
            submitted.master_password == case["kdf_input"],
        )


def _fernet(run: Runner, directory: Path) -> None:
    data = _load(directory, "fernet.json")
    for vector in data["vectors"]:
        token = vector["token"].encode()
        expected = bytes.fromhex(vector["plaintext_hex"])
        got = helpers.decrypt_bytes(vector["key"], token)
        run.record(["fernet", vector["note"], got.hex() if got is not None else None])
        run.check(f"fernet decrypt {vector['note']}", got == expected)
        run.check(
            f"fernet reference {vector['note']}",
            _reference_decrypt(vector["key"], token) == expected,
        )
        if vector["plaintext"] is not None:
            run.check(
                f"fernet text {vector['note']}",
                helpers.decrypt(vector["key"], token) == vector["plaintext"],
            )
        raw = base64.urlsafe_b64decode(token)
        run.check(f"fernet version {vector['note']}", raw[0] == 0x80)
        run.check(
            f"fernet timestamp {vector['note']}",
            struct.unpack(">Q", raw[1:9])[0] == vector["timestamp"],
        )
        rebuilt = Fernet(vector["key"])._encrypt_from_parts(
            expected, vector["timestamp"], bytes.fromhex(vector["iv_hex"])
        )
        run.record(["fernet encrypt", vector["note"], rebuilt.decode()])
        run.check(f"fernet deterministic encrypt {vector['note']}", rebuilt == token)
    for vector in data["invalid"]:
        token = vector["token"].encode()
        run.check(
            f"fernet refuses {vector['note']}",
            helpers.decrypt(vector["key"], token) is None
            and helpers.decrypt_bytes(vector["key"], token) is None,
        )
    key = data["vectors"][0]["key"]
    for plaintext in (b"", b"x", "ключ 🦋".encode(), bytes(range(256)) * 3):
        token = helpers.encrypt(key, plaintext)
        run.check(
            f"fernet new token {len(plaintext)}",
            _reference_decrypt(key, token) == plaintext
            and helpers.encrypt(key, plaintext) != token,
        )


def _key_check(run: Runner, directory: Path) -> None:
    data = _load(directory, "key_check.json")
    salt = bytes.fromhex(data["salt_hex"])
    key = helpers.generate_key_derivation(salt, data["password"]).decode()
    token = data["token"].encode()
    run.record(["key_check", key])
    run.check("key_check key", key == data["key"])
    run.check("key_check verifies", helpers.verify_key_check(key, token, salt))
    run.check("key_check bytes", helpers.verify_key_check(key.encode(), token, salt))
    run.check(
        "key_check bound to salt", not helpers.verify_key_check(key, token, bytes(16))
    )
    rebuilt = Fernet(key)._encrypt_from_parts(
        b"ciphermoth-key-check-v1:" + salt,
        data["timestamp"],
        bytes.fromhex(data["iv_hex"]),
    )
    run.check("key_check deterministic token", rebuilt == token)
    fresh = helpers.create_key_check(key, salt)
    run.check(
        "key_check fresh",
        _reference_decrypt(key, fresh) == b"ciphermoth-key-check-v1:" + salt,
    )
    for rejected in data["rejected_keys"]:
        run.check(
            f"key_check rejects {rejected['note']}",
            not helpers.verify_key_check(rejected["key"], token, salt),
        )


def _bcrypt(run: Runner, directory: Path) -> None:
    data = _load(directory, "bcrypt.json")
    for vector in data["vectors"]:
        run.check(
            f"bcrypt {vector['note']}",
            helpers.verify_master_password(vector["password"], vector["hash"]),
        )
    for vector in data["mismatches"]:
        run.check(
            f"bcrypt mismatch {vector['note']}",
            not helpers.verify_master_password(vector["password"], vector["hash"]),
        )
    hashed = helpers.hash_master_password("Moth-Test-Vault-2026!")
    run.check(
        "bcrypt new hash",
        hashed.startswith("$2b$12$")
        and helpers.verify_master_password("Moth-Test-Vault-2026!", hashed),
    )


def _totp(run: Runner, directory: Path) -> None:
    data = _load(directory, "totp.json")
    original = helpers.time
    try:
        for vector in data["vectors"]:
            helpers.time = types.SimpleNamespace(time=lambda t=vector["time"]: float(t))
            code = helpers.generate_totp(
                vector["secret"], digits=vector["digits"], period=vector["period"]
            )
            run.record(["totp", vector["time"], code])
            run.check(
                f"totp {vector['time']} {vector['secret'][:8]}", code == vector["code"]
            )
    finally:
        helpers.time = original


def _backup(run: Runner, directory: Path) -> None:
    data = _load(directory, "backup_zip.json")
    archive = (directory / data["file"]).read_bytes()
    with pyzipper.AESZipFile(io.BytesIO(archive)) as zf:
        run.check("backup members", zf.namelist() == [data["member"]])
        zf.setpassword(data["password"].encode())
        content = json.loads(zf.read(data["member"]))
        run.record(
            [
                "backup",
                hashlib.sha256(
                    json.dumps(content, sort_keys=True).encode()
                ).hexdigest(),
            ]
        )
        run.check("backup json", content == data["json"])
    try:
        with pyzipper.AESZipFile(io.BytesIO(archive)) as zf:
            zf.setpassword(b"wrong password")
            zf.read(data["member"])
        run.check("backup wrong password refused", False)
    except RuntimeError:
        run.check("backup wrong password refused", True)
    entries = [{"name": "Synthetic", "value": "synthetic-value"}]
    created = helpers.create_encrypted_zip(entries, "Synthetic-Backup-2026")
    with pyzipper.AESZipFile(io.BytesIO(created)) as zf:
        zf.setpassword(b"Synthetic-Backup-2026")
        run.check(
            "backup round trip",
            json.loads(zf.read("ciphermoth_backup.json"))["passwords"] == entries,
        )


def environment() -> dict:
    import bcrypt
    import fastapi
    import pydantic
    import sqlalchemy
    from cryptography import __version__ as cryptography_version
    from cryptography.hazmat.backends.openssl.backend import backend

    return {
        "frozen": bool(getattr(sys, "frozen", False)),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cryptography": cryptography_version,
        "openssl": backend.openssl_version_text(),
        "bcrypt": bcrypt.__version__,
        "fastapi": fastapi.__version__,
        "pydantic": pydantic.VERSION,
        "sqlalchemy": sqlalchemy.__version__,
        "sqlite": sqlite3.sqlite_version,
    }


def run_all(directory: Path) -> dict:
    run = Runner()
    for section in (_argon2, _fernet, _key_check, _bcrypt, _totp, _backup):
        try:
            section(run, directory)
        except Exception as exc:
            run.failures.append(f"{section.__name__} raised {type(exc).__name__}")
    digest = hashlib.sha256(
        json.dumps(run.outputs, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    return {
        "passed": run.passed,
        "failed": run.failures,
        "results_sha256": digest,
        "environment": environment(),
    }
