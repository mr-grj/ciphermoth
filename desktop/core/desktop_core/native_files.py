"""Shell-authorized files. Paths never originate in the renderer's API bridge.

Requests still use production FastAPI validation, auth and transactions. Only
ciphertext streams touch disk; 256 KiB chunks cross the in-process ASGI bridge.
"""

import errno
import json
import os
import stat
import tempfile
from pathlib import Path

from . import asgi_bridge

CHUNK = 256 * 1024
MAX_BACKUP = 1024 * 1024 * 1024


async def _call(app, header, body):
    operation = header.get("native")
    path = Path(header["file"])
    if not path.is_absolute():
        raise ValueError("absolute file required")
    fields = json.loads(body)
    token = header.get("session", "")
    headers = [("x-ciphermoth-session", token)]
    if operation == "backup_export":
        if path.suffix != ".cmbackup" or path.exists():
            return (
                400,
                [],
                b'{"detail":"Choose a new .cmbackup filename. '
                b'Existing files are never replaced."}',
            )
        fd, partial = tempfile.mkstemp(
            prefix=".ciphermoth-", suffix=".partial", dir=path.parent
        )
        try:
            with os.fdopen(fd, "wb") as output:
                result = await asgi_bridge.call(
                    app,
                    "POST",
                    "/api/passwords/backup",
                    "",
                    [*headers, ("content-type", "application/json")],
                    body,
                    MAX_BACKUP,
                    output=output,
                )
                if result[0] != 200:
                    return result
                output.flush()
                os.fsync(output.fileno())
            # link is atomic and fails if a file appeared after the dialog.
            os.link(partial, path)
            if os.name != "nt":
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return 200, [], b'{"saved":true}'
        finally:
            os.unlink(partial)
    if operation != "backup_import":
        raise ValueError("unknown file operation")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BACKUP:
            return 400, [], b'{"detail":"Choose a backup file no larger than 1 GiB."}'
        boundary = "ciphermoth" + os.urandom(16).hex()
        prefix = bytearray()
        for key in ("master_password", "on_conflict"):
            value = fields[key]
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError("invalid form field")
            prefix += (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"'
                f"\r\n\r\n{value}\r\n"
            ).encode()
        prefix += (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="vault.cmbackup"'
            "\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()

        def chunks():
            yield bytes(prefix)
            remaining = info.st_size
            while remaining:
                chunk = source.read(min(CHUNK, remaining))
                if not chunk:
                    raise OSError("backup changed while reading")
                remaining -= len(chunk)
                yield chunk
            yield suffix

        return await asgi_bridge.call(
            app,
            "POST",
            "/api/passwords/import",
            "",
            [*headers, ("content-type", f"multipart/form-data; boundary={boundary}")],
            b"",
            24 * 1024 * 1024,
            input_chunks=chunks(),
            input_size=len(prefix) + info.st_size + len(suffix),
        )


async def call(app, header, body):
    try:
        return await _call(app, header, body)
    except OSError as error:
        if error.errno == errno.ENOSPC:
            detail = "Not enough free disk space. Free space and try again."
        elif error.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            detail = (
                "The selected file or folder is not accessible. "
                "Choose a writable folder."
            )
        elif error.errno == errno.EEXIST:
            detail = "A file already exists there. Choose a new filename."
        else:
            detail = (
                "The file operation could not finish safely. Check the selected "
                "file, available disk space, and folder permissions."
            )
        return 400, [], json.dumps({"detail": detail}).encode()
