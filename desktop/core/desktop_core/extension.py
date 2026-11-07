"""Extension sessions for the desktop app's paired browsers (docs/EXTENSION.md,
desktop mode).

Only the Rust shell can send these (native frames never come from the
renderer's API bridge). The shell holds no full session token: an extension
session is opened from the key of the window's one unlocked session, checked
against the vault like every request, and its token stays in the shell, which
uses it for ``/api/extension/*`` like any extension. Locking the window stops
this process, which ends every session.
"""

import json
import re

from crud.master_password import MasterPasswordCRUD
from errors import InvalidKey, SessionRequired
from schemas import ExtensionBrowser

_BROWSERS = set(ExtensionBrowser.__args__)
_CLIENT = re.compile(r"[A-Za-z0-9_-]{22}", re.ASCII)
_LOCKED = (401, [], b'{"code":"locked","detail":"CipherMoth is locked."}')


def _json(value) -> tuple[int, list, bytes]:
    return 200, [], json.dumps(value).encode()


async def call(app, header: dict) -> tuple[int, list, bytes]:
    operation = header.get("native")
    sessions = app.state.vault_sessions
    if operation == "extension_status":
        try:
            sessions.sole_full_key()
        except SessionRequired:
            return _json({"unlocked": False})
        return _json({"unlocked": True})
    if operation == "extension_end":
        client = header.get("client")
        if client is not None and not (
            isinstance(client, str) and _CLIENT.fullmatch(client)
        ):
            raise ValueError("invalid client")
        return _json({"ended": sessions.revoke_extensions(client)})
    if operation != "extension_open":
        raise ValueError("unknown extension operation")
    browser, client = header.get("browser"), header.get("client")
    if (
        browser not in _BROWSERS
        or not isinstance(client, str)
        or not _CLIENT.fullmatch(client)
        or set(header) != {"native", "browser", "client"}
    ):
        raise ValueError("invalid extension session request")
    try:
        key = sessions.sole_full_key()
    except SessionRequired:
        return _LOCKED
    async with app.state.database.transaction(write=False) as session:
        try:
            await MasterPasswordCRUD(session).verify_vault_key(key)
        except InvalidKey:
            return _LOCKED
    token, _handle = sessions.open_extension(key, browser, client)
    return _json({"session_token": token})
