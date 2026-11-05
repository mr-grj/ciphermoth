class VaultError(Exception):
    """Base class for errors the vault core raises on purpose. Their message is
    shown to the client, so it must never contain a secret."""


class InvalidRequest(VaultError):
    pass


class Forbidden(VaultError):
    pass


class InvalidKey(Forbidden):
    pass


class WrongScope(Forbidden):
    """A live session used on a route its scope does not allow: a browser
    extension session outside /api/extension, or a full session on the routes
    only the extension calls."""


class UseHandoff(VaultError):
    """The browser extension cannot unlock this vault with the master password
    alone (it needs a security key): unlock in the web app and connect."""


class OriginMismatch(VaultError):
    """The extension asked for a login on a page its saved address does not
    match, without the user confirming it in the popup."""


class NotFound(VaultError):
    pass


class SessionRequired(VaultError):
    pass


class VaultBusy(VaultError):
    pass


class VaultDamaged(VaultError):
    """A stored value failed authenticated decryption or its format check: the
    vault file was damaged or altered."""
