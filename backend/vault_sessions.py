"""
Unlocked vault sessions, held in the memory of the one process that serves the
vault.

A session maps an opaque bearer token to the keys unwrapped at unlock
(``helpers.VaultKey``), so session clients never hold them. Only a SHA-256
digest of each token is kept, as the lookup key. Sessions end when they sit
idle longer than the configured inactivity timeout (plus
``EXPIRY_TOLERANCE_MS``), after an absolute lifetime, when they are locked,
when the master password changes, and when the process exits. An ended session
is deleted and can never be used again. Nothing is ever written to disk.

The tolerance exists only for request latency: a client measures inactivity
from when it sent its last request, the server from when it received it, so a
request a client sends just before its own deadline can reach the server a
moment after it. It never lets a session outlive the setting by more than that.

Server mode keeps one session per client (browser tab or CLI command), bounded
by ``max_sessions``: when full, expired sessions are dropped first and then the
least recently used one. A desktop core uses ``max_sessions=1``: unlocking
replaces the previous session and the shell, not the renderer, holds the token.

Every session has a scope. ``FULL`` sessions are the ones above. ``EXTENSION``
sessions belong to a browser extension: they may only list matching logins and
read one login at the moment of a fill (``/api/extension/*``). Every other route
refuses them, and the extension routes refuse full sessions (``WrongScope``).
Extension sessions have their own cap (``max_extension_sessions``) and are
evicted among themselves, so they never push out a web, CLI or desktop session.
They share the idle timeout, the absolute lifetime, ``revoke_all`` and the
sweeper with full sessions. Each one also has an opaque handle, unrelated to its
token, so the vault's settings can list and disconnect them without a token.

Limits: Python cannot reliably erase a secret from memory. Locking drops every
reference to the key, but copies made by ``str``, ``base64`` and
``cryptography`` stay in freed memory until it is reused. Sessions protect the
key from clients and from storage, not from someone who can read the process's
memory.
"""

import hashlib
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NamedTuple

from errors import SessionRequired, WrongScope
from helpers import VaultKey

TOKEN_BYTES = 32
HANDLE_BYTES = 16
EXPIRY_TOLERANCE_MS = 5_000
MAX_LIFETIME_MS = 12 * 60 * 60 * 1000
DEFAULT_MAX_SESSIONS = 32
DEFAULT_MAX_EXTENSION_SESSIONS = 8

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_ENDED = "Your session expired or was locked. Unlock the vault again."
_EXTENSION_ONLY = (
    "A browser extension session can only fill logins. Open CipherMoth to do this."
)
_FULL_ONLY = "This route only accepts a CipherMoth browser extension session."


class Scope(StrEnum):
    FULL = "full"
    EXTENSION = "extension"


class Instant(NamedTuple):
    monotonic: float
    wall: float

    def ms_since(self, earlier: "Instant") -> float:
        """
        The larger of the two clocks' elapsed times. The monotonic clock stops
        while the machine sleeps on macOS and Linux, and the wall clock can be
        set back, so each one covers the other's blind spot.
        """
        return 1000 * max(self.monotonic - earlier.monotonic, self.wall - earlier.wall)


def system_clock() -> Instant:
    return Instant(time.monotonic(), time.time())


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


@dataclass(slots=True)
class _Session:
    key: VaultKey = field(repr=False)
    created: Instant
    last_used: Instant
    scope: Scope = Scope.FULL
    handle: str = ""
    browser: str | None = None


@dataclass(frozen=True, slots=True)
class SessionInfo:
    idle_timeout_ms: int
    expires_in_ms: int


@dataclass(frozen=True, slots=True)
class ExtensionSessionInfo:
    """What the vault's settings may show about an extension session: never its
    token or key."""

    handle: str
    browser: str
    created: float
    last_used: float


class VaultSessions:
    def __init__(
        self,
        *,
        idle_timeout_ms: int,
        tolerance_ms: int = EXPIRY_TOLERANCE_MS,
        max_lifetime_ms: int = MAX_LIFETIME_MS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_extension_sessions: int = DEFAULT_MAX_EXTENSION_SESSIONS,
        clock: Callable[[], Instant] = system_clock,
    ) -> None:
        if max_sessions < 1 or max_extension_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        self._idle_timeout_ms = idle_timeout_ms
        self._tolerance_ms = tolerance_ms
        self._max_lifetime_ms = max_lifetime_ms
        self._max_sessions = max_sessions
        self._max_extension_sessions = max_extension_sessions
        self._clock = clock
        self._sessions: OrderedDict[bytes, _Session] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def idle_timeout_ms(self) -> int:
        return self._idle_timeout_ms

    def set_idle_timeout(self, idle_timeout_ms: int) -> None:
        """
        Apply a new inactivity timeout to every open session, measured from its
        last activity. Sessions that already expired under the old timeout are
        deleted first, so raising it never revives one.
        """
        now = self._clock()
        with self._lock:
            self._drop_expired(now)
            self._idle_timeout_ms = idle_timeout_ms

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def open(self, key: VaultKey) -> str:
        return self._open(key, Scope.FULL, None)[0]

    def open_extension(self, key: VaultKey, browser: str) -> tuple[str, str]:
        """A new extension session: its token and its handle."""
        return self._open(key, Scope.EXTENSION, browser)

    def _open(
        self, key: VaultKey, scope: Scope, browser: str | None
    ) -> tuple[str, str]:
        token = secrets.token_urlsafe(TOKEN_BYTES)
        handle = secrets.token_urlsafe(HANDLE_BYTES)
        now = self._clock()
        cap = (
            self._max_extension_sessions
            if scope is Scope.EXTENSION
            else self._max_sessions
        )
        with self._lock:
            self._drop_expired(now)
            same_scope = [d for d, s in self._sessions.items() if s.scope is scope]
            while len(same_scope) >= cap:
                del self._sessions[same_scope.pop(0)]
            self._sessions[_digest(token)] = _Session(
                key=key,
                created=now,
                last_used=now,
                scope=scope,
                handle=handle,
                browser=browser,
            )
        return token, handle

    def resolve(
        self, token: str | None, *, refresh: bool = True, scope: Scope = Scope.FULL
    ) -> VaultKey:
        """
        Return the vault key of a live session of ``scope``. ``refresh`` records
        the request as activity, restarting the inactivity timeout; a session
        that has already expired is deleted, never refreshed. A live session of
        the other scope is refused with ``WrongScope`` and not refreshed.
        """
        now = self._clock()
        with self._lock:
            digest, session = self._live(token, now, scope)
            if refresh:
                session.last_used = now
                self._sessions.move_to_end(digest)
            return session.key

    def info(self, token: str | None, *, scope: Scope = Scope.FULL) -> SessionInfo:
        """How long the session has left, measured against the configured
        timeout without the tolerance. Reading it is not activity."""
        now = self._clock()
        with self._lock:
            _, session = self._live(token, now, scope)
            remaining = self._remaining_ms(session, now, tolerance=False)
            return SessionInfo(
                idle_timeout_ms=self._idle_timeout_ms,
                expires_in_ms=max(0, int(remaining)),
            )

    def revoke(self, token: str | None, *, scope: Scope | None = None) -> bool:
        """End the session of ``token``; with ``scope``, only if it has that
        scope, so the lock route of one kind of client cannot end another's."""
        if token is None or not _TOKEN.fullmatch(token):
            return False
        digest = _digest(token)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None or (scope is not None and session.scope is not scope):
                return False
            del self._sessions[digest]
            return True

    def revoke_all(self, keep: str | None = None) -> int:
        """End every session of both scopes, except ``keep`` (a session just
        opened for the change that ends the others)."""
        kept = _digest(keep) if keep is not None and _TOKEN.fullmatch(keep) else None
        with self._lock:
            count = 0
            for digest in list(self._sessions):
                if digest != kept:
                    del self._sessions[digest]
                    count += 1
            return count

    def extension_sessions(self) -> list[ExtensionSessionInfo]:
        """The live extension sessions, most recently used first."""
        now = self._clock()
        with self._lock:
            self._drop_expired(now)
            return [
                ExtensionSessionInfo(
                    handle=session.handle,
                    browser=session.browser or "",
                    created=session.created.wall,
                    last_used=session.last_used.wall,
                )
                for session in reversed(self._sessions.values())
                if session.scope is Scope.EXTENSION
            ]

    def revoke_extension(self, handle: str) -> bool:
        """End the extension session with this handle. Full sessions are never
        ended through a handle."""
        with self._lock:
            for digest, session in self._sessions.items():
                if session.scope is Scope.EXTENSION and secrets.compare_digest(
                    session.handle.encode(), handle.encode()
                ):
                    del self._sessions[digest]
                    return True
            return False

    def drop_expired(self) -> int:
        with self._lock:
            return self._drop_expired(self._clock())

    def _live(
        self, token: str | None, now: Instant, scope: Scope
    ) -> tuple[bytes, _Session]:
        if token is None or not _TOKEN.fullmatch(token):
            raise SessionRequired(_ENDED)
        digest = _digest(token)
        session = self._sessions.get(digest)
        if session is None:
            raise SessionRequired(_ENDED)
        if self._remaining_ms(session, now) <= 0:
            del self._sessions[digest]
            raise SessionRequired(_ENDED)
        if session.scope is not scope:
            raise WrongScope(
                _EXTENSION_ONLY if session.scope is Scope.EXTENSION else _FULL_ONLY
            )
        return digest, session

    def _remaining_ms(
        self, session: _Session, now: Instant, *, tolerance: bool = True
    ) -> float:
        idle_limit = self._idle_timeout_ms + (self._tolerance_ms if tolerance else 0)
        return min(
            idle_limit - now.ms_since(session.last_used),
            self._max_lifetime_ms - now.ms_since(session.created),
        )

    def _drop_expired(self, now: Instant) -> int:
        expired = [
            digest
            for digest, session in self._sessions.items()
            if self._remaining_ms(session, now) <= 0
        ]
        for digest in expired:
            del self._sessions[digest]
        return len(expired)
