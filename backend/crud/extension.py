"""
What a browser extension session can read: the active logins whose saved
address matches a page, a search over active logins, and one login's username
and password (or its current 2FA code) at the moment of a fill.

Nothing else. Notes, history, descriptions, custom fields, attachments, tags,
the trash and the 2FA secret never leave through these methods, and they write
nothing. Entries are addressed by row id; damaged rows are skipped in listings
and refused (``VaultDamaged``) when asked for directly.
"""

import logging
import time
from dataclasses import dataclass

from sqlalchemy import select

from crud.base import BaseCRUD
from crud.records import EntryDocument, open_entry
from errors import InvalidRequest, NotFound, OriginMismatch, VaultDamaged
from helpers import VaultKey, generate_totp
from models import EntryModel
from schemas import (
    ExtensionCredential,
    ExtensionLogin,
    ExtensionLogins,
    ExtensionTotp,
)
from url_match import (
    Origin,
    candidate_filter,
    could_match,
    normalize,
    origins_match,
)
from validators import normalize_totp_secret

logger = logging.getLogger(__name__)

MAX_RESULTS = 50
TOTP_PERIOD = 30
_NO_LOGIN = "No such login in the vault."
_NOT_A_PAGE = "This page has no web address CipherMoth can fill."
_MISMATCH = "This login is saved for another site. Confirm in the extension first."


@dataclass(frozen=True, slots=True)
class _Login:
    model: EntryModel
    document: EntryDocument
    origin: Origin | None


def _display_host(origin: Origin | None) -> str | None:
    """Host (and port) of a saved address, with the scheme only when it is the
    insecure one, so the popup can say "saved for github.com"."""
    if origin is None:
        return None
    text = str(origin)
    return text if origin.scheme == "http" else text.removeprefix("https://")


def _sort_key(login: _Login) -> tuple[bool, str, str, int]:
    name = login.document.name
    return (not login.document.favorite, name.casefold(), name, login.model.id)


def _page(origin: str) -> Origin:
    page = normalize(origin)
    if page is None:
        raise InvalidRequest(_NOT_A_PAGE)
    return page


class ExtensionCRUD(BaseCRUD):
    async def _logins(self, key: VaultKey, needle: str | None = None) -> list[_Login]:
        """Every readable active login, or with ``needle`` only those whose
        saved URL can match it (``url_match.could_match``)."""
        models = (
            await self.session.scalars(
                select(EntryModel).where(EntryModel.deleted.is_(None))
            )
        ).all()
        logins = []
        for model in models:
            try:
                document = open_entry(key, model)
            except VaultDamaged:
                logger.warning("Entry #%s is damaged; not listed.", model.id)
                continue
            if document.kind != "login":
                continue
            if needle is not None and not (
                document.url and could_match(needle, document.url)
            ):
                continue
            logins.append(_Login(model, document, normalize(document.url)))
        return logins

    @staticmethod
    def _listing(logins: list[_Login]) -> ExtensionLogins:
        logins.sort(key=_sort_key)
        return ExtensionLogins(
            logins=[
                ExtensionLogin(
                    id=login.model.id,
                    name=login.document.name,
                    username=login.document.username,
                    host=_display_host(login.origin),
                    favorite=login.document.favorite,
                    has_totp=bool(login.document.totp_secret),
                )
                for login in logins[:MAX_RESULTS]
            ],
            truncated=len(logins) > MAX_RESULTS,
        )

    async def matches(
        self, key: VaultKey, origin: str, *, subdomains: bool
    ) -> ExtensionLogins:
        page = _page(origin)
        needle = candidate_filter(page, subdomains=subdomains)
        return self._listing(
            [
                login
                for login in await self._logins(key, needle)
                if login.origin is not None
                and origins_match(page, login.origin, subdomains=subdomains)
            ]
        )

    async def search(self, key: VaultKey, query: str) -> ExtensionLogins:
        needle = query.strip().casefold()
        return self._listing(
            [
                login
                for login in await self._logins(key)
                if not needle
                or any(
                    needle in text.casefold()
                    for text in (
                        login.document.name,
                        login.document.username or "",
                        _display_host(login.origin) or "",
                    )
                )
            ]
        )

    async def _login(
        self,
        key: VaultKey,
        entry_id: int,
        origin: str,
        *,
        subdomains: bool,
        confirmed_mismatch: bool,
    ) -> EntryDocument:
        page = _page(origin)
        model = await self.session.scalar(
            select(EntryModel).where(
                EntryModel.id == entry_id, EntryModel.deleted.is_(None)
            )
        )
        if model is None:
            raise NotFound(_NO_LOGIN)
        document = open_entry(key, model)
        if document.kind != "login":
            raise NotFound(_NO_LOGIN)
        saved = normalize(document.url)
        matched = saved is not None and origins_match(
            page, saved, subdomains=subdomains
        )
        if not matched and not confirmed_mismatch:
            raise OriginMismatch(_MISMATCH)
        return document

    async def credential(
        self,
        key: VaultKey,
        entry_id: int,
        origin: str,
        *,
        subdomains: bool,
        confirmed_mismatch: bool,
    ) -> ExtensionCredential:
        document = await self._login(
            key,
            entry_id,
            origin,
            subdomains=subdomains,
            confirmed_mismatch=confirmed_mismatch,
        )
        return ExtensionCredential(username=document.username, password=document.value)

    async def totp(
        self,
        key: VaultKey,
        entry_id: int,
        origin: str,
        *,
        subdomains: bool,
        confirmed_mismatch: bool,
    ) -> ExtensionTotp:
        document = await self._login(
            key,
            entry_id,
            origin,
            subdomains=subdomains,
            confirmed_mismatch=confirmed_mismatch,
        )
        try:
            secret = normalize_totp_secret(document.totp_secret)
        except ValueError:
            raise InvalidRequest("This login's 2FA secret is not valid.") from None
        if secret is None:
            raise NotFound("This login has no 2FA code.")
        try:
            code = generate_totp(secret, period=TOTP_PERIOD)
        except ValueError:
            raise InvalidRequest("This login's 2FA secret is not valid.") from None
        return ExtensionTotp(
            code=code, expires_in=TOTP_PERIOD - int(time.time()) % TOTP_PERIOD
        )
