"""
The routes of the CipherMoth browser extension (docs/EXTENSION.md).

Extension sessions reach only the routes marked ``ExtensionKeyDep`` below;
every other route refuses them, and these refuse full sessions. Everything is
POST with a JSON body, so page hosts and entry ids never appear in a URL or an
access log. Nothing here writes to the vault: all of them run in read
transactions (``deps._READ_ONLY_ROUTES``).
"""

from fastapi import APIRouter, Depends, Request, status

from api.endpoints.deps import (
    ExtensionCredentialDep,
    ExtensionCRUDDep,
    ExtensionKeyDep,
    SessionTokenHeader,
    VaultAccessDep,
    VaultKeyDep,
    VaultSessionsDep,
    require_master_password,
)
from api.rate_limit import limiter, rate
from api.responses import inject_responses
from schemas import (
    ExtensionCredential,
    ExtensionLoginRequest,
    ExtensionLogins,
    ExtensionMatchRequest,
    ExtensionSearchRequest,
    ExtensionSessionCreated,
    ExtensionSessionInfo,
    ExtensionSessionRequest,
    ExtensionTotp,
    ExtensionUnlockPayload,
    SimpleDetailSchema,
    VaultLock,
    VaultSessionStatus,
    VaultUnlock,
)
from vault_sessions import Scope

router = APIRouter(tags=["extension"])

_REFUSED = inject_responses(
    {
        status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
        status.HTTP_409_CONFLICT: SimpleDetailSchema,
        status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
    }
)


@router.post(
    "/unlock",
    name="extension:unlock",
    response_model=VaultUnlock,
    responses=_REFUSED,
)
@limiter.limit(rate("30/hour"))
async def unlock(
    request: Request, body: ExtensionUnlockPayload, access: VaultAccessDep
) -> VaultUnlock:
    """An extension session from the master password. A vault that needs a
    security key answers 409 ``use_handoff``: connect from the web app."""
    return await access.unlock_extension(body)


@router.post(
    "/sessions",
    name="extension:connect",
    response_model=ExtensionSessionCreated,
    dependencies=[Depends(require_master_password)],
    responses=_REFUSED,
)
@limiter.limit(rate("10/hour"))
async def connect(
    request: Request,
    body: ExtensionSessionRequest,
    access: VaultAccessDep,
    key: VaultKeyDep,
) -> ExtensionSessionCreated:
    """The handoff: an unlocked web app session opens an extension session for
    the browser it runs in and passes the token to the extension."""
    return await access.connect_extension(key, body.browser)


@router.get(
    "/sessions",
    name="extension:sessions",
    response_model=list[ExtensionSessionInfo],
    dependencies=[Depends(require_master_password)],
    responses=_REFUSED,
)
async def list_sessions(
    access: VaultAccessDep, key: VaultKeyDep
) -> list[ExtensionSessionInfo]:
    return access.extension_sessions()


@router.delete(
    "/sessions/{session_id}",
    name="extension:disconnect",
    response_model=VaultLock,
    dependencies=[Depends(require_master_password)],
    responses=_REFUSED,
)
async def disconnect(
    session_id: str, access: VaultAccessDep, key: VaultKeyDep
) -> VaultLock:
    access.disconnect_extension(session_id)
    return VaultLock(locked=True)


@router.post(
    "/matches",
    name="extension:matches",
    response_model=ExtensionLogins,
    responses=_REFUSED,
)
async def matches(
    body: ExtensionMatchRequest, crud: ExtensionCRUDDep, key: ExtensionKeyDep
) -> ExtensionLogins:
    """The active logins saved for the page's origin, favorites first."""
    return await crud.matches(key, body.origin, subdomains=body.subdomains)


@router.post(
    "/search",
    name="extension:search",
    response_model=ExtensionLogins,
    responses=_REFUSED,
)
async def search(
    body: ExtensionSearchRequest, crud: ExtensionCRUDDep, key: ExtensionKeyDep
) -> ExtensionLogins:
    return await crud.search(key, body.query)


@router.post(
    "/credential",
    name="extension:credential",
    response_model=ExtensionCredential,
    responses=_REFUSED,
)
@limiter.limit(rate("300/hour"))
async def credential(
    request: Request,
    body: ExtensionLoginRequest,
    crud: ExtensionCRUDDep,
    key: ExtensionKeyDep,
) -> ExtensionCredential:
    """One login's username and password, for a fill or a copy. A login saved
    for another site needs ``confirmed_mismatch`` (409 ``origin_mismatch``)."""
    return await crud.credential(
        key,
        body.id,
        body.origin,
        subdomains=body.subdomains,
        confirmed_mismatch=body.confirmed_mismatch,
    )


@router.post(
    "/totp",
    name="extension:totp",
    response_model=ExtensionTotp,
    responses=_REFUSED,
)
@limiter.limit(rate("300/hour"))
async def totp(
    request: Request,
    body: ExtensionLoginRequest,
    crud: ExtensionCRUDDep,
    key: ExtensionKeyDep,
) -> ExtensionTotp:
    """A login's current 2FA code. The secret never leaves the server."""
    return await crud.totp(
        key,
        body.id,
        body.origin,
        subdomains=body.subdomains,
        confirmed_mismatch=body.confirmed_mismatch,
    )


@router.post(
    "/session",
    name="extension:session-activity",
    response_model=VaultSessionStatus,
    responses=_REFUSED,
)
async def session_activity(
    access: VaultAccessDep, credential: ExtensionCredentialDep, key: ExtensionKeyDep
) -> VaultSessionStatus:
    return access.extension_status(credential)


@router.post("/lock", name="extension:lock", response_model=VaultLock)
async def lock(
    token: SessionTokenHeader, vault_sessions: VaultSessionsDep
) -> VaultLock:
    """End the caller's extension session. Never ends a full session."""
    vault_sessions.revoke(token, scope=Scope.EXTENSION)
    return VaultLock(locked=True)
