from fastapi import (
    APIRouter,
    Depends,
    Request,
    status,
)

from api.endpoints.deps import (
    CredentialDep,
    MasterPasswordCRUDDep,
    SessionTokenHeader,
    VaultAccessDep,
    VaultSessionsDep,
    get_vault_key,
    get_vault_key_quietly,
    require_master_password,
)
from api.rate_limit import limiter, rate
from api.responses import inject_responses
from schemas import (
    Confirmation,
    DeviceEnrollRequest,
    DeviceUnlockRequest,
    DeviceUnlockResult,
    DeviceUnlockSettings,
    DeviceUnlockStatus,
    MasterPasswordCreate,
    MasterPasswordCreatePayload,
    MasterPasswordStatus,
    MasterPasswordUpdate,
    MasterPasswordUpdatePayload,
    RecoverPayload,
    RecoverResult,
    SecurityKeyChallenge,
    SimpleDetailSchema,
    VaultLock,
    VaultSessionStatus,
    VaultUnlock,
)
from vault_sessions import Scope

router = APIRouter(tags=["master-password"])


@router.get(
    "/status",
    name="master-password:status",
    response_model=MasterPasswordStatus,
)
async def get_status(
    crud: MasterPasswordCRUDDep,
) -> MasterPasswordStatus:
    security_key_required, recovery_code = await crud.security_key_status()
    return MasterPasswordStatus(
        initialized=await crud.is_initialized(),
        security_key_required=security_key_required,
        recovery_code=recovery_code,
    )


@router.post(
    "/unlock",
    name="master-password:unlock",
    response_model=VaultUnlock,
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("30/hour"))
async def unlock(
    request: Request,
    body: Confirmation,
    access: VaultAccessDep,
) -> VaultUnlock:
    return await access.unlock(body)


@router.post(
    "/unlock/challenge",
    name="master-password:unlock-challenge",
    response_model=SecurityKeyChallenge,
    responses=inject_responses(
        {
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("60/hour"))
async def unlock_challenge(
    request: Request, access: VaultAccessDep
) -> SecurityKeyChallenge:
    """A challenge for a registered security key, when the vault needs one to
    unlock. Single use, valid for five minutes."""
    return await access.unlock_challenge()


@router.post(
    "/recover",
    name="master-password:recover",
    response_model=RecoverResult,
    responses=inject_responses(
        {
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("10/hour"))
async def recover(
    request: Request, body: RecoverPayload, access: VaultAccessDep
) -> RecoverResult:
    """Set a new master password with the recovery code. Re-keys the vault, ends
    every other session and returns a new recovery code (the old one stops
    working)."""
    return await access.recover(body)


@router.post(
    "/lock",
    name="master-password:lock",
    response_model=VaultLock,
)
async def lock(
    token: SessionTokenHeader, vault_sessions: VaultSessionsDep
) -> VaultLock:
    vault_sessions.revoke(token, scope=Scope.FULL)
    return VaultLock(locked=True)


@router.get(
    "/session",
    name="master-password:session",
    response_model=VaultSessionStatus,
    dependencies=[Depends(require_master_password), Depends(get_vault_key_quietly)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def get_session_status(
    access: VaultAccessDep, credential: CredentialDep
) -> VaultSessionStatus:
    return access.status(credential)


@router.post(
    "/session",
    name="master-password:session-activity",
    response_model=VaultSessionStatus,
    dependencies=[Depends(require_master_password), Depends(get_vault_key)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def record_session_activity(
    access: VaultAccessDep, credential: CredentialDep
) -> VaultSessionStatus:
    return access.status(credential)


@router.post(
    "/create",
    name="master-password:create",
    response_model=MasterPasswordCreate,
    responses=inject_responses(
        {
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("5/hour"))
async def create_master_password(
    request: Request,
    body: MasterPasswordCreatePayload,
    access: VaultAccessDep,
) -> MasterPasswordCreate:
    return await access.create(body.master_password)


@router.patch(
    "/update",
    name="master-password:update",
    response_model=MasterPasswordUpdate,
    dependencies=[Depends(get_vault_key)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("10/hour"))
async def update_master_password(
    request: Request,
    body: MasterPasswordUpdatePayload,
    access: VaultAccessDep,
    credential: CredentialDep,
) -> MasterPasswordUpdate:
    return await access.change_master_password(credential, body)


@router.get(
    "/device-unlock",
    name="master-password:device-status",
    response_model=DeviceUnlockStatus,
)
async def get_device_unlock(access: VaultAccessDep) -> DeviceUnlockStatus:
    return await access.device_status()


@router.post(
    "/device-unlock/unlock",
    name="master-password:device-unlock",
    response_model=DeviceUnlockResult,
    responses=inject_responses({status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema}),
)
@limiter.limit(rate("30/hour"))
async def unlock_with_device(
    request: Request,
    body: DeviceUnlockRequest,
    access: VaultAccessDep,
) -> DeviceUnlockResult:
    return await access.unlock_with_device(body)


@router.post(
    "/device-unlock/enroll",
    name="master-password:device-enroll",
    response_model=DeviceUnlockStatus,
    dependencies=[Depends(get_vault_key)],
    responses=inject_responses(
        {
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("10/hour"))
async def enroll_device(
    request: Request,
    body: DeviceEnrollRequest,
    access: VaultAccessDep,
    credential: CredentialDep,
) -> DeviceUnlockStatus:
    await access.enroll_device(body, credential)
    return await access.device_status()


@router.patch(
    "/device-unlock",
    name="master-password:device-settings",
    response_model=DeviceUnlockStatus,
    dependencies=[Depends(get_vault_key)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def update_device_unlock(
    body: DeviceUnlockSettings, access: VaultAccessDep
) -> DeviceUnlockStatus:
    access.set_password_interval(body.password_interval_days)
    return await access.device_status()


@router.delete(
    "/device-unlock/{credential_id}",
    name="master-password:device-forget",
    response_model=DeviceUnlockStatus,
    dependencies=[Depends(get_vault_key)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def forget_device(
    credential_id: str, access: VaultAccessDep
) -> DeviceUnlockStatus:
    access.forget_device(credential_id)
    return await access.device_status()
