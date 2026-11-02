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
    DeviceEnrollRequest,
    DeviceUnlockRequest,
    DeviceUnlockResult,
    DeviceUnlockSettings,
    DeviceUnlockStatus,
    MasterPassword,
    MasterPasswordCreate,
    MasterPasswordCreatePayload,
    MasterPasswordStatus,
    MasterPasswordUpdate,
    MasterPasswordUpdatePayload,
    SimpleDetailSchema,
    VaultLock,
    VaultSessionStatus,
    VaultUnlock,
)

router = APIRouter(tags=["master-password"])


@router.get(
    "/status",
    name="master-password:status",
    response_model=MasterPasswordStatus,
)
async def get_status(
    crud: MasterPasswordCRUDDep,
) -> MasterPasswordStatus:
    return MasterPasswordStatus(initialized=await crud.is_initialized())


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
    body: MasterPassword,
    access: VaultAccessDep,
) -> VaultUnlock:
    return await access.unlock(body.master_password)


@router.post(
    "/lock",
    name="master-password:lock",
    response_model=VaultLock,
)
async def lock(
    token: SessionTokenHeader, vault_sessions: VaultSessionsDep
) -> VaultLock:
    vault_sessions.revoke(token)
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
    return await access.change_master_password(
        credential,
        master_password=body.master_password,
        new_master_password=body.new_master_password,
    )


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
) -> DeviceUnlockStatus:
    await access.enroll_device(body)
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
