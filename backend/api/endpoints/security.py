from fastapi import APIRouter, Depends, Request, status

from api.endpoints.deps import (
    CredentialDep,
    SecurityCRUDDep,
    VaultAccessDep,
    VaultKeyDep,
    get_vault_key,
    require_master_password,
)
from api.rate_limit import limiter, rate
from api.responses import inject_responses
from schemas import (
    Confirmation,
    RecoveryCodeResult,
    SecurityKeyAdd,
    SecurityKeyChallenge,
    SecurityKeyRegistrationOptions,
    SecurityStatus,
    SimpleDetailSchema,
)

router = APIRouter(
    tags=["security"],
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)


@router.get("", name="security:status", response_model=SecurityStatus)
async def get_security(crud: SecurityCRUDDep, key: VaultKeyDep) -> SecurityStatus:
    return await crud.status(key)


@router.post(
    "/challenge",
    name="security:challenge",
    response_model=SecurityKeyChallenge,
    dependencies=[Depends(get_vault_key)],
)
async def confirm_challenge(
    access: VaultAccessDep, credential: CredentialDep
) -> SecurityKeyChallenge:
    """A challenge for a registered security key to confirm a sensitive change
    of this session."""
    return await access.confirm_challenge(credential)


@router.post(
    "/keys/options",
    name="security:key-options",
    response_model=SecurityKeyRegistrationOptions,
)
async def registration_options(
    crud: SecurityCRUDDep, key: VaultKeyDep
) -> SecurityKeyRegistrationOptions:
    return await crud.registration_options()


@router.post(
    "/keys",
    name="security:key-add",
    response_model=SecurityStatus,
    responses=inject_responses({status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema}),
)
@limiter.limit(rate("10/hour"))
async def add_security_key(
    request: Request, body: SecurityKeyAdd, crud: SecurityCRUDDep, key: VaultKeyDep
) -> SecurityStatus:
    return await crud.add(key, body)


@router.post(
    "/keys/{key_id}/remove",
    name="security:key-remove",
    response_model=SecurityStatus,
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("10/hour"))
async def remove_security_key(
    request: Request,
    key_id: int,
    body: Confirmation,
    crud: SecurityCRUDDep,
    key: VaultKeyDep,
) -> SecurityStatus:
    return await crud.remove(key, key_id, body)


@router.post(
    "/recovery-code",
    name="security:recovery-code",
    response_model=RecoveryCodeResult,
    responses=inject_responses({status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema}),
)
@limiter.limit(rate("10/hour"))
async def create_recovery_code(
    request: Request, body: Confirmation, crud: SecurityCRUDDep, key: VaultKeyDep
) -> RecoveryCodeResult:
    return await crud.create_recovery_code(key, body)


@router.post(
    "/recovery-code/remove",
    name="security:recovery-code-remove",
    response_model=SecurityStatus,
    responses=inject_responses({status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema}),
)
@limiter.limit(rate("10/hour"))
async def remove_recovery_code(
    request: Request, body: Confirmation, crud: SecurityCRUDDep, key: VaultKeyDep
) -> SecurityStatus:
    return await crud.remove_recovery_code(key, body)
