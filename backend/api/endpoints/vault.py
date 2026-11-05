from typing import Literal

from fastapi import APIRouter, Depends, status

from api.endpoints.deps import (
    DamageCRUDDep,
    PasswordCRUDDep,
    VaultKeyDep,
    require_master_password,
)
from api.responses import inject_responses
from schemas import (
    BulkMovePayload,
    BulkMoveResult,
    BulkResult,
    BulkTrashedPayload,
    BulkTrashPayload,
    DamagedRows,
    PasswordDelete,
    SimpleDetailSchema,
)

router = APIRouter(tags=["vault"], dependencies=[Depends(require_master_password)])


@router.get(
    "/damaged",
    name="vault:damaged",
    response_model=DamagedRows,
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def get_damaged(crud: DamageCRUDDep, key: VaultKeyDep) -> DamagedRows:
    return await crud.find(key)


@router.delete(
    "/damaged/{kind}/{row_id}",
    name="vault:remove-damaged",
    response_model=PasswordDelete,
    responses=inject_responses(
        {
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
        }
    ),
)
async def remove_damaged(
    kind: Literal["entries", "attachments"],
    row_id: int,
    crud: DamageCRUDDep,
    key: VaultKeyDep,
) -> PasswordDelete:
    return await crud.remove(key, kind, row_id)


_BULK_RESPONSES = inject_responses(
    {
        status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
        status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
    }
)


@router.post(
    "/entries/trash",
    name="vault:trash-entries",
    response_model=BulkResult,
    responses=_BULK_RESPONSES,
)
async def trash_entries(
    body: BulkTrashPayload, crud: PasswordCRUDDep, key: VaultKeyDep
) -> BulkResult:
    return await crud.trash_passwords([e.password_name for e in body.entries], key)


@router.post(
    "/entries/move",
    name="vault:move-entries",
    response_model=BulkMoveResult,
    responses=_BULK_RESPONSES,
)
async def move_entries(
    body: BulkMovePayload, crud: PasswordCRUDDep, key: VaultKeyDep
) -> BulkMoveResult:
    return await crud.move_passwords(
        [e.password_name for e in body.entries], body.folder, key
    )


@router.post(
    "/trash/restore",
    name="vault:restore-entries",
    response_model=BulkResult,
    responses=_BULK_RESPONSES,
)
async def restore_entries(
    body: BulkTrashedPayload, crud: PasswordCRUDDep, key: VaultKeyDep
) -> BulkResult:
    return await crud.restore_passwords(body.entries, key)


@router.post(
    "/trash/purge",
    name="vault:purge-entries",
    response_model=BulkResult,
    responses=_BULK_RESPONSES,
)
async def purge_entries(
    body: BulkTrashedPayload, crud: PasswordCRUDDep, key: VaultKeyDep
) -> BulkResult:
    return await crud.purge_passwords(body.entries, key)
