import io
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import (
    APIRouter,
    Depends,
    Form,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import ValidationError
from starlette.datastructures import UploadFile as StarletteUpload
from starlette.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

from api.endpoints.deps import (
    AttachmentCRUDDep,
    BackupCRUDDep,
    CredentialDep,
    EntryName,
    PasswordCRUDDep,
    SessionKeyDep,
    VaultKeyDep,
    require_master_password,
)
from api.rate_limit import limiter, rate
from api.responses import inject_responses
from backup_format import MAX_BACKUP_BYTES
from errors import InvalidRequest
from schemas import (
    AttachmentResponse,
    Confirmation,
    FavoriteUpdatePayload,
    MasterPassword,
    OnConflict,
    Password,
    PasswordCreate,
    PasswordDelete,
    PasswordImportResult,
    PasswordResponse,
    PasswordUpdate,
    PasswordUpdatePayload,
    SimpleDetailSchema,
)
from webauthn import session_binding

router = APIRouter(tags=["passwords"])

_MAX_CSV_FILE_BYTES = 10 * 1024 * 1024
_MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
_BACKUP_CHUNK_BYTES = 1024 * 1024


class BackupResponse(StreamingResponse):
    """Own the ciphertext file across success, disconnect and send failure.
    BackgroundTask alone is not guaranteed to run when response delivery raises.
    """

    def __init__(self, backup, filename: str) -> None:
        self.backup = backup
        size = backup.seek(0, 2)
        backup.seek(0)
        super().__init__(
            iter(lambda: backup.read(_BACKUP_CHUNK_BYTES), b""),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(size),
            },
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.backup.close()


async def _read_capped(file: UploadFile, max_bytes: int, message: str) -> bytes:
    if file.size is not None and file.size > max_bytes:
        raise InvalidRequest(message)
    data = await file.read()
    if len(data) > max_bytes:
        raise InvalidRequest(message)
    return data


def _backup_password(submitted: str) -> str:
    try:
        return MasterPassword(master_password=submitted).master_password
    except ValidationError:
        raise InvalidRequest("Enter the password the backup was made with.") from None


def _safe_content_disposition(filename: str) -> str:
    cleaned = "".join(
        character
        for character in filename
        if character.isprintable() and character not in '"\\'
    )
    cleaned = cleaned.strip() or "attachment"
    ascii_name = cleaned.encode("ascii", "replace").decode("ascii").replace("?", "_")
    quoted = quote(cleaned, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted}"


@router.get(
    "",
    name="passwords:get",
    response_model=list[PasswordResponse],
    dependencies=[Depends(require_master_password)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def get_passwords(
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> list[PasswordResponse]:
    return await crud.get_passwords(key)


@router.get(
    "/trash",
    name="passwords:trash",
    response_model=list[PasswordResponse],
    dependencies=[Depends(require_master_password)],
    responses=inject_responses({status.HTTP_403_FORBIDDEN: SimpleDetailSchema}),
)
async def get_trash(
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> list[PasswordResponse]:
    return await crud.get_trash(key)


@router.get(
    "/{password_name}",
    name="passwords:get_by_name",
    response_model=PasswordResponse,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def get_password(
    password_name: EntryName,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> PasswordResponse:
    return await crud.get_password(password_name, key)


@router.post(
    "/create",
    name="password:create",
    response_model=PasswordCreate,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
        }
    ),
)
async def create_password(
    password: Password,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> PasswordCreate:
    return await crud.create_password(password, key)


@router.patch(
    "/update",
    name="passwords:update",
    response_model=PasswordUpdate,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
        }
    ),
)
async def update_password(
    body: PasswordUpdatePayload,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> PasswordUpdate:
    return await crud.update_password(
        password_name=body.password.password_name,
        new_password=body.new_password,
        key=key,
    )


@router.patch(
    "/{password_name}/favorite",
    name="passwords:favorite",
    response_model=PasswordUpdate,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def set_favorite(
    password_name: EntryName,
    body: FavoriteUpdatePayload,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> PasswordUpdate:
    return await crud.set_favorite(password_name, body.favorite, key)


@router.delete(
    "/{password_name}",
    name="passwords:delete",
    response_model=PasswordDelete,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def delete_password(
    password_name: EntryName,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
) -> PasswordDelete:
    return await crud.delete_password(password_name, key)


@router.post(
    "/{password_name}/restore",
    name="passwords:restore",
    response_model=PasswordUpdate,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
        }
    ),
)
async def restore_password(
    password_name: EntryName,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
    entry_id: int | None = Query(default=None, gt=0),
) -> PasswordUpdate:
    return await crud.restore_password(password_name, key, entry_id=entry_id)


@router.delete(
    "/{password_name}/purge",
    name="passwords:purge",
    response_model=PasswordDelete,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def purge_password(
    password_name: EntryName,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
    entry_id: int | None = Query(default=None, gt=0),
) -> PasswordDelete:
    return await crud.purge_password(password_name, key, entry_id=entry_id)


@router.get(
    "/{password_name}/attachments",
    name="attachments:list",
    response_model=list[AttachmentResponse],
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def list_attachments(
    password_name: EntryName,
    crud: AttachmentCRUDDep,
    key: VaultKeyDep,
) -> list[AttachmentResponse]:
    return await crud.list_attachments(password_name, key)


@router.post(
    "/{password_name}/attachments",
    name="attachments:add",
    response_model=AttachmentResponse,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("60/hour"))
async def add_attachment(
    request: Request,
    password_name: EntryName,
    file: UploadFile,
    crud: AttachmentCRUDDep,
    key: VaultKeyDep,
) -> AttachmentResponse:
    data = await _read_capped(
        file, _MAX_ATTACHMENT_BYTES, "Attachment too large. Maximum size is 5 MB."
    )
    return await crud.add_attachment(
        password_name=password_name,
        filename=file.filename or "attachment",
        content_type=file.content_type,
        data=data,
        key=key,
    )


@router.get(
    "/{password_name}/attachments/{attachment_id}",
    name="attachments:download",
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def download_attachment(
    password_name: EntryName,
    attachment_id: int,
    crud: AttachmentCRUDDep,
    key: VaultKeyDep,
) -> StreamingResponse:
    filename, content_type, data = await crud.get_attachment_data(
        password_name, attachment_id, key
    )
    return StreamingResponse(
        io.BytesIO(data),
        media_type=content_type or "application/octet-stream",
        headers={"Content-Disposition": _safe_content_disposition(filename)},
    )


@router.delete(
    "/{password_name}/attachments/{attachment_id}",
    name="attachments:delete",
    response_model=PasswordDelete,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
        }
    ),
)
async def delete_attachment(
    password_name: EntryName,
    attachment_id: int,
    crud: AttachmentCRUDDep,
    key: VaultKeyDep,
) -> PasswordDelete:
    await crud.delete_attachment(password_name, attachment_id, key)
    return PasswordDelete(deleted=True, detail="Attachment deleted.")


_IMPORT_FORM = {
    "content": {
        "multipart/form-data": {
            "schema": {
                "type": "object",
                "required": ["file", "master_password"],
                "properties": {
                    "file": {"type": "string", "format": "binary"},
                    "master_password": {"type": "string"},
                    "on_conflict": {"type": "string", "enum": ["skip", "overwrite"]},
                },
            }
        }
    },
    "required": True,
}


@router.post(
    "/import",
    name="passwords:import",
    response_model=PasswordImportResult,
    openapi_extra={"requestBody": _IMPORT_FORM},
    responses=inject_responses(
        {
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("5/hour"))
async def import_passwords(
    request: Request,
    crud: BackupCRUDDep,
    key: SessionKeyDep,
) -> PasswordImportResult:
    """
    The body is read only after the session check (no form parameters, so
    FastAPI does not parse it first), with one file part and no database
    transaction open while it arrives; the CRUD method checks the key
    against the vault once the slow work is done.
    """
    async with request.form(max_files=1, max_fields=2) as form:
        file = form.get("file")
        master_password = form.get("master_password")
        on_conflict = form.get("on_conflict") or OnConflict.skip.value
        if not isinstance(file, StarletteUpload) or not isinstance(
            master_password, str
        ):
            raise InvalidRequest("Send the backup file and its password.")
        if on_conflict not in (OnConflict.skip.value, OnConflict.overwrite.value):
            raise InvalidRequest("on_conflict must be 'skip' or 'overwrite'.")
        if file.size is not None and file.size > MAX_BACKUP_BYTES:
            raise InvalidRequest("File exceeds the backup format's maximum size.")
        return await crud.import_backup(
            upload=file.file,
            password=_backup_password(master_password),
            key=key,
            on_conflict=OnConflict(on_conflict),
        )


@router.post(
    "/import/csv",
    name="passwords:import_csv",
    response_model=PasswordImportResult,
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_400_BAD_REQUEST: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("5/hour"))
async def import_passwords_csv(
    request: Request,
    file: UploadFile,
    crud: PasswordCRUDDep,
    key: VaultKeyDep,
    on_conflict: OnConflict = Form(OnConflict.skip),
) -> PasswordImportResult:
    file_bytes = await _read_capped(
        file, _MAX_CSV_FILE_BYTES, "File too large. Maximum allowed size is 10 MB."
    )
    return await crud.import_passwords_csv(
        file_bytes=file_bytes,
        key=key,
        on_conflict=on_conflict,
    )


@router.post(
    "/backup",
    name="passwords:backup",
    dependencies=[Depends(require_master_password)],
    responses=inject_responses(
        {
            status.HTTP_403_FORBIDDEN: SimpleDetailSchema,
            status.HTTP_404_NOT_FOUND: SimpleDetailSchema,
            status.HTTP_429_TOO_MANY_REQUESTS: SimpleDetailSchema,
        }
    ),
)
@limiter.limit(rate("3/hour"))
async def backup_passwords(
    request: Request,
    body: Confirmation,
    crud: BackupCRUDDep,
    key: VaultKeyDep,
    credential: CredentialDep,
) -> StreamingResponse:
    backup = await crud.create_backup(body, key, session_binding(credential.token))
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"ciphermoth_backup_{stamp}.cmbackup"
    return BackupResponse(backup, filename)
