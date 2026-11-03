from fastapi import APIRouter

from schemas import MetaResponse
from settings import get_api_settings

router = APIRouter(tags=["meta"])


@router.get("", name="meta:get", response_model=MetaResponse)
def get_meta() -> MetaResponse:
    return MetaResponse(
        version=get_api_settings().version,
        features=[
            "bulk-entry-actions",
            "entry-names-with-slash",
            "recovery-code",
            "security-keys",
            "vault-sessions",
        ],
    )
