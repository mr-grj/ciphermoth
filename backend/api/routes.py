from fastapi import APIRouter, FastAPI
from fastapi.exceptions import RequestValidationError

from api.endpoints import (
    extension,
    health,
    master_password,
    meta,
    password,
    security,
    settings,
    vault,
)
from api.exceptions import validation_handler, vault_error_handler
from api.responses import inject_responses
from errors import VaultError


def make_api_router() -> APIRouter:
    api_router = APIRouter()

    api_router.responses = inject_responses()

    api_router.include_router(master_password.router, prefix="/master_password")
    api_router.include_router(extension.router, prefix="/extension")
    api_router.include_router(health.router, prefix="/health")
    api_router.include_router(meta.router, prefix="/meta")
    api_router.include_router(password.router, prefix="/passwords")
    api_router.include_router(security.router, prefix="/security")
    api_router.include_router(settings.router, prefix="/settings")
    api_router.include_router(vault.router, prefix="/vault")

    return api_router


def make_api_exceptions(app: FastAPI) -> None:
    app.add_exception_handler(VaultError, vault_error_handler)
    app.add_exception_handler(RequestValidationError, validation_handler)
