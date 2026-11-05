import logging
import traceback
from collections.abc import Mapping

from fastapi import (
    Request,
    status,
)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from errors import (
    Forbidden,
    InvalidKey,
    InvalidRequest,
    NotFound,
    OriginMismatch,
    SessionRequired,
    UseHandoff,
    VaultBusy,
    VaultDamaged,
    VaultError,
    WrongScope,
)

logger = logging.getLogger(__name__)


_ERROR_RESPONSES: tuple[tuple[type[VaultError], int, str | None], ...] = (
    (SessionRequired, status.HTTP_401_UNAUTHORIZED, "invalid_session"),
    (InvalidKey, status.HTTP_403_FORBIDDEN, "invalid_key"),
    (WrongScope, status.HTTP_403_FORBIDDEN, "extension_scope"),
    (UseHandoff, status.HTTP_409_CONFLICT, "use_handoff"),
    (OriginMismatch, status.HTTP_409_CONFLICT, "origin_mismatch"),
    (Forbidden, status.HTTP_403_FORBIDDEN, None),
    (NotFound, status.HTTP_404_NOT_FOUND, None),
    (InvalidRequest, status.HTTP_400_BAD_REQUEST, None),
    (VaultBusy, status.HTTP_503_SERVICE_UNAVAILABLE, "busy"),
    (VaultDamaged, status.HTTP_500_INTERNAL_SERVER_ERROR, "vault_damaged"),
    (VaultError, status.HTTP_400_BAD_REQUEST, None),
)


async def vault_error_handler(request: Request, exc: Exception) -> JSONResponse:
    status_code, code = next(
        (status_code, code)
        for error, status_code, code in _ERROR_RESPONSES
        if isinstance(exc, error)
    )
    content: dict[str, str] = {"detail": str(exc)}
    headers: dict[str, str] = {}
    if code is not None:
        content["code"] = code
    if status_code == status.HTTP_401_UNAUTHORIZED:
        headers["WWW-Authenticate"] = "CipherMoth-Session"
    if status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
        headers["Retry-After"] = "2"
    return JSONResponse(status_code=status_code, content=content, headers=headers)


async def validation_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    FastAPI's default 422 body echoes every rejected value back, which for this
    API means passwords, notes and master passwords, and fails to render at all
    when the value holds an unpaired surrogate. Only the location and message
    are returned.
    """
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "detail": jsonable_encoder(
                [{"type": e["type"], "loc": e["loc"], "msg": e["msg"]} for e in errors]
            )
        },
    )


def _route_label(scope: Scope) -> str:
    endpoint = scope.get("endpoint")
    if endpoint is None:
        return "<unmatched route>"
    module = getattr(endpoint, "__module__", None) or "?"
    qualname = getattr(endpoint, "__qualname__", None) or type(endpoint).__name__
    name = f"{module}.{qualname}"
    path = getattr(scope.get("route"), "path", None)
    return f"{name} ({path})" if isinstance(path, str) else name


def log_unhandled_exception(scope: Scope, exc: BaseException) -> None:
    logger.error(
        "Unhandled %s on %s %s\n%s",
        type(exc).__name__,
        scope.get("method", "-"),
        _route_label(scope),
        "".join(traceback.format_tb(exc.__traceback__)).rstrip(),
    )


class UnhandledErrorMiddleware:
    """
    Turn any unhandled exception into a generic 500 and log it without request
    details or the exception message, which can carry entry names or SQL
    parameters. The exception is not re-raised, so the server does not log the
    full traceback again on its own.
    """

    def __init__(self, app: ASGIApp, headers: Mapping[str, str]) -> None:
        self.app = app
        self.headers = dict(headers)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            log_unhandled_exception(scope, exc)
            if response_started:
                return
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An internal server error occurred."},
                headers=self.headers,
            )
            await response(scope, receive, send)
