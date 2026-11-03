import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, RedirectResponse, Response

from api.access_log import install_access_log_redaction
from api.body_limit import BodySizeLimitMiddleware, keep_uploads_in_memory
from api.exceptions import UnhandledErrorMiddleware
from api.path_guard import EntryNamePaths
from api.rate_limit import limiter
from api.retired_clients import RETIRED_KEY_HEADER, RetiredClients
from api.routes import make_api_exceptions, make_api_router
from api.security_headers import SecurityHeaders
from crud.engine import Database
from models import SETTINGS_DEFAULTS
from settings import get_api_settings
from storage import VaultLock
from vault_sessions import VaultSessions
from webauthn import Challenges

_SESSION_SWEEP_SECONDS = 30

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-XSS-Protection": "0",
    "Permissions-Policy": (
        "clipboard-write=(self), camera=(), microphone=(), geolocation=()"
    ),
    "Cache-Control": "no-store",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def rate_limit_exceeded(request: Request, exc: Exception) -> Response:
    limit = exc.detail if isinstance(exc, RateLimitExceeded) else "too many requests"
    response = JSONResponse(
        {"detail": f"Too many attempts. Try again later (limit: {limit})."},
        status_code=429,
    )
    return request.app.state.limiter._inject_headers(
        response, request.state.view_rate_limit
    )


async def _drop_expired_sessions(vault_sessions: VaultSessions) -> None:
    while True:
        await asyncio.sleep(_SESSION_SWEEP_SECONDS)
        vault_sessions.drop_expired()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    database: Database = app.state.database
    vault_sessions: VaultSessions = app.state.vault_sessions
    with VaultLock(database.data_dir):
        await database.prepare()
        sweeper = asyncio.create_task(_drop_expired_sessions(vault_sessions))
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            vault_sessions.revoke_all()
            await database.dispose()


def get_application(
    database: Database | None = None, vault_sessions: VaultSessions | None = None
) -> FastAPI:
    settings = get_api_settings()
    server = FastAPI(**settings.fastapi_kwargs, lifespan=lifespan)
    server.state.database = database or Database()
    server.state.vault_sessions = (
        vault_sessions
        if vault_sessions is not None
        else VaultSessions(idle_timeout_ms=SETTINGS_DEFAULTS["inactivity_ms"])
    )

    server.state.security_challenges = Challenges()
    server.state.limiter = limiter
    server.add_exception_handler(RateLimitExceeded, rate_limit_exceeded)

    install_access_log_redaction()
    keep_uploads_in_memory()
    server.add_middleware(UnhandledErrorMiddleware, headers=_SECURITY_HEADERS)
    server.add_middleware(BodySizeLimitMiddleware)
    server.add_middleware(EntryNamePaths)
    server.add_middleware(RetiredClients)
    server.add_middleware(
        CORSMiddleware,  # type: ignore[arg-type]
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=[
            "Content-Type",
            "x-ciphermoth-session",
            RETIRED_KEY_HEADER,
            "x-ciphermoth-entry",
        ],
    )

    server.add_middleware(SecurityHeaders, headers=_SECURITY_HEADERS)

    if not settings.disable_docs:

        @server.get("/", include_in_schema=False)
        def redirect_to_docs() -> RedirectResponse:
            return RedirectResponse(settings.docs_url)

    server.include_router(make_api_router(), prefix="/api")
    make_api_exceptions(server)

    return server


app = get_application()
