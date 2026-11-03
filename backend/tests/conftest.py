import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from hypothesis import HealthCheck, settings

from api.rate_limit import limiter
from crud.engine import Database
from main import app
from tests.support import api_server, data_dir, fresh_vault_sessions, reset_vault

_HYPOTHESIS_HEALTH = [HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
settings.register_profile(
    "default",
    max_examples=25,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=_HYPOTHESIS_HEALTH,
)
settings.register_profile(
    "stress",
    max_examples=500,
    deadline=None,
    suppress_health_check=_HYPOTHESIS_HEALTH,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


async def _prepare_test_vault() -> None:
    database = Database(data_dir())
    try:
        await database.prepare()
    finally:
        await database.dispose()


def pytest_sessionstart(session: pytest.Session) -> None:
    asyncio.run(_prepare_test_vault())


@pytest.fixture(autouse=True)
async def clean_state() -> AsyncIterator[None]:
    await reset_vault()
    limiter.reset()
    app.state.vault_sessions = fresh_vault_sessions()
    app.state.security_challenges.clear()
    yield


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver/api", timeout=60
    ) as http:
        yield http


@pytest.fixture(scope="session")
def live_server_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("live-server") / "uvicorn.log"


@pytest.fixture(scope="session")
def live_server(live_server_log: Path) -> Iterator[str]:
    with api_server(live_server_log) as server:
        yield server.base_url
