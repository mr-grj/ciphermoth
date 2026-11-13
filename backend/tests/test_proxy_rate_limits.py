from pathlib import Path

import httpx
import pytest

from tests.support import api_server


@pytest.mark.parametrize("trusted_proxy", [False, True])
def test_unlock_rate_limit_uses_only_trusted_forwarded_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trusted_proxy: bool
) -> None:
    # Exercise uvicorn's actual proxy middleware and the production limit;
    # an empty throwaway vault avoids spending Argon2 work on these requests.
    monkeypatch.delenv("CIPHERMOTH_RATE_LIMIT", raising=False)
    monkeypatch.setenv(
        "FORWARDED_ALLOW_IPS", "127.0.0.1" if trusted_proxy else "192.0.2.1"
    )
    with (
        api_server(tmp_path / "server.log", tmp_path / "vault") as server,
        httpx.Client(base_url=server.base_url, timeout=10) as client,
    ):
        for attempt in range(30):
            address = "198.51.100.1" if trusted_proxy else f"198.51.100.{attempt + 1}"
            response = client.post(
                "/master_password/unlock",
                json={"master_password": "synthetic-proxy-rate-test"},
                headers={"X-Forwarded-For": address},
            )
            assert response.status_code == 404

        blocked = client.post(
            "/master_password/unlock",
            json={"master_password": "synthetic-proxy-rate-test"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        assert blocked.status_code == 429

        other_client = client.post(
            "/master_password/unlock",
            json={"master_password": "synthetic-proxy-rate-test"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        )
        assert other_client.status_code == (404 if trusted_proxy else 429)
