import logging

import pytest

from api.access_log import RedactEntryNames, install_access_log_redaction, redact_path


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/api/passwords/github", "/api/passwords/{password_name}"),
        ("GET", "/api/passwords/Bank%20%23main", "/api/passwords/{password_name}"),
        (
            "PATCH",
            "/api/passwords/github/favorite",
            "/api/passwords/{password_name}/favorite",
        ),
        (
            "POST",
            "/api/passwords/github/restore",
            "/api/passwords/{password_name}/restore",
        ),
        (
            "DELETE",
            "/api/passwords/github/purge",
            "/api/passwords/{password_name}/purge",
        ),
        (
            "POST",
            "/api/passwords/github/attachments",
            "/api/passwords/{password_name}/attachments",
        ),
        (
            "GET",
            "/api/passwords/github/attachments/12",
            "/api/passwords/{password_name}/attachments/12",
        ),
        ("GET", "/api/passwords/team/prod/db", "/api/passwords/{redacted}"),
        ("GET", "/api/passwords/a/b/favorite", "/api/passwords/{redacted}"),
        ("GET", "/api/passwords/import", "/api/passwords/{password_name}"),
        (
            "POST",
            "/api/passwords/import/attachments",
            "/api/passwords/{password_name}/attachments",
        ),
        ("GET", "/api/passwords/trash", "/api/passwords/trash"),
        ("POST", "/api/passwords/create", "/api/passwords/create"),
        ("PATCH", "/api/passwords/update", "/api/passwords/update"),
        ("POST", "/api/passwords/import", "/api/passwords/import"),
        ("POST", "/api/passwords/import/csv", "/api/passwords/import/csv"),
        ("POST", "/api/passwords/backup", "/api/passwords/backup"),
        ("GET", "/api/passwords", "/api/passwords"),
        ("GET", "/api/passwords?q=secret", "/api/passwords?{redacted}"),
        ("GET", "/api/settings", "/api/settings"),
        ("POST", "/api/extension/matches", "/api/extension/matches"),
        ("POST", "/api/extension/search", "/api/extension/search"),
        ("POST", "/api/extension/credential", "/api/extension/credential"),
        ("POST", "/api/extension/totp", "/api/extension/totp"),
        ("POST", "/api/extension/unlock", "/api/extension/unlock"),
        ("POST", "/api/extension/session", "/api/extension/session"),
        ("POST", "/api/extension/lock", "/api/extension/lock"),
        ("GET", "/api/extension/sessions", "/api/extension/sessions"),
        ("POST", "/api/extension/sessions", "/api/extension/sessions"),
        (
            "DELETE",
            "/api/extension/sessions/0f3Kq9x2",
            "/api/extension/sessions/0f3Kq9x2",
        ),
        (
            "GET",
            "/api/passwords/x?token=abc",
            "/api/passwords/{password_name}?{redacted}",
        ),
    ],
)
def test_redact_path(method: str, path: str, expected: str) -> None:
    assert redact_path(method, path) == expected


def test_filter_rewrites_uvicorn_access_records() -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", "/api/passwords/my-bank?x=1", "1.1", 200),
        None,
    )
    assert RedactEntryNames().filter(record) is True
    message = record.getMessage()
    assert "my-bank" not in message
    assert "x=1" not in message
    assert message == (
        '127.0.0.1:5000 - "GET /api/passwords/{password_name}?{redacted} HTTP/1.1" 200'
    )


def test_filter_leaves_other_records_alone() -> None:
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, "plain %s", ("text",), None
    )
    assert RedactEntryNames().filter(record) is True
    assert record.getMessage() == "plain text"


def test_installation_is_idempotent() -> None:
    install_access_log_redaction()
    install_access_log_redaction()
    filters = logging.getLogger("uvicorn.access").filters
    assert sum(isinstance(f, RedactEntryNames) for f in filters) == 1
