import http.server
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
import typer
from typer.testing import CliRunner, Result

from cli import app as cli_app
from tests.authenticator import SoftKey
from tests.support import (
    MASTER_PASSWORD,
    WRONG_MASTER_PASSWORD,
    db_execute,
    db_snapshot,
    name_index,
    plant_entry,
)

runner = CliRunner()


@pytest.fixture
def api(live_server: str) -> str:
    resp = httpx.post(
        f"{live_server}/master_password/create",
        json={"master_password": MASTER_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return live_server


def cli(api: str, *args: str, answers: list[str] | None = None) -> Result:
    lines = [MASTER_PASSWORD, *(answers or [])]
    return runner.invoke(
        cli_app,
        list(args),
        input="\n".join(lines) + "\n",
        env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
    )


def ok(result: Result) -> str:
    assert result.exit_code == 0, result.output
    return result.output


async def test_cli_entry_lifecycle(api: str) -> None:
    ok(
        cli(
            api,
            "password",
            "create",
            "Bank [main] #1",
            answers=[
                "Pa$$-[bold]w0rd",
                "Pa$$-[bold]w0rd",
                "moth@example.com",
                "https://bank.test",
                "JBSWY3DPEHPK3PXP",
                "checking",
                "Finance",
            ],
        )
    )
    ok(
        cli(
            api,
            "password",
            "create",
            "recovery codes",
            "--kind",
            "note",
            answers=["code-1 code-2", "code-1 code-2", "", ""],
        )
    )

    listing = ok(cli(api, "password", "list"))
    assert "Bank [main] #1" in listing
    assert "recovery codes" in listing

    details = ok(cli(api, "password", "get", "Bank [main] #1"))
    assert "Pa$$-[bold]w0rd" in details
    assert "moth@example.com" in details
    assert "Finance" in details
    assert "2FA code" in details

    ok(
        cli(
            api,
            "password",
            "update",
            "Bank [main] #1",
            answers=["New-Pass-2", "New-Pass-2", "", "", "", "", ""],
        )
    )
    details = ok(cli(api, "password", "get", "Bank [main] #1"))
    assert "New-Pass-2" in details
    assert "moth@example.com" in details

    ok(cli(api, "password", "delete", "Bank [main] #1", "--yes"))
    assert "Bank [main] #1" in ok(cli(api, "password", "trash"))
    assert "Bank [main] #1" not in ok(cli(api, "password", "list"))
    ok(cli(api, "password", "restore", "Bank [main] #1"))
    assert "New-Pass-2" in ok(cli(api, "password", "get", "Bank [main] #1"))

    ok(cli(api, "password", "delete", "recovery codes", "--yes"))
    ok(cli(api, "password", "purge", "recovery codes", "--yes"))
    assert "The trash is empty" in ok(cli(api, "password", "trash"))


@pytest.mark.parametrize(
    "payload",
    [
        "\x1b[31mterminal canary",
        "\x1b[0mterminal canary",
        "\x9b0mterminal canary",
    ],
    ids=["escape-color", "escape-reset", "c1-reset"],
)
async def test_cli_terminal_controls_are_visible_text_without_changing_values(
    api: str, key: dict[str, str], payload: str
) -> None:
    _api_create(
        api,
        key,
        {
            "password_name": "terminal canary",
            "password_value": payload,
            "username": payload,
            "description": payload,
            "custom_fields": [{"label": payload, "value": payload, "hidden": False}],
        },
    )
    for output in (
        ok(cli(api, "password", "list")),
        ok(cli(api, "password", "get", "terminal canary")),
    ):
        assert all(ord(c) != 27 and not 128 <= ord(c) < 160 for c in output)
        assert "\\x1b" in output or "\\x9b" in output
    stored = httpx.get(f"{api}/passwords/terminal%20canary", headers=key).json()
    assert stored["password_value"] == payload
    assert stored["username"] == payload
    assert stored["description"] == payload
    assert stored["custom_fields"][0] == {
        "label": payload,
        "value": payload,
        "hidden": False,
    }


async def test_cli_backup_import_and_csv(api: str, tmp_path: Path) -> None:
    ok(
        cli(
            api,
            "password",
            "create",
            "mail",
            answers=["mail-Pass-1", "mail-Pass-1", "", "", "", "", ""],
        )
    )
    ok(cli(api, "backup", "--out", str(tmp_path)))
    [archive] = list(tmp_path.glob("ciphermoth_backup_*.cmbackup"))
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    content = archive.read_bytes()
    assert content.startswith(b"CMBACKUP")
    assert b"mail" not in content

    ok(cli(api, "password", "delete", "mail", "--yes"))
    ok(cli(api, "password", "purge", "mail", "--yes"))
    assert "1 added" in ok(cli(api, "import", str(archive), answers=[""]))
    assert "mail-Pass-1" in ok(cli(api, "password", "get", "mail"))
    wrong = cli(api, "import", str(archive), answers=[WRONG_MASTER_PASSWORD])
    assert wrong.exit_code == 1
    assert "Incorrect backup password" in wrong.output

    csv_file = tmp_path / "export.csv"
    csv_file.write_text("name,password\nmail,csv-Pass-2\nshop,shop-Pass-3\n")
    output = ok(cli(api, "import-csv", str(csv_file), "--on-conflict", "overwrite"))
    assert "1 added" in output
    assert "1 overwritten" in output
    assert "csv-Pass-2" in ok(cli(api, "password", "get", "mail"))


async def test_cli_selects_the_requested_same_name_trash_row(
    api: str, key: dict[str, str]
) -> None:
    for value in ("older", "newer"):
        _api_create(api, key, {"password_name": "shared", "password_value": value})
        assert httpx.delete(f"{api}/passwords/shared", headers=key).is_success
    rows = httpx.get(f"{api}/passwords/trash", headers=key).json()
    older = next(row for row in rows if row["password_value"] == "older")
    newer = next(row for row in rows if row["password_value"] == "newer")
    assert str(older["id"]) in ok(cli(api, "password", "trash"))
    ok(cli(api, "password", "purge", "shared", "--id", str(older["id"]), "--yes"))
    remaining = httpx.get(f"{api}/passwords/trash", headers=key).json()
    assert [row["id"] for row in remaining] == [newer["id"]]
    ok(cli(api, "password", "restore", "shared", "--id", str(newer["id"])))
    assert _api_get(api, key, "shared")["password_value"] == "newer"


async def test_cli_rejects_a_wrong_master_password(live_server: str) -> None:
    httpx.post(
        f"{live_server}/master_password/create",
        json={"master_password": MASTER_PASSWORD},
    )
    result = runner.invoke(
        cli_app,
        ["password", "list"],
        input=WRONG_MASTER_PASSWORD + "\n",
        env={"CIPHERMOTH_API_URL": live_server},
    )
    assert result.exit_code == 1
    assert "Invalid master password" in result.output


async def test_live_server_logs_do_not_contain_secrets(
    api: str, live_server_log: Path
) -> None:
    ok(
        cli(
            api,
            "password",
            "create",
            "log-canary-entry",
            answers=["log-canary-Value", "log-canary-Value", "", "", "", "", ""],
        )
    )
    ok(cli(api, "password", "get", "log-canary-entry"))
    log = live_server_log.read_text(errors="replace")
    assert "log-canary-Value" not in log
    assert MASTER_PASSWORD not in log
    assert "log-canary-entry" not in log
    assert '"GET /api/passwords/{password_name} HTTP/1.1" 200' in log


async def test_cli_lists_and_disconnects_connected_browsers(api: str) -> None:
    assert "No browser is connected" in ok(cli(api, "browsers"))
    resp = httpx.post(
        f"{api}/extension/unlock",
        json={"master_password": MASTER_PASSWORD, "browser": "Firefox"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["session_token"]
    listed = ok(cli(api, "browsers"))
    assert "Firefox" in listed
    assert token not in listed
    web = httpx.post(
        f"{api}/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    ).json()["session_token"]
    (session,) = httpx.get(
        f"{api}/extension/sessions", headers={"x-ciphermoth-session": web}
    ).json()
    handle = session["id"]
    assert handle in listed
    assert "Disconnected" in ok(cli(api, "browsers", "--disconnect", handle))
    assert "No browser is connected" in ok(cli(api, "browsers"))
    ended = httpx.post(
        f"{api}/extension/session", headers={"x-ciphermoth-session": token}
    )
    assert ended.status_code == 401
    missing = cli(api, "browsers", "--disconnect", "no-such-id")
    assert missing.exit_code == 1
    assert "No such browser extension session" in missing.output
    assert "Traceback" not in missing.output


async def test_cli_reports_and_removes_damaged_rows_without_a_traceback(
    api: str, tmp_path: Path
) -> None:
    ok(
        cli(
            api,
            "password",
            "create",
            "good",
            answers=["good-Pass-1", "good-Pass-1", "", "", "", "", ""],
        )
    )
    assert "Nothing is damaged" in ok(cli(api, "damaged"))
    planted = await plant_entry("planted")
    await db_execute(
        "UPDATE entries SET document = :document WHERE id = :id",
        document=b"\x02" + os.urandom(60),
        id=planted,
    )
    listing = ok(cli(api, "password", "list"))
    assert "good" in listing and "planted" not in listing
    backup = cli(api, "backup", "--out", str(tmp_path))
    assert backup.exit_code == 1
    assert f"Entry #{planted}" in backup.output
    assert "Traceback" not in backup.output
    report = ok(cli(api, "damaged"))
    assert f"entry #{planted} cannot be read" in report
    assert cli(api, "damaged", "--remove", answers=["n"]).exit_code == 1
    assert "Removed 1 damaged row" in ok(cli(api, "damaged", "--remove", "--yes"))
    assert "Nothing is damaged" in ok(cli(api, "damaged"))
    ok(cli(api, "backup", "--out", str(tmp_path)))

    missing = cli(api, "password", "delete", "never-existed", "--yes")
    assert missing.exit_code == 1
    assert "No password found" in missing.output


async def test_cli_deletes_several_entries_together(api: str) -> None:
    for name in ("one", "two/x", "three [3]", "kept"):
        ok(cli(api, "password", "create", name, answers=["Value-12345"] * 2 + [""] * 5))

    refused = cli(api, "password", "delete", "one", "missing", "--yes")
    assert refused.exit_code == 1
    assert "No password found for 'missing'" in refused.output
    assert "one" in ok(cli(api, "password", "list"))

    asked = cli(api, "password", "delete", "one", "two/x", "three [3]", answers=["n"])
    assert asked.exit_code == 1
    assert "three [3]" in asked.output and "Move these 3 entries" in asked.output

    out = ok(cli(api, "password", "delete", "one", "two/x", "one", "three [3]", "-y"))
    assert "Moved 3 entries to trash" in out
    listing = ok(cli(api, "password", "list"))
    assert "kept" in listing and "one" not in listing and "two/x" not in listing
    assert "three [3]" in ok(cli(api, "password", "trash"))


def test_cli_refuses_several_names_on_an_older_server() -> None:
    def respond(handler: _Recorder) -> None:
        if not _answer_unlock(handler, "sessions"):
            handler.send(500, {"detail": "unexpected"})

    with _fake_server(respond) as (api, requests):
        result = cli(api, "password", "delete", "a", "b", "--yes")
    assert result.exit_code == 1
    assert "needs CipherMoth 3.3.0 or newer" in result.output
    assert not any("/vault/entries/trash" in line for line in map(str, requests))


async def test_cli_moves_several_entries_to_a_folder(api: str) -> None:
    for name in ("one", "two/x", "three [3]", "kept"):
        ok(cli(api, "password", "create", name, answers=["Value-12345"] * 2 + [""] * 5))

    def folder_of(name: str) -> str | None:
        resp = httpx.post(
            f"{api}/master_password/unlock", json={"master_password": MASTER_PASSWORD}
        )
        headers = {"x-ciphermoth-session": resp.json()["session_token"]}
        rows = httpx.get(f"{api}/passwords", headers=headers).json()
        return next(r["folder"] for r in rows if r["password_name"] == name)

    for args, message in (
        ((), "Give either --folder NAME or --no-folder."),
        (("--folder", "W", "--no-folder"), "Give either --folder NAME or --no-folder."),
        (("--folder", "   "), "Folder name can't be empty."),
    ):
        refused = cli(api, "password", "move", "one", *args)
        assert refused.exit_code == 1
        assert message in refused.output

    refused = cli(api, "password", "move", "one", "missing", "-f", "Work")
    assert refused.exit_code == 1
    assert "No password found for 'missing'" in refused.output
    assert folder_of("one") is None

    out = ok(
        cli(
            api,
            "password",
            "move",
            "one",
            "two/x",
            "one",
            "three [3]",
            "-f",
            " [Work] ",
        )
    )
    assert "Moved 3 entries to [Work]" in out
    assert [folder_of(n) for n in ("one", "two/x", "three [3]", "kept")] == [
        "[Work]",
        "[Work]",
        "[Work]",
        None,
    ]
    assert "Folder" in ok(cli(api, "password", "get", "one"))

    out = ok(cli(api, "password", "move", "one", "kept", "--folder", "[Work]"))
    assert "Moved 1 entry to [Work] (1 entry already there)" in out

    out = ok(cli(api, "password", "move", "one", "two/x", "--no-folder"))
    assert "Took 2 entries out of their folder" in out
    assert folder_of("one") is None and folder_of("three [3]") == "[Work]"

    too_long = cli(api, "password", "move", "one", "-f", "F" * 201)
    assert too_long.exit_code == 1
    assert folder_of("one") is None


async def test_cli_shows_password_history(api: str) -> None:
    ok(
        cli(
            api,
            "password",
            "create",
            "site [x]",
            answers=["First-[b]-1"] * 2 + [""] * 5,
        )
    )
    assert "No earlier passwords for site [x]." in ok(
        cli(api, "password", "history", "site [x]")
    )
    for value in ("Second-Value-2", "Third-Value-3"):
        ok(
            cli(
                api, "password", "update", "site [x]", answers=[value, value] + [""] * 5
            )
        )

    out = ok(cli(api, "password", "history", "site [x]"))
    assert out.index("Second-Value-2") < out.index("First-[b]-1")
    assert "Third-Value-3" not in out
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", out)

    missing = cli(api, "password", "history", "missing")
    assert missing.exit_code == 1
    assert "No password found" in missing.output


def test_cli_refuses_to_move_on_an_older_server() -> None:
    def respond(handler: _Recorder) -> None:
        if not _answer_unlock(handler, "sessions"):
            handler.send(500, {"detail": "unexpected"})

    with _fake_server(respond) as (api, requests):
        result = cli(api, "password", "move", "a", "--folder", "Work")
    assert result.exit_code == 1
    assert "needs CipherMoth 3.5.0 or newer" in result.output
    assert not any("/vault/entries/move" in line for line in map(str, requests))


FULL_ENTRY = {
    "password_name": "full",
    "kind": "login",
    "username": "moth@example.com",
    "password_value": "full-Value-1",
    "url": "https://full.test",
    "totp_secret": "JBSWY3DPEHPK3PXP",
    "description": "every field",
    "tags": ["one", "two"],
    "custom_fields": [
        {"label": "PIN", "value": "1234", "hidden": True},
        {"label": "Account", "value": "42", "hidden": False},
    ],
    "folder": "Finance",
    "favorite": True,
}
NOTE_ENTRY = {
    "password_name": "note",
    "kind": "note",
    "password_value": "  body line\n\n",
    "description": "a note",
    "tags": ["n"],
    "custom_fields": [{"label": "ref", "value": "x", "hidden": False}],
    "folder": "Notes",
    "favorite": True,
}
COMPARED = (
    "kind",
    "username",
    "password_value",
    "url",
    "totp_secret",
    "description",
    "tags",
    "custom_fields",
    "folder",
    "favorite",
    "password_history",
)


@pytest.fixture
def key(api: str) -> dict[str, str]:
    resp = httpx.post(
        f"{api}/master_password/unlock", json={"master_password": MASTER_PASSWORD}
    )
    return {"x-ciphermoth-session": resp.json()["session_token"]}


def _api_create(api: str, key: dict[str, str], item: dict) -> None:
    resp = httpx.post(f"{api}/passwords/create", json=item, headers=key)
    assert resp.status_code == 200, resp.text


def _api_get(api: str, key: dict[str, str], name: str) -> dict:
    resp = httpx.get(f"{api}/passwords/{quote(name, safe='')}", headers=key)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("item", [FULL_ENTRY, NOTE_ENTRY], ids=["login", "note"])
async def test_cli_update_with_blank_answers_changes_nothing(
    api: str, key: dict[str, str], item: dict
) -> None:
    _api_create(api, key, item)
    before = _api_get(api, key, item["password_name"])
    prompts = 3 if item["kind"] == "note" else 6

    ok(cli(api, "password", "update", item["password_name"], answers=[""] * prompts))

    after = _api_get(api, key, item["password_name"])
    assert {f: after[f] for f in COMPARED} == {f: before[f] for f in COMPARED}


async def test_cli_update_changes_only_what_was_typed(
    api: str, key: dict[str, str]
) -> None:
    _api_create(api, key, FULL_ENTRY)

    ok(
        cli(
            api,
            "password",
            "update",
            "full",
            answers=["full-Value-2", "full-Value-2", "", "", "", "new description", ""],
        )
    )

    after = _api_get(api, key, "full")
    assert after["password_value"] == "full-Value-2"
    assert after["description"] == "new description"
    assert [h["value"] for h in after["password_history"]] == ["full-Value-1"]
    for field in ("username", "url", "totp_secret", "tags", "custom_fields"):
        assert after[field] == FULL_ENTRY[field]
    assert after["folder"] == "Finance"
    assert after["favorite"] is True


HOSTILE_NAMES = [
    "notes#2024",
    "a?b=c&d",
    "50% off",
    ".",
    "..",
    "...",
    "space  name ",
    "ünï 🦋",
    "[bold]markup[bold]",
    "back\\slash",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
async def test_cli_reaches_exactly_the_named_entry(
    api: str, key: dict[str, str], name: str
) -> None:
    for decoy in ("notes", "a", "50", "escape", "decoy"):
        _api_create(api, key, {"password_name": decoy, "password_value": f"{decoy}-v"})
    if name in (".", ".."):
        await plant_entry(name, "target-Value-1")
    else:
        _api_create(
            api, key, {"password_name": name, "password_value": "target-Value-1"}
        )
    stored = name.strip()

    assert "target-Value-1" in ok(cli(api, "password", "get", stored))
    ok(cli(api, "password", "delete", stored, "--yes"))

    rows = await db_execute("SELECT name_index FROM entries WHERE deleted IS NOT NULL")
    assert rows == [(await name_index(stored),)]


SLASH_NAMES = ["a/b", "x/purge", "x/restore", "x/attachments/1", "../x", "x/.."]


async def _slash_vault(api: str, key: dict[str, str], name: str) -> list[tuple]:
    _api_create(api, key, {"password_name": "x", "password_value": "x-trashed"})
    assert httpx.delete(f"{api}/passwords/x", headers=key).is_success
    _api_create(api, key, {"password_name": "x", "password_value": "x-Value-1"})
    resp = httpx.post(
        f"{api}/passwords/x/attachments",
        files={"file": ("f.bin", b"keep me", "application/octet-stream")},
        headers=key,
    )
    assert resp.status_code == 200
    _api_create(api, key, {"password_name": name, "password_value": "slash-v"})
    return await _rows_named("x")


async def _rows_named(name: str) -> list[tuple]:
    return await db_execute(
        "SELECT e.id, e.document, e.deleted, a.id FROM entries e "
        "LEFT JOIN attachments a ON a.entry_id = e.id "
        "WHERE e.name_index = :index ORDER BY e.id",
        index=await name_index(name),
    )


@pytest.mark.parametrize("name", SLASH_NAMES)
async def test_cli_manages_names_with_a_slash_without_touching_others(
    api: str, key: dict[str, str], name: str
) -> None:
    decoys = await _slash_vault(api, key, name)

    assert "slash-v" in ok(cli(api, "password", "get", name))
    ok(cli(api, "password", "delete", name, "--yes"))
    ok(cli(api, "password", "restore", name))
    ok(cli(api, "password", "delete", name, "--yes"))
    ok(cli(api, "password", "purge", name, "--yes"))

    assert await _rows_named("x") == decoys
    assert await _rows_named(name) == []


@pytest.mark.parametrize("command", [["get"], ["delete", "--yes"], ["purge", "--yes"]])
def test_cli_refuses_slash_names_unless_the_server_says_it_routes_them(
    command: list[str],
) -> None:
    def respond(handler: _Recorder) -> None:
        if handler.path.endswith("/meta"):
            handler.send(502, b"bad gateway")
        elif not _answer_unlock(handler, "sessions"):
            handler.send(200, {})

    with _fake_server(respond) as (api, requests):
        result = runner.invoke(
            cli_app,
            ["password", command[0], "x/purge", *command[1:]],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api},
        )

    assert result.exit_code == 1
    assert "Update CipherMoth" in result.output
    assert [path for _, path, _ in requests if "/passwords" in path] == []


async def test_cli_explains_an_entry_it_cannot_open_by_name(
    api: str, key: dict[str, str]
) -> None:
    await plant_entry("trash", "legacy-v")
    for command in ("get", "update"):
        result = cli(api, "password", command, "trash")
        assert result.exit_code == 1
        assert "can't be opened by name" in result.output
        assert "Traceback" not in result.output
    ok(cli(api, "password", "delete", "trash", "--yes"))
    assert await db_execute(
        "SELECT count(*) FROM entries WHERE name_index = :index "
        "AND deleted IS NOT NULL",
        index=await name_index("trash"),
    ) == [(1,)]


async def test_cli_prints_markup_in_stored_values_literally(
    api: str, key: dict[str, str]
) -> None:
    markup = "[red]x[/red] [/] [link=https://evil.test]click[/link] [bold"
    name = "markup [red]x[red] [bold"
    _api_create(
        api,
        key,
        {
            "password_name": name,
            "password_value": "v " + markup,
            "username": "u " + markup,
            "url": "https://x.test/" + markup,
            "description": "d " + markup,
            "folder": "f " + markup,
            "tags": ["t [red]x[/red] [/]"],
            "custom_fields": [{"label": "l " + markup, "value": "c " + markup}],
        },
    )

    details = ok(cli(api, "password", "get", name))
    for prefix in ("v", "u", "d", "f", "l", "c"):
        assert f"{prefix} {markup}" in details
    assert "t [red]x[/red] [/]" in details
    listing = ok(cli(api, "password", "list"))
    assert name in listing


async def test_cli_masks_hidden_custom_fields(api: str, key: dict[str, str]) -> None:
    _api_create(api, key, FULL_ENTRY)
    details = ok(cli(api, "password", "get", "full"))
    assert "1234" not in details
    assert "••••••••" in details
    assert "42" in details


async def test_cli_never_echoes_the_master_password(
    api: str, key: dict[str, str], tmp_path: Path
) -> None:
    _api_create(api, key, FULL_ENTRY)
    outputs = [
        cli(api, "password", "list").output,
        cli(api, "password", "get", "full").output,
        cli(api, "backup", "--out", str(tmp_path)).output,
    ]
    for output in outputs:
        assert MASTER_PASSWORD not in output


def test_cli_takes_no_secret_as_an_argument_or_option() -> None:
    command = typer.main.get_command(cli_app)
    forbidden = ("password", "secret", "master", "key", "totp", "value", "token")

    def walk(cmd: Any, path: str) -> list[str]:
        found = [
            f"{path} {p.name}"
            for p in cmd.params
            if any(word in (p.name or "").lower() for word in forbidden)
        ]
        for name, sub in getattr(cmd, "commands", {}).items():
            found += walk(sub, f"{path} {name}")
        return found

    assert walk(command, "ciphermoth") == []


class _Recorder(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str, dict]] = []
    respond: Callable[["_Recorder"], None] = staticmethod(lambda handler: None)

    def _handle(self) -> None:
        self.rfile.read(int(self.headers.get("content-length") or 0))
        type(self).requests.append((self.command, self.path, dict(self.headers)))
        type(self).respond(self)

    do_GET = do_POST = do_PATCH = do_DELETE = _handle

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send(self, status: int, payload: object, **headers: str) -> None:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@contextmanager
def _fake_server(respond: Callable[[_Recorder], None]) -> Iterator[tuple[str, list]]:
    handler = type(
        "Handler", (_Recorder,), {"requests": [], "respond": staticmethod(respond)}
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api", handler.requests
    finally:
        server.shutdown()
        server.server_close()


TOKEN = "T" * 43
FAKE_KEY = "K" * 43 + "="
SERVERS = {
    "v1.4.6": {"version": "1.4.6"},
    "v1.4.7": {"version": "1.4.7", "features": ["entry-names-with-slash"]},
    "sessions": {
        "version": "1.5.0",
        "features": ["entry-names-with-slash", "vault-sessions"],
    },
}


def _answer_unlock(handler: _Recorder, server: str) -> bool:
    path = handler.path
    sessions = "vault-sessions" in SERVERS[server].get("features", [])
    if path.endswith("/meta"):
        handler.send(200, SERVERS[server])
    elif path.endswith("/master_password/unlock"):
        if sessions:
            handler.send(200, {"valid": True, "session_token": TOKEN})
        else:
            handler.send(404, {"detail": "Not Found"})
    elif path.endswith("/master_password/check"):
        handler.send(200, {"valid": True, "key_derivation": FAKE_KEY})
    elif path.endswith("/master_password/lock") and sessions:
        handler.send(200, {"locked": True})
    else:
        return False
    return True


@pytest.mark.parametrize("interrupted", [False, True])
def test_cli_streams_large_backups_and_never_publishes_partial_transfers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    size = 25 * 1024 * 1024
    original_read = httpx.Response.read

    def no_buffer(response: httpx.Response) -> bytes:
        if (
            response.request.url.path.endswith("/passwords/backup")
            and response.is_success
        ):
            pytest.fail("The CLI buffered the entire backup response")
        return original_read(response)

    monkeypatch.setattr(httpx.Response, "read", no_buffer)

    def respond(handler: _Recorder) -> None:
        if _answer_unlock(handler, "sessions"):
            return
        handler.send_response(200)
        handler.send_header("content-length", str(size))
        handler.end_headers()
        chunk = b"encrypted-fixture".ljust(1024 * 1024, b"x")
        for _ in range(2 if interrupted else 25):
            handler.wfile.write(chunk)

    with _fake_server(respond) as (api, _):
        result = cli(api, "backup", "--out", str(tmp_path))
        if interrupted:
            assert result.exit_code == 1
            assert "Backup could not be saved" in result.output
            assert list(tmp_path.iterdir()) == []
        else:
            ok(result)
            [archive] = tmp_path.glob("*.cmbackup")
            assert archive.stat().st_size == size
            assert stat.S_IMODE(archive.stat().st_mode) == 0o600
            assert not list(tmp_path.glob("*.partial"))
            # Repeating the command cannot replace the earlier backup.
            ok(cli(api, "backup", "--out", str(tmp_path)))
            assert len(list(tmp_path.glob("*.cmbackup"))) == 2
            assert archive.stat().st_size == size


def test_cli_import_streams_from_disk_and_rewinds_on_session_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = tmp_path / "large.cmbackup"
    file.write_bytes(b"ciphertext" * (3 * 1024 * 1024))
    attempts = 0

    def no_read_bytes(path: Path) -> bytes:
        pytest.fail(f"The CLI buffered the entire import: {path.name}")

    monkeypatch.setattr(Path, "read_bytes", no_read_bytes)

    def receive(handler: _Recorder) -> None:
        body = handler.rfile.read(int(handler.headers.get("content-length") or 0))
        if handler.path.endswith("/passwords/import"):
            assert body.count(b"ciphertext") == 3 * 1024 * 1024
        type(handler).requests.append(
            (handler.command, handler.path, dict(handler.headers))
        )
        type(handler).respond(handler)

    monkeypatch.setattr(_Recorder, "do_POST", receive)

    def respond(handler: _Recorder) -> None:
        nonlocal attempts
        if _answer_unlock(handler, "sessions"):
            return
        assert int(handler.headers["content-length"]) > file.stat().st_size
        attempts += 1
        if attempts == 1:
            handler.send(401, {"detail": "Your session expired."})
        else:
            handler.send(200, {"imported": 1, "overwritten": 0, "skipped": 0})

    with _fake_server(respond) as (api, _):
        ok(cli(api, "import", str(file), answers=[""]))
    assert attempts == 2


def _lower(headers: dict) -> dict:
    return {name.lower(): value for name, value in headers.items()}


@pytest.mark.parametrize("server", sorted(SERVERS))
@pytest.mark.parametrize("redirect_unlock", [False, True])
def test_cli_never_follows_redirects_with_the_key_or_password(
    redirect_unlock: bool, server: str
) -> None:
    with _fake_server(lambda handler: handler.send(200, [])) as (evil, evil_requests):

        def respond(handler: _Recorder) -> None:
            unlocking = handler.path.endswith(
                ("/master_password/check", "/master_password/unlock")
            )
            legacy_probe = server != "sessions" and handler.path.endswith("/unlock")
            if (
                handler.path.endswith("/meta")
                or legacy_probe
                or (unlocking and not redirect_unlock)
            ):
                _answer_unlock(handler, server)
            else:
                handler.send(
                    307, b"", location=f"{evil.removesuffix('/api')}{handler.path}"
                )

        with _fake_server(respond) as (api, _):
            result = runner.invoke(
                cli_app,
                ["password", "list"],
                input=MASTER_PASSWORD + "\n",
                env={"CIPHERMOTH_API_URL": api},
            )

    assert result.exit_code == 1
    assert evil_requests == []


def test_cli_uses_a_session_and_locks_it_when_the_command_ends() -> None:
    def respond(handler: _Recorder) -> None:
        if _answer_unlock(handler, "sessions"):
            return
        if handler.path.endswith("/passwords/missing"):
            handler.send(404, {"detail": "No password found."})
        else:
            handler.send(200, [])

    with _fake_server(respond) as (api, requests):
        for command in (["list"], ["get", "missing"]):
            runner.invoke(
                cli_app,
                ["password", *command],
                input=MASTER_PASSWORD + "\n",
                env={"CIPHERMOTH_API_URL": api},
            )

    paths = [path.removeprefix("/api") for _, path, _ in requests]
    assert paths == [
        "/meta",
        "/master_password/unlock",
        "/passwords",
        "/master_password/lock",
        "/meta",
        "/master_password/unlock",
        "/passwords/missing",
        "/master_password/lock",
    ]
    for _, path, headers in requests:
        headers = _lower(headers)
        assert "x-ciphermoth-key-derivation" not in headers
        assert "authorization" not in headers
        if path.endswith(("/passwords", "/missing", "/lock")):
            assert headers["x-ciphermoth-session"] == TOKEN


@pytest.mark.parametrize("server", ["v1.4.6", "v1.4.7"])
def test_cli_refuses_servers_that_predate_sessions(server: str) -> None:
    def respond(handler: _Recorder) -> None:
        if not _answer_unlock(handler, server):
            handler.send(200, [])

    with _fake_server(respond) as (api, requests):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
        )

    assert result.exit_code == 1
    assert "older than 1.5.0" in result.output
    assert "Traceback" not in result.output
    paths = [path.removeprefix("/api") for _, path, _ in requests]
    assert paths == ["/meta", "/master_password/unlock"]
    assert all("x-ciphermoth-key-derivation" not in _lower(h) for _, _, h in requests)


def test_cli_points_at_the_api_url_when_nothing_answers_there() -> None:
    with _fake_server(lambda handler: handler.send(404, {"detail": "Not Found"})) as (
        api,
        requests,
    ):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api.removesuffix("/api"), "COLUMNS": "200"},
        )

    assert result.exit_code == 1
    assert "CIPHERMOTH_API_URL ends in /api" in result.output
    assert "Traceback" not in result.output
    paths = [path for _, path, _ in requests]
    assert paths == ["/meta", "/master_password/unlock"]


@pytest.mark.parametrize("failure", ["meta-connect", "unlock-connect", "not-found"])
def test_cli_diagnostics_do_not_echo_url_credentials_or_metadata(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import cli as backend_cli

    original = httpx.Client
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if failure == "meta-connect" or (
            failure == "unlock-connect" and request.method == "POST"
        ):
            raise httpx.ConnectError("synthetic connection failure", request=request)
        if failure == "unlock-connect":
            return httpx.Response(200, json=SERVERS["sessions"])
        return httpx.Response(404, json={"detail": "Not Found"})

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        return original(*args, **kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(backend_cli.httpx, "Client", client)
    address = (
        "http://UrlUserCanary:UrlPasswordCanary@vault.invalid/api"
        "?token=UrlQueryCanary#UrlFragmentCanary"
    )
    result = runner.invoke(
        cli_app,
        ["password", "list"],
        input=MASTER_PASSWORD + "\n",
        env={"CIPHERMOTH_API_URL": address, "COLUMNS": "200"},
    )
    assert result.exit_code == 1
    assert all(
        value not in result.output
        for value in (
            "UrlUserCanary",
            "UrlPasswordCanary",
            "UrlQueryCanary",
            "UrlFragmentCanary",
        )
    )
    assert "http://vault.invalid/api" in result.output
    assert requests
    assert all(
        request.headers.get("authorization", "").startswith("Basic ")
        for request in requests
    )


def test_cli_unexpected_errors_do_not_render_secret_locals() -> None:
    canary = "Traceback-Password-Canary-2026!"
    code = (
        "import cli\n"
        "def fail(self):\n"
        "    raise RuntimeError('synthetic authenticator fault')\n"
        "cli._Vault._security_key_required = fail\n"
        "cli.app()\n"
    )
    with _fake_server(lambda handler: handler.send(200, SERVERS["sessions"])) as (
        api,
        _,
    ):
        result = subprocess.run(
            [sys.executable, "-c", code, "password", "list"],
            input=canary + "\n",
            capture_output=True,
            text=True,
            timeout=30,
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
        )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "synthetic authenticator fault" in output
    assert canary not in output


@pytest.mark.parametrize("meta", ["unreachable", "broken"])
def test_cli_does_not_fall_back_to_the_vault_key_when_meta_fails(meta: str) -> None:
    def respond(handler: _Recorder) -> None:
        if handler.path.endswith("/meta"):
            if meta == "broken":
                handler.send(502, b"<html>bad gateway</html>")
            else:
                handler.send(500, {"detail": "boom"})
        elif not _answer_unlock(handler, "sessions"):
            handler.send(200, [])

    with _fake_server(respond) as (api, requests):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api},
        )

    assert result.exit_code == 0, result.output
    paths = [path.removeprefix("/api") for _, path, _ in requests]
    assert "/master_password/check" not in paths
    assert all("x-ciphermoth-key-derivation" not in _lower(h) for _, _, h in requests)


@pytest.mark.parametrize(
    ("meta", "unlock_status", "unlock_body"),
    [
        ("sessions", 404, {"detail": "Not Found"}),
        ("broken", 404, {"detail": "No master password found."}),
        ("broken", 403, {"detail": "Forbidden."}),
        ("broken", 500, {"detail": "An internal server error occurred."}),
        ("broken", 404, b"<html>proxy 404</html>"),
        ("broken", 429, {"detail": "Too many attempts."}),
    ],
)
def test_cli_never_falls_back_to_the_vault_key_on_an_unrelated_error(
    meta: str, unlock_status: int, unlock_body: object
) -> None:
    def respond(handler: _Recorder) -> None:
        if handler.path.endswith("/meta"):
            if meta == "sessions":
                handler.send(200, SERVERS["sessions"])
            else:
                handler.send(502, b"bad gateway")
        elif handler.path.endswith("/master_password/unlock"):
            handler.send(unlock_status, unlock_body)
        else:
            handler.send(200, {"valid": True, "key_derivation": FAKE_KEY})

    with _fake_server(respond) as (api, requests):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api},
        )

    assert result.exit_code == 1
    paths = [path.removeprefix("/api") for _, path, _ in requests]
    assert "/master_password/check" not in paths
    assert "Traceback" not in result.output


def test_cli_keeps_credentials_in_the_url_for_a_proxy() -> None:
    def respond(handler: _Recorder) -> None:
        if not _answer_unlock(handler, "sessions"):
            handler.send(200, [])

    with _fake_server(respond) as (api, requests):
        proxied = api.replace("http://", "http://moth:proxy-pass@")
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": proxied},
        )

    assert result.exit_code == 0, result.output
    listing = next(h for _, path, h in requests if path.endswith("/passwords"))
    assert _lower(listing)["authorization"].startswith("Basic ")
    assert _lower(listing)["x-ciphermoth-session"] == TOKEN


@pytest.mark.parametrize("expires_again", [False, True])
def test_cli_unlocks_again_once_when_its_session_ends_mid_command(
    expires_again: bool,
) -> None:
    listings = 0

    def respond(handler: _Recorder) -> None:
        nonlocal listings
        if _answer_unlock(handler, "sessions"):
            return
        listings += 1
        if listings == 1 or expires_again:
            handler.send(
                401,
                {"detail": "Your session expired.", "code": "invalid_session"},
            )
        else:
            handler.send(200, [])

    with _fake_server(respond) as (api, requests):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api},
        )

    paths = [path.removeprefix("/api") for _, path, _ in requests]
    assert paths.count("/master_password/unlock") == 2
    assert paths.count("/passwords") == 2
    assert paths[-1] == "/master_password/lock"
    if expires_again:
        assert result.exit_code == 1
        assert "Your session expired." in result.output
    else:
        assert result.exit_code == 0, result.output


async def test_cli_ends_its_sessions_on_the_live_server(
    api: str, live_server_log: Path
) -> None:
    log_start = live_server_log.stat().st_size
    ok(cli(api, "password", "list"))
    result = cli(api, "password", "get", "does-not-exist")
    assert result.exit_code == 1

    log = live_server_log.read_bytes()[log_start:].decode(errors="replace")
    assert log.count("POST /api/master_password/unlock") == 2
    assert log.count("POST /api/master_password/lock") == 2
    assert "/master_password/check" not in log


def _old_cli() -> typer.Typer:
    path = Path(__file__).resolve().parents[2] / "testdata/clients/cli_v1_4_7.py"
    spec = importlib.util.spec_from_file_location("ciphermoth_cli_v1_4_7", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def old_cli(api: str, *args: str, answers: list[str] | None = None) -> Result:
    lines = [MASTER_PASSWORD, *(answers or [])]
    return runner.invoke(
        _old_cli(),
        list(args),
        input="\n".join(lines) + "\n",
        env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
    )


async def test_the_v147_cli_is_told_to_update_and_changes_nothing(
    api: str, tmp_path: Path, live_server_log: Path
) -> None:
    ok(cli(api, "password", "create", "kept", answers=["kept-Pass-1"] * 2 + [""] * 5))
    before = await db_snapshot()
    log_start = live_server_log.stat().st_size
    for args, answers in (
        (["password", "list"], []),
        (["password", "get", "kept"], []),
        (
            ["password", "create", "from-old-cli"],
            ["old-cli-Pass-1", "old-cli-Pass-1", "moth", "", "", "", ""],
        ),
        (["password", "delete", "kept", "--yes"], []),
        (["backup", "--out", str(tmp_path)], []),
    ):
        result = old_cli(api, *args, answers=answers)
        assert result.exit_code == 1, args
        assert "no longer hands out or accepts the vault key" in result.output
        assert "CLI to 1.5.0 or newer" in result.output
        assert "Traceback" not in result.output
        assert "kept-Pass-1" not in result.output
    assert await db_snapshot() == before
    assert list(tmp_path.iterdir()) == []
    log = live_server_log.read_bytes()[log_start:].decode(errors="replace")
    assert log.count("POST /api/master_password/check") == 5
    assert "/api/passwords" not in log
    assert "kept-Pass-1" in ok(cli(api, "password", "get", "kept"))


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (
            403,
            {
                "detail": "Invalid or expired vault key. [Unlock] again.",
                "code": "invalid_key",
            },
            "[Unlock] again",
        ),
        (400, {"error": "legacy [error] shape"}, "legacy [error] shape"),
        (500, b"plain [text] failure", "plain [text] failure"),
        (429, {"detail": "Too many attempts."}, "CIPHERMOTH_RATE_LIMIT"),
    ],
)
def test_cli_reports_server_errors_readably(
    status: int, payload: object, expected: str
) -> None:
    def respond(handler: _Recorder) -> None:
        handler.send(status, payload, **{"content-type": "application/json"})

    with _fake_server(respond) as (api, _):
        result = runner.invoke(
            cli_app,
            ["password", "list"],
            input=MASTER_PASSWORD + "\n",
            env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
        )

    assert result.exit_code == 1
    assert expected in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("url", "warned"),
    [
        ("http://vault.example.invalid:9/api", True),
        ("https://vault.example.invalid:9/api", False),
        ("http://localhost:9/api", False),
        ("http://127.0.0.1:9/api", False),
    ],
)
def test_cli_warns_before_sending_the_master_password_over_plain_http(
    url: str, warned: bool
) -> None:
    result = runner.invoke(
        cli_app,
        ["password", "list"],
        input=MASTER_PASSWORD + "\n",
        env={"CIPHERMOTH_API_URL": url},
    )
    assert result.exit_code == 1
    assert ("plain HTTP" in result.output) is warned
    assert "Cannot reach the API" in result.output or "Traceback" not in result.output


CIP = Path(__file__).resolve().parents[2] / "scripts" / "cip"


def _cip(
    tmp_path: Path, *args: str, running: bool = True
) -> tuple[int, str, list[str]]:
    home = tmp_path / "install"
    bin_dir = tmp_path / "bin"
    home.mkdir(exist_ok=True)
    bin_dir.mkdir(exist_ok=True)
    (home / "docker-compose.prod.yml").write_text("services: {}\n")
    shutil.copy(CIP, home / "cip")
    calls = tmp_path / "calls"
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$4" = "ps" ]; then '
        + ("echo backend; " if running else "")
        + "exit 0; fi\n"
        f'for arg in "$@"; do printf "%s\\0" "$arg" >> "{calls}"; done\n'
    )
    docker.chmod(0o755)
    link = tmp_path / "cip-link"
    if not link.exists():
        link.symlink_to(home / "cip")
    result = subprocess.run(
        ["sh", str(link), *args],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        timeout=30,
    )
    recorded = calls.read_bytes().split(b"\0")[:-1] if calls.exists() else []
    return result.returncode, result.stderr, [a.decode() for a in recorded]


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_cip_passes_arguments_through_verbatim(tmp_path: Path) -> None:
    hostile = ["password", "get", "name with spaces; rm -rf / $(id) `id` \"q\" 'q' *"]

    code, stderr, calls = _cip(tmp_path, *hostile)

    assert code == 0, stderr
    compose = str((tmp_path / "install" / "docker-compose.prod.yml").resolve())
    assert (
        calls[-len(hostile) - 7 :]
        == [
            "compose",
            "-f",
            compose,
            "exec",
            "backend",
            "ciphermoth",
            *hostile,
        ][-len(hostile) - 7 :]
    )


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_cip_refuses_when_the_backend_is_not_running(tmp_path: Path) -> None:
    code, stderr, calls = _cip(tmp_path, "password", "list", running=False)
    assert code == 1
    assert "isn't running" in stderr
    assert calls == []


async def test_cli_reports_records_that_were_not_imported(api: str) -> None:
    export = Path(__file__).resolve().parents[2] / "testdata" / "csv" / "bitwarden.csv"

    output = ok(cli(api, "import-csv", str(export)))

    assert "3 added" in output
    assert "1 record(s) were not imported" in output
    assert "row 5 (Visa ending 4242): 'card' items can't be imported" in output


async def test_cli_reports_renamed_records(api: str, tmp_path: Path) -> None:
    export = tmp_path / "dupes.csv"
    export.write_text("name,password\nsite,a\nsite,b\n")
    output = ok(cli(api, "import-csv", str(export)))
    assert "2 added" in output
    assert "1 record(s) were imported under a new name" in output
    assert "row 3 (site): imported as 'site (2)'" in output


def test_cli_names_the_entry_on_every_entry_request() -> None:
    def respond(handler: _Recorder) -> None:
        if _answer_unlock(handler, "sessions"):
            return
        if handler.command == "GET":
            handler.send(200, {"password_name": "x/purge", "password_value": "v"})
        else:
            handler.send(200, {})

    with _fake_server(respond) as (api, requests):
        for command in (["get"], ["delete", "--yes"], ["restore"], ["purge", "--yes"]):
            result = runner.invoke(
                cli_app,
                ["password", command[0], "x/purge", *command[1:]],
                input=MASTER_PASSWORD + "\n",
                env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
            )
            assert result.exit_code == 0, result.output

    entry_requests = [r for r in requests if "/passwords/x%2Fpurge" in r[1]]
    assert len(entry_requests) == 5
    for _, _, headers in entry_requests:
        assert headers.get("x-ciphermoth-entry") == "x%2Fpurge"


def _register_soft_key(api: str, session: dict[str, str]) -> SoftKey:
    soft = SoftKey()
    options = httpx.post(f"{api}/security/keys/options", headers=session).json()
    resp = httpx.post(
        f"{api}/security/keys",
        json={
            "name": "CLI key",
            "confirmation": {"master_password": MASTER_PASSWORD},
            "registration": soft.register(options["challenge"]),
            "assertion": soft.answer(options["secret_challenge"], options["prf_salt"]),
        },
        headers=session,
    )
    assert resp.status_code == 200, resp.text
    return soft


@pytest.fixture
def plugged_in(monkeypatch: pytest.MonkeyPatch):
    """Stand in for the USB key: the CLI's CTAP client answers with a SoftKey."""
    import security_key_client

    touches: list[str] = []
    keys: list = []

    def answer(
        challenge: dict, on_touch=lambda: None, get_pin=lambda: None, event=None
    ) -> dict:
        on_touch()
        soft = keys[0]
        descriptor = next(k for k in challenge["keys"] if k["credential_id"] == soft.id)
        touches.append(challenge["challenge"])
        return soft.answer(challenge["challenge"], descriptor["prf_salt"])

    monkeypatch.setattr(security_key_client, "answer", answer)
    return keys, touches


async def test_cli_unlocks_and_backs_up_with_a_security_key(
    api: str, key: dict[str, str], tmp_path: Path, plugged_in
) -> None:
    keys, touches = plugged_in
    _api_create(api, key, {"password_name": "mail", "password_value": "mail-Pass-1"})
    keys.append(_register_soft_key(api, key))

    output = ok(cli(api, "password", "get", "mail"))
    assert "mail-Pass-1" in output
    assert "Touch your security key" in output
    assert len(touches) == 1

    ok(cli(api, "backup", "--out", str(tmp_path)))
    assert len(touches) == 3  # unlock, then the backup's own confirmation
    [archive] = list(tmp_path.glob("ciphermoth_backup_*.cmbackup"))
    assert archive.read_bytes().startswith(b"CMBACKUP")


async def test_cli_recover_resets_the_master_password(
    api: str, key: dict[str, str], plugged_in
) -> None:
    keys, _ = plugged_in
    _api_create(api, key, {"password_name": "mail", "password_value": "mail-Pass-1"})
    resp = httpx.post(
        f"{api}/security/recovery-code",
        json={"master_password": MASTER_PASSWORD},
        headers=key,
    )
    code = resp.json()["recovery_code"]
    keys.append(_register_soft_key(api, key))

    new_password = "Cli-Recovered-Vault-2029!"
    result = runner.invoke(
        cli_app,
        ["recover"],
        input=f"{code}\n{new_password}\n{new_password}\nn\n",
        env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
    )
    output = ok(result)
    assert code not in output
    [new_code] = re.findall(r"(?:[0-9A-Z]{4}-){7}[0-9A-Z]{4}", output)
    assert new_code != code

    # The key still works with the new password.
    result = runner.invoke(
        cli_app,
        ["password", "get", "mail"],
        input=f"{new_password}\n",
        env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"},
    )
    assert "mail-Pass-1" in ok(result)


async def test_cli_recover_without_a_code_explains(api: str) -> None:
    result = runner.invoke(
        cli_app, ["recover"], env={"CIPHERMOTH_API_URL": api, "COLUMNS": "200"}
    )
    assert result.exit_code == 1
    assert "no recovery code" in result.output
