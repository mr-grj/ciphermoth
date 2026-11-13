import binascii
import contextlib
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import quote

import httpx
import typer
from rich.console import Console
from rich.markup import escape as _markup_escape
from rich.table import Table

from helpers import generate_totp
from url_parse import split_url

app = typer.Typer(
    name="ciphermoth",
    help="Manage your self-hosted ciphermoth vault from the terminal.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
pw_app = typer.Typer(
    help="List, reveal, add, edit and delete vault entries.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(pw_app, name="password")

_out = Console()
_err = Console(stderr=True)

_LABEL_WIDTH = 13
_KINDS = ("login", "note")
_CONFLICTS = ("skip", "overwrite")
_TRANSFER_TIMEOUT = 600
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
_SESSION_HEADER = "x-ciphermoth-session"
_SESSIONS = "vault-sessions"
_SLASH_NAMES = "entry-names-with-slash"
_BULK = "bulk-entry-actions"
_BULK_MOVE = "bulk-entry-move"
_SECURITY_KEYS = "security-keys"
_RECOVERY = "recovery-code"
_EXTENSION = "browser-extension"
_SERVER_TOO_OLD = (
    "This server runs a CipherMoth release older than 1.5.0, which this CLI no "
    "longer supports. Update the server, or use CipherMoth CLI 1.5.x."
)
_NO_UNLOCK_ROUTE = (
    "No CipherMoth unlock route at {url!r}. Check that CIPHERMOTH_API_URL ends "
    "in /api. A server older than 1.5.0 also answers like this: update it, or "
    "use CipherMoth CLI 1.5.x."
)


_TERMINAL_CONTROL = re.compile(r"[\x1b\x80-\x9f]")


def _safe_markup(value: str) -> str:
    # Rich's markup escaping alone passes terminal controls through to a pipe.
    visible = _TERMINAL_CONTROL.sub(lambda match: f"\\x{ord(match[0]):02x}", value)
    return _markup_escape(visible)


def _api_url() -> str:
    return os.environ.get("CIPHERMOTH_API_URL", "http://localhost:8000/api").rstrip("/")


def _display_api_url() -> str:
    # Proxy credentials and URL metadata must not be copied into diagnostics.
    address = _api_url()
    try:
        parts = split_url(address)
    except ValueError:
        return "<configured API>"
    if "@" not in parts.netloc and not parts.query and not parts.fragment:
        return address
    authority = parts.netloc.rsplit("@", 1)[-1]
    return f"{parts.scheme}://{authority}{parts.path}"


def _die(msg: str) -> NoReturn:
    _err.print(f"[red]✗[/red]  {_safe_markup(msg)}")
    raise typer.Exit(1)


def _ok(msg: str) -> None:
    _out.print(f"[green]✓[/green]  {msg}")


def _check(resp: httpx.Response) -> None:
    if resp.is_success:
        return

    try:
        payload = resp.json()
        detail = payload.get("detail") or payload.get("error") or resp.text
    except ValueError:
        detail = resp.text

    if resp.status_code == 429:
        _die(
            f"{detail} Every command unlocks the vault once, so a batch of them "
            f"can hit this. Raise CIPHERMOTH_RATE_LIMIT on the backend to lift it."
        )

    _die(str(detail))


def _warn_plaintext_transport() -> None:
    parsed = split_url(_api_url())
    host = parsed.hostname or ""
    if parsed.scheme == "https" or host in _LOCAL_HOSTS:
        return

    _err.print(
        f"[yellow]![/yellow]  {_safe_markup(host)} is reached over plain HTTP, so your "
        f"master password crosses the network unencrypted. Put the API behind HTTPS."
    )


def _features(client: httpx.Client) -> list[str] | None:
    try:
        resp = client.get("/meta")
    except httpx.ConnectError:
        _die(f"Cannot reach the API at {_display_api_url()!r}. Is the service running?")
    except httpx.HTTPError:
        return None
    if not resp.is_success:
        return None
    try:
        features = resp.json().get("features", [])
    except (ValueError, AttributeError):
        return None
    if not isinstance(features, list):
        return None
    return [feature for feature in features if isinstance(feature, str)]


def _touch_prompt() -> None:
    _err.print("[cyan]›[/cyan]  Touch your security key…")


def _security_key_pin() -> str:
    return typer.prompt("Security key PIN", hide_input=True)


def _security_key_answer(challenge: dict) -> dict:
    """Ask a plugged-in registered security key to answer ``challenge`` over USB.
    A mistyped PIN is asked again: the key, not this CLI, counts the attempts."""
    from security_key_client import SecurityKeyError, SecurityKeyPinInvalid, answer

    for attempt in range(3):
        try:
            return answer(challenge, on_touch=_touch_prompt, get_pin=_security_key_pin)
        except SecurityKeyPinInvalid as error:
            if attempt == 2:
                _die(str(error))
            _err.print(f"[red]✗[/red]  {_safe_markup(str(error))}")
        except SecurityKeyError as error:
            _die(str(error))
    _die("The security key could not be used.")


class _Vault:
    """
    One unlocked vault for the length of a command: a vault session that is
    locked again when the command ends.
    """

    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        features = _features(client)
        self.meta_known = features is not None
        self.features = features or []
        self.master = ""
        self._auth: dict[str, str] = {}

    def unlock(self) -> None:
        self.master = typer.prompt("Master password", hide_input=True)
        self._authenticate()

    def _post_password(self, path: str) -> httpx.Response:
        body: dict[str, Any] = {"master_password": self.master}
        try:
            if self._security_key_required():
                resp = self.client.post("/master_password/unlock/challenge")
                _check(resp)
                body["security_key"] = _security_key_answer(resp.json())
            return self.client.post(path, json=body)
        except httpx.ConnectError:
            _die(
                f"Cannot reach the API at {_display_api_url()!r}. "
                "Is the service running?"
            )

    def _security_key_required(self) -> bool:
        if _SECURITY_KEYS not in self.features:
            return False
        resp = self.client.get("/master_password/status")
        _check(resp)
        return bool(resp.json().get("security_key_required"))

    def confirmation(self) -> dict[str, Any]:
        """The master password again, with the security key's answer when the
        vault requires one, for a change the server asks to confirm."""
        body: dict[str, Any] = {"master_password": self.master}
        if self._security_key_required():
            resp = self.send("POST", "/security/challenge")
            _check(resp)
            body["security_key"] = _security_key_answer(resp.json())
        return body

    def _has_no_unlock_route(self, resp: httpx.Response) -> bool:
        if _SESSIONS in self.features or resp.status_code not in (404, 405):
            return False
        try:
            detail = resp.json().get("detail")
        except (ValueError, AttributeError):
            return False
        return detail in ("Not Found", "Method Not Allowed")

    def _authenticate(self) -> None:
        resp = self._post_password("/master_password/unlock")
        if self._has_no_unlock_route(resp):
            if self.meta_known:
                _die(_SERVER_TOO_OLD)
            _die(_NO_UNLOCK_ROUTE.format(url=_display_api_url()))

        _check(resp)
        data = resp.json()
        if not data.get("valid"):
            _die("Invalid master password.")

        self._auth = {_SESSION_HEADER: data["session_token"]}

    def headers(self, name: str | None = None) -> dict[str, str]:
        headers = dict(self._auth)
        if name is not None:
            headers["x-ciphermoth-entry"] = quote(name, safe="")
        return headers

    def send(
        self, method: str, url: str, *, name: str | None = None, **kwargs: Any
    ) -> httpx.Response:
        resp = self.client.request(method, url, headers=self.headers(name), **kwargs)
        if resp.status_code == 401 and self._auth:
            self._authenticate()
            resp = self.client.request(
                method, url, headers=self.headers(name), **kwargs
            )
        return resp

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[httpx.Response]:
        for attempt in range(2):
            with self.client.stream(
                method, url, headers=self.headers(), **kwargs
            ) as resp:
                if resp.status_code == 401 and self._auth and attempt == 0:
                    resp.read()
                else:
                    if not resp.is_success:
                        resp.read()
                    yield resp
                    return
            self._authenticate()

    def entry_path(self, name: str, suffix: str = "") -> str:
        if "/" in name and _SLASH_NAMES not in self.features:
            _die(
                "This server can't address entry names containing '/'. "
                "Update CipherMoth, or rename the entry in the web UI."
            )
        encoded = quote(name, safe="")
        if encoded in (".", ".."):
            encoded = encoded.replace(".", "%2E")
        return f"/passwords/{encoded}{suffix}"

    def lock(self) -> None:
        if self._auth:
            with contextlib.suppress(httpx.HTTPError):
                self.client.post("/master_password/lock", headers=self._auth)
        self._auth = {}
        self.master = ""


@contextmanager
def _vault(timeout: float = 30) -> Iterator[_Vault]:
    _warn_plaintext_transport()
    with httpx.Client(
        base_url=_api_url(), timeout=timeout, follow_redirects=False
    ) as client:
        vault = _Vault(client)
        try:
            vault.unlock()
            yield vault
        finally:
            vault.lock()


def _entry(resp: httpx.Response, name: str) -> dict:
    _check(resp)
    item = resp.json()
    if not isinstance(item, dict):
        _die(
            f"'{name}' can't be opened by name. Rename the entry in the web UI "
            "to manage it from the CLI."
        )
    return item


def _optional(label: str, current: str | None = None) -> str | None:
    return (
        typer.prompt(label, default=current or "", show_default=bool(current)) or None
    )


def _prompt_secret(label: str) -> str:
    return typer.prompt(label, hide_input=True, confirmation_prompt=True)


def _prompt_optional_secret(label: str) -> str | None:
    value = typer.prompt(label, hide_input=True, default="", show_default=False)
    if not value:
        return None

    if typer.prompt("Repeat for confirmation", hide_input=True) != value:
        _die("The two entries did not match.")

    return value


def _totp_code(secret: str) -> str:
    try:
        return generate_totp(secret)
    except (binascii.Error, ValueError):
        return "unreadable 2FA secret"


def _detail_rows(item: dict) -> list[tuple[str, str]]:
    rows = [("Note" if item.get("kind") == "note" else "Value", item["password_value"])]

    for label, key in (("Username", "username"), ("URL", "url")):
        if item.get(key):
            rows.append((label, item[key]))

    if item.get("totp_secret"):
        rows.append(("2FA code", _totp_code(item["totp_secret"])))

    if item.get("folder"):
        rows.append(("Folder", item["folder"]))

    if item.get("tags"):
        rows.append(("Tags", ", ".join(item["tags"])))

    for field in item.get("custom_fields") or []:
        shown = "••••••••" if field.get("hidden") else field.get("value", "")
        rows.append((field["label"], shown))

    if item.get("description"):
        rows.append(("Description", item["description"]))

    return rows


def _print_details(item: dict) -> None:
    rows = _detail_rows(item)
    width = max([_LABEL_WIDTH, *(len(label) + 2 for label, _ in rows)])

    _out.print(f"\n  [bold cyan]{_safe_markup(item['password_name'])}[/bold cyan]")

    for label, value in rows:
        head, *rest = str(value).split("\n")
        padding = " " * (width - len(label))
        _out.print(f"  [dim]{_safe_markup(label)}[/dim]{padding}{_safe_markup(head)}")
        for line in rest:
            _out.print(f"  {' ' * width}{_safe_markup(line)}")

    _out.print()


@pw_app.command("list", help="List every entry in the vault.")
def pw_list() -> None:
    with _vault() as vault:
        resp = vault.send("GET", "/passwords")

    _check(resp)

    items: list[dict] = resp.json()
    if not items:
        _out.print("[dim]The vault is empty.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="dim")

    for item in items:
        table.add_row(
            _safe_markup(item["password_name"]),
            _safe_markup(item.get("description") or "-"),
        )

    _out.print(table)


@pw_app.command("get", help="Reveal one entry, including its live 2FA code.")
def pw_get(name: Annotated[str, typer.Argument(help="Entry name.")]) -> None:
    with _vault() as vault:
        resp = vault.send("GET", vault.entry_path(name), name=name)

    _print_details(_entry(resp, name))


@pw_app.command(
    "create", help="Add a login or a secure note, prompting for each field."
)
def pw_create(
    name: Annotated[str, typer.Argument(help="Name for the new entry.")],
    kind: Annotated[
        str, typer.Option("--kind", "-k", help="Entry type: login or note.")
    ] = "login",
) -> None:
    if kind not in _KINDS:
        _die("--kind must be 'login' or 'note'.")

    is_note = kind == "note"

    with _vault() as vault:
        existing = vault.send("GET", vault.entry_path(name), name=name)
        if existing.is_success and isinstance(existing.json(), dict):
            _die(f"An entry named '{name}' already exists.")

        value = _prompt_secret("Note body" if is_note else "Password value")
        username = None if is_note else _optional("Username / email")
        url = None if is_note else _optional("URL")
        totp_secret = None if is_note else _optional("TOTP secret")
        description = _optional("Description")
        folder = _optional("Folder")
        resp = vault.send(
            "POST",
            "/passwords/create",
            name=name,
            json={
                "password_name": name,
                "kind": kind,
                "username": username,
                "password_value": value,
                "url": url,
                "totp_secret": totp_secret,
                "description": description,
                "folder": folder,
            },
        )

    _check(resp)

    _ok(f"Created [cyan]{_safe_markup(name)}[/cyan]")


@pw_app.command(
    "update",
    help="Edit an entry. Leave a prompt blank to keep the current value.",
)
def pw_update(name: Annotated[str, typer.Argument(help="Entry name.")]) -> None:
    with _vault() as vault:
        current = _entry(vault.send("GET", vault.entry_path(name), name=name), name)
        is_note = current.get("kind") == "note"

        secret_label = "New note" if is_note else "New password value"
        new_value = (
            _prompt_optional_secret(f"{secret_label} (blank to keep the current one)")
            or current["password_value"]
        )
        new_username = (
            None if is_note else _optional("Username / email", current.get("username"))
        )
        new_url = None if is_note else _optional("URL", current.get("url"))
        new_totp = (
            None if is_note else _optional("TOTP secret", current.get("totp_secret"))
        )
        new_description = _optional("Description", current.get("description"))
        new_folder = _optional("Folder", current.get("folder"))

        shared = {
            "password_name": name,
            "kind": current.get("kind", "login"),
            "tags": current.get("tags", []),
            "custom_fields": current.get("custom_fields", []),
            "favorite": current.get("favorite", False),
        }
        resp = vault.send(
            "PATCH",
            "/passwords/update",
            name=name,
            json={
                "password": {
                    **shared,
                    "username": current.get("username"),
                    "password_value": current["password_value"],
                    "url": current.get("url"),
                    "totp_secret": current.get("totp_secret"),
                    "description": current.get("description"),
                    "folder": current.get("folder"),
                },
                "new_password": {
                    **shared,
                    "username": new_username,
                    "password_value": new_value,
                    "url": new_url,
                    "totp_secret": new_totp,
                    "description": new_description,
                    "folder": new_folder,
                },
            },
        )

    _check(resp)

    _ok(f"Updated [cyan]{_safe_markup(name)}[/cyan]")


@pw_app.command(
    "delete",
    help=(
        "Move one or more entries to the trash. They can be restored later. "
        "Several names move together or, if one is missing, not at all."
    ),
)
def pw_delete(
    names: Annotated[list[str], typer.Argument(help="Entry names.")],
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip confirmation.")
    ] = False,
) -> None:
    names = list(dict.fromkeys(names))
    if len(names) == 1:
        _delete_one(names[0], yes)
        return

    with _vault() as vault:
        if _BULK not in vault.features:
            _die("Deleting several entries at once needs CipherMoth 3.3.0 or newer.")
        if not yes:
            _out.print("\n".join(f"  {_safe_markup(name)}" for name in names))
            typer.confirm(f"Move these {len(names)} entries to trash?", abort=True)
        resp = vault.send(
            "POST",
            "/vault/entries/trash",
            json={"entries": [{"password_name": name} for name in names]},
        )

    _check(resp)

    _ok(f"Moved {len(names)} entries to trash")


@pw_app.command(
    "move",
    help=(
        "Move one or more entries into a folder, or out of their folder with "
        "--no-folder. Several names move together or, if one is missing, not at all."
    ),
)
def pw_move(
    names: Annotated[list[str], typer.Argument(help="Entry names.")],
    folder: Annotated[
        str | None,
        typer.Option("--folder", "-f", help="Folder to move the entries into."),
    ] = None,
    no_folder: Annotated[
        bool,
        typer.Option("--no-folder", help="Take the entries out of their folder."),
    ] = False,
) -> None:
    if (folder is None) == (not no_folder):
        _die("Give either --folder NAME or --no-folder.")
    if folder is not None:
        folder = folder.strip()
        if not folder:
            _die("Folder name can't be empty. Use --no-folder to remove the folder.")
    names = list(dict.fromkeys(names))

    with _vault() as vault:
        if _BULK_MOVE not in vault.features:
            _die("Moving entries to a folder needs CipherMoth 3.5.0 or newer.")
        resp = vault.send(
            "POST",
            "/vault/entries/move",
            json={
                "entries": [{"password_name": name} for name in names],
                "folder": folder,
            },
        )

    _check(resp)

    result = resp.json()
    count = result.get("count", 0)
    moved = (
        f"Moved {_count(count)} to [cyan]{_safe_markup(folder)}[/cyan]"
        if folder is not None
        else f"Took {_count(count)} out of their folder"
    )
    unchanged = result.get("unchanged", 0)
    if unchanged:
        moved += f" ({_count(unchanged)} already there)"
    _ok(moved)


def _count(count: int) -> str:
    return f"{count} {'entry' if count == 1 else 'entries'}"


def _delete_one(name: str, yes: bool) -> None:
    with _vault() as vault:
        exists = vault.send("GET", vault.entry_path(name), name=name)
        if exists.status_code == 404:
            _check(exists)

        if not yes:
            typer.confirm(f"Move '{name}' to trash?", abort=True)

        resp = vault.send("DELETE", vault.entry_path(name), name=name)

    _check(resp)

    _ok(f"Moved [cyan]{_safe_markup(name)}[/cyan] to trash")


@pw_app.command(
    "history",
    help="Reveal an entry's earlier passwords, newest first (the last 10 are kept).",
)
def pw_history(name: Annotated[str, typer.Argument(help="Entry name.")]) -> None:
    with _vault() as vault:
        item = _entry(vault.send("GET", vault.entry_path(name), name=name), name)

    history = item.get("password_history") or []
    if not history:
        _out.print(f"[dim]No earlier passwords for {_safe_markup(name)}.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("In use until", style="dim", no_wrap=True)
    table.add_column("Password")
    for entry in history:
        table.add_row(
            _safe_markup(_local_time(entry.get("changed_at"))),
            _safe_markup(str(entry.get("value", ""))),
        )
    _out.print(f"\n  [bold cyan]{_safe_markup(name)}[/bold cyan]")
    _out.print(table)


def _local_time(value: object) -> str:
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone().strftime("%Y-%m-%d %H:%M")


@pw_app.command("trash", help="List the entries waiting in the trash.")
def pw_trash() -> None:
    with _vault() as vault:
        resp = vault.send("GET", "/passwords/trash")

    _check(resp)

    items: list[dict] = resp.json()
    if not items:
        _out.print("[dim]The trash is empty.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="dim")
    table.add_column("Deleted", style="dim")

    for item in items:
        table.add_row(
            str(item.get("id", "-")),
            _safe_markup(item["password_name"]),
            _safe_markup(item.get("description") or "-"),
            (item.get("deleted") or "-")[:19].replace("T", " "),
        )

    _out.print(table)


@pw_app.command(
    "restore",
    help="Restore the newest trashed entry of this name, or select one with --id.",
)
def pw_restore(
    name: Annotated[str, typer.Argument(help="Entry name.")],
    entry_id: Annotated[
        int | None, typer.Option("--id", min=1, help="Row ID from 'password trash'.")
    ] = None,
) -> None:
    with _vault() as vault:
        params = _trash_params(vault, name, entry_id)
        resp = vault.send(
            "POST", vault.entry_path(name, "/restore"), name=name, params=params
        )

    _check(resp)

    _ok(f"Restored [cyan]{_safe_markup(name)}[/cyan]")


@pw_app.command(
    "purge",
    help=(
        "Permanently delete the newest trashed entry of this name, or select one "
        "with --id. This cannot be undone."
    ),
)
def pw_purge(
    name: Annotated[str, typer.Argument(help="Entry name.")],
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip confirmation.")
    ] = False,
    entry_id: Annotated[
        int | None, typer.Option("--id", min=1, help="Row ID from 'password trash'.")
    ] = None,
) -> None:
    if not yes:
        selected = f" (row #{entry_id})" if entry_id is not None else " (newest)"
        typer.confirm(f"Permanently delete '{name}'{selected} from trash?", abort=True)

    with _vault() as vault:
        params = _trash_params(vault, name, entry_id)
        resp = vault.send(
            "DELETE", vault.entry_path(name, "/purge"), name=name, params=params
        )

    _check(resp)

    _ok(f"Permanently deleted [cyan]{_safe_markup(name)}[/cyan]")


def _trash_params(vault: _Vault, name: str, entry_id: int | None) -> dict[str, int]:
    if entry_id is None:
        return {}
    response = vault.send("GET", "/passwords/trash")
    _check(response)
    # Older servers ignore an unknown query parameter; refuse before sending a
    # mutation unless this server supplies selectable row IDs in its Trash list.
    if not any(
        row.get("id") == entry_id and row.get("password_name") == name
        for row in response.json()
    ):
        _die(
            "No matching Trash row ID. Refresh 'password trash' and use this "
            "release's server."
        )
    return {"entry_id": entry_id}


@app.command(
    "backup",
    help=(
        "Save a complete encrypted backup (.cmbackup): every entry, the trash, "
        "history, attachments and settings, protected by your master password."
    ),
)
def cmd_backup(
    out_dir: Annotated[
        Path, typer.Option("--out", "-o", help="Directory to save the backup file.")
    ] = Path("."),
) -> None:
    staged: Path | None = None
    try:
        with _vault(timeout=_TRANSFER_TIMEOUT) as vault:
            with vault.stream(
                "POST", "/passwords/backup", json=vault.confirmation()
            ) as resp:
                _check(resp)
                out_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
                with tempfile.NamedTemporaryFile(
                    prefix=f"ciphermoth_backup_{stamp}_",
                    suffix=".cmbackup.partial",
                    dir=out_dir,
                    delete=False,
                ) as output:
                    staged = Path(output.name)
                    for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                dest = staged.with_suffix("")
                # Publish only a completed transfer; never replace an existing
                # backup (or follow a pre-existing destination symlink).
                os.link(staged, dest)
    except (httpx.HTTPError, OSError):
        _die("Backup could not be saved. Check the connection and destination space.")
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)

    _ok(f"Backup saved to [cyan]{_safe_markup(str(dest))}[/cyan]")


@app.command(
    "recover",
    help=(
        "Forgot the master password? Set a new one with your recovery code. The "
        "code is used up: a new one is shown, save it."
    ),
)
def cmd_recover() -> None:
    _warn_plaintext_transport()
    with httpx.Client(
        base_url=_api_url(), timeout=60, follow_redirects=False
    ) as client:
        features = _features(client) or []
        if _RECOVERY not in features:
            _die("This server has no recovery codes. Update CipherMoth.")
        status = client.get("/master_password/status")
        _check(status)
        if not status.json().get("recovery_code"):
            _die(
                "This vault has no recovery code, so a forgotten master password "
                "cannot be reset."
            )
        code = typer.prompt("Recovery code", hide_input=True)
        new_password = typer.prompt(
            "New master password", hide_input=True, confirmation_prompt=True
        )
        keep = True
        if status.json().get("security_key_required"):
            keep = not typer.confirm(
                "Did you lose your security keys? (Yes removes them; the vault then "
                "opens with the new master password alone)",
                default=False,
            )
        resp = client.post(
            "/master_password/recover",
            json={
                "recovery_code": code,
                "new_master_password": new_password,
                "keep_security_keys": keep,
            },
        )
        _check(resp)
        data = resp.json()
        with contextlib.suppress(httpx.HTTPError):
            client.post(
                "/master_password/lock",
                headers={_SESSION_HEADER: data["session_token"]},
            )
    _ok("Master password reset. Every other session was logged out.")
    _out.print(
        "\n  Your new recovery code (the old one no longer works):\n\n"
        f"    [bold]{_safe_markup(data['recovery_code'])}[/bold]\n\n"
        "  Write it down and keep it offline. Anyone holding it can open the vault."
    )


@app.command(
    "damaged",
    help=(
        "List entries and attachments the vault file holds but cannot read (damaged "
        "or altered), and optionally remove them. Backups and master password "
        "changes refuse to run while any remain."
    ),
)
def cmd_damaged(
    remove: Annotated[
        bool, typer.Option("--remove", help="Remove every damaged row.")
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip confirmation.")
    ] = False,
) -> None:
    with _vault() as vault:
        resp = vault.send("GET", "/vault/damaged")
        _check(resp)
        rows = [
            (kind, row_id)
            for kind in ("entries", "attachments")
            for row_id in resp.json()[kind]
        ]
        if not rows:
            _ok("Nothing is damaged.")
            return
        for kind, row_id in rows:
            label = "entry" if kind == "entries" else "attachment"
            _err.print(f"[yellow]![/yellow]  {label} #{row_id} cannot be read")
        if not remove:
            _out.print(
                "Restore a snapshot (docs/UPDATING.md), or run "
                "'ciphermoth damaged --remove'. Removing an entry also removes its "
                "attachments."
            )
            return
        if not yes:
            typer.confirm(f"Permanently remove {len(rows)} damaged row(s)?", abort=True)
        for kind, row_id in rows:
            _check(vault.send("DELETE", f"/vault/damaged/{kind}/{row_id}"))
    _ok(f"Removed {len(rows)} damaged row(s)")


@app.command(
    "browsers",
    help=(
        "List the browsers whose CipherMoth extension is connected to this vault, "
        "and optionally disconnect one."
    ),
)
def cmd_browsers(
    disconnect: Annotated[
        str | None,
        typer.Option("--disconnect", help="ID of the browser to disconnect."),
    ] = None,
) -> None:
    with _vault() as vault:
        if _EXTENSION not in vault.features:
            _die("This server has no browser extension support. Update CipherMoth.")
        if disconnect is not None:
            _check(
                vault.send(
                    "DELETE", f"/extension/sessions/{quote(disconnect, safe='')}"
                )
            )
            _ok("Disconnected. That browser's extension is locked.")
            return
        resp = vault.send("GET", "/extension/sessions")
    _check(resp)

    sessions: list[dict] = resp.json()
    if not sessions:
        _out.print("[dim]No browser is connected.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("ID", style="dim")
    table.add_column("Browser", style="cyan")
    table.add_column("Connected", style="dim")
    table.add_column("Last used", style="dim")
    for item in sessions:
        table.add_row(
            _safe_markup(str(item.get("id", "-"))),
            _safe_markup(str(item.get("browser", "-"))),
            _safe_markup(_local_time(item.get("created"))),
            _safe_markup(_local_time(item.get("last_used"))),
        )
    _out.print(table)


def _report_import(payload: dict) -> None:
    _ok(
        f"Import complete - "
        f"[cyan]{payload['imported']}[/cyan] added, "
        f"[cyan]{payload['overwritten']}[/cyan] overwritten, "
        f"[cyan]{payload['skipped']}[/cyan] skipped"
    )
    restored = [
        f"{payload[key]} {label}"
        for key, label in (
            ("trashed", "in the trash"),
            ("attachments", "attachment(s)"),
        )
        if payload.get(key)
    ]
    if payload.get("settings_restored"):
        restored.append("settings")
    if restored:
        _ok("Also restored: " + ", ".join(restored))

    for key, title in (
        ("renamed", "were imported under a new name"),
        ("ignored", "were not imported"),
    ):
        count = payload.get(key, 0)
        if not count:
            continue
        _err.print(f"[yellow]![/yellow]  {count} record(s) {title}:")
        rows = payload.get(f"{key}_rows", [])
        for row in rows:
            name = f" ({row['name']})" if row.get("name") else ""
            _err.print(
                f"   {_safe_markup(row['where'] + name)}: {_safe_markup(row['reason'])}"
            )
        if count > len(rows):
            _err.print(f"   and {count - len(rows)} more")


def _validate_import_file(file: Path, on_conflict: str) -> None:
    if not file.is_file():
        _die(f"File not found: {file}")

    if on_conflict not in _CONFLICTS:
        _die("--on-conflict must be 'skip' or 'overwrite'.")


@app.command(
    "import",
    help=(
        "Restore a CipherMoth backup: a complete backup (.cmbackup) or a backup "
        "ZIP from CipherMoth 2.0 or earlier."
    ),
)
def cmd_import(
    file: Annotated[
        Path, typer.Argument(help="Path to the backup (.cmbackup or legacy .zip).")
    ],
    on_conflict: Annotated[
        str,
        typer.Option(
            help=(
                "How to handle existing entries: skip or overwrite. A complete "
                "backup moves each entry it overwrites to the trash."
            ),
        ),
    ] = "skip",
) -> None:
    _validate_import_file(file, on_conflict)

    with _vault(timeout=_TRANSFER_TIMEOUT) as vault, file.open("rb") as upload:
        backup_password = typer.prompt(
            "Backup password (Enter if it is the current master password)",
            hide_input=True,
            default="",
            show_default=False,
        )
        resp = vault.send(
            "POST",
            "/passwords/import",
            data={
                "master_password": backup_password or vault.master,
                "on_conflict": on_conflict,
            },
            files={"file": (file.name, upload, "application/octet-stream")},
        )

    _check(resp)

    _report_import(resp.json())


@app.command(
    "import-csv",
    help="Import a CSV exported from Chrome, Bitwarden, KeePass or Proton Pass.",
)
def cmd_import_csv(
    file: Annotated[
        Path, typer.Argument(help="Path to a CSV exported from another manager.")
    ],
    on_conflict: Annotated[
        str,
        typer.Option(
            help="How to handle existing entries: skip or overwrite.",
        ),
    ] = "skip",
) -> None:
    _validate_import_file(file, on_conflict)

    with _vault(timeout=60) as vault, file.open("rb") as upload:
        resp = vault.send(
            "POST",
            "/passwords/import/csv",
            data={"on_conflict": on_conflict},
            files={"file": (file.name, upload, "text/csv")},
        )

    _check(resp)

    _report_import(resp.json())


if __name__ == "__main__":
    app()
