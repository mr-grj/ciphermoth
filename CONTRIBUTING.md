# Contributing to CipherMoth

Thanks for wanting to help. CipherMoth is a one-person project, so issues, ideas, docs fixes and pull requests are all genuinely welcome. If you want to run CipherMoth on a server rather than hack on it, you want the [self-hosting guide](docs/SELF-HOSTING.md) instead.

**Security problems go to a [private advisory](https://github.com/mr-grj/ciphermoth/security/advisories/new), never a public issue.** See [SECURITY.md](SECURITY.md).

## Find your way around

| Folder | What lives there | Stack |
|---|---|---|
| [`backend/`](backend) | The vault core: crypto, storage, sessions, the HTTP API and the `ciphermoth` CLI | Python 3.13, FastAPI, SQLAlchemy 2.0, SQLite 3.53, uv |
| [`frontend/`](frontend) | The UI shared by the desktop app and the web app | React 19, Vite, MUI, easy-peasy |
| [`desktop/`](desktop) | The native app around the UI and a bundled Python core | Tauri 2, Rust, PyInstaller |
| [`extension/`](extension) | The browser extension | Manifest V3, TypeScript, Preact, esbuild, Playwright |
| [`docker/`](docker) | Release images and their smoke tests | Docker, Compose v2 |
| [`testdata/`](testdata) | Frozen test vectors and vaults shared by every implementation | |
| [`docs/`](docs) | User guides and the [vault format specification](docs/VAULT_FORMAT.md) | |

A few rules keep the code reviewable: all cryptography lives in `backend/helpers.py`; business logic lives in `backend/crud/`, never in the HTTP handlers; and the CLI is a second front end, so a feature that changes the API usually needs a matching change in `backend/cli.py` and [docs/CLI.md](docs/CLI.md).

Each part has its own development guide:

- **Desktop app:** [desktop/README.md](desktop/README.md) (`make desktop-setup`, then `make desktop-dev`). [desktop/RELEASING.md](desktop/RELEASING.md) covers release builds and updater signing.
- **Browser extension:** [docs/EXTENSION.md](docs/EXTENSION.md#development).
- **Web app and server:** below.

## Prerequisites

[uv](https://docs.astral.sh/uv/) for the backend (`uv sync --group dev` inside `backend/`), Node.js with npm for the frontend (`npm install` inside `frontend/`), and Docker for the dev stack. The desktop app also needs Rust; its guide lists the rest.

## The web app and server

Start the dev stack. It builds from your working tree and hot-reloads, and it's a throwaway sandbox with its own vault, completely separate from any real vault.

```shell
make dev     # build + start with hot-reload
```

**Open [http://localhost:3000](http://localhost:3000)** (UI) and `http://localhost:8000` (API); the API explorer is at `/docs` on the API port. The backend restarts on any `.py` change and the React dev server picks up frontend changes instantly.

### Dev sandbox vs the real vault

| | Development (local) | Real vault |
|---|---|---|
| Start it with | `make dev` | `docker compose -f docker-compose.prod.yml up -d` (or `make prod-up`) |
| Source | built from your working tree, hot-reload | prebuilt GHCR images |
| Compose project | `ciphermoth-dev` | `ciphermoth` |
| Vault volume (one SQLite file) | `ciphermoth-dev_vault_data` (disposable) | `ciphermoth_vault_data` (persistent) |
| UI / API | `:3000` / `:8000` | `:3000` / `:8000` (configurable) |
| Badge in app bar | amber **DEV** | calm **LIVE** |

They are separate Compose projects with separate volumes, so the dev sandbox can never see or clobber your real vault. The environment badge is derived from the build itself (Vite dev server vs `vite build`), so there's nothing to configure. If you ever see amber, you're in the sandbox, don't type anything real.

> Both default to port `3000`. That's fine because dev is local and the real vault runs on your server. If you ever run both on one host, remap the prod ports with `CIPHERMOTH_FRONTEND_PORT` / `CIPHERMOTH_BACKEND_PORT`.

All `make` commands run locally, not inside Docker.

| Command | What it does |
|---|---|
| `make dev` | Build and start the dev stack with hot-reload (UI `:3000`, API `:8000`) |
| `make down` | Stop the dev stack, keeping its vault volume |
| `make clean` | Remove the dev stack + its volume, delete `__pycache__` |
| `make all` | `clean` then `dev`, a fresh dev sandbox |
| `make prod-up` | Pull and start the real vault from GHCR images (an optional sibling `.env` holds its settings) |
| `make prod-snapshot` | Write a consistent snapshot of the real vault into its volume |
| `make prod-down` | Stop the real vault, keeping its vault volume |
| `make clean-prod` | Destroy the real vault's volume (guarded, asks to confirm) |
| `make lint` | `ruff check` (backend) + ESLint (frontend) |
| `make typecheck` | `ty check` (backend) |
| `make format` | Auto-format backend (ruff) and frontend (Prettier) |
| `make check` | Lint + type check + format check, no writes, what CI runs |
| `make test` | Backend tests on a throwaway SQLite vault (no Docker needed), then the frontend tests |
| `make test-stress` | Every backend test, including fuzzing with many more examples, random process kills and scale tests |
| `python3 docker/smoke/compose_smoke.py --tag <tag>` | Drives the production images (tagged `ghcr.io/mr-grj/ciphermoth-{backend,frontend}:<tag>`) through a real Compose install in throwaway `cm-*` projects: fresh install, snapshot, restore, refusals, CLI, logs. CI runs it on every image build; after a release, the `Release smoke test` workflow (manual dispatch) runs it and `docker/smoke/published_installer.sh` against the published images on amd64 and arm64 |

`make lint/typecheck/format/check` need [uv](https://docs.astral.sh/uv/) with dev deps (`uv sync --group dev` inside `backend/`) and Node.js with npm deps (`npm install` inside `frontend/`). The backend only runs on SQLite 3.51.3 or newer (older releases have the WAL-reset corruption bug), so `backend/pyproject.toml` tells uv to use its own managed Python builds, which bundle a current SQLite; a system Python with an older SQLite is refused at startup. If an old `backend/.venv` was made with another Python, recreate it: `rm -rf backend/.venv && uv sync --group dev`.

### Before you push

Run `make check` and `make test`. Together they mirror CI: `ruff check` + `ruff format --check` + `ty check` and pytest on the backend, ESLint + Prettier + Vitest on the frontend. Keep them green.

### Tests

`make test` runs the backend suite on a throwaway SQLite vault in a fresh temporary folder (the suite never opens a vault you did not create for it), then the frontend tests. To iterate faster, run pytest directly:

```shell
cd backend
uv run pytest -x
```

What the suite protects, and where:

| Area | Tests |
|---|---|
| Every route rejects missing, forged, expired and locked sessions, and refuses the retired vault key header, alone or next to a valid session | `test_authz.py`, `test_vault_key.py`, `test_adversarial.py` |
| Vault sessions expire, lock, end on rotation and survive races | `test_sessions.py` |
| The CLI refuses servers older than v1.5.0, and the released v1.4.7 CLI is told to update without changing anything | `test_cli.py`, with that CLI frozen in `testdata/clients` |
| The frontend image validates its API URL and renders its CSP | `docker/frontend/runtime-config.test.mjs` (part of `make test`) |
| The CSP lets the UI reach its API and blocks every other destination | `docker/frontend/browser/csp.browser.test.mjs`, run with `make test-browser` (builds the image, drives Chromium) |
| The vault file: initialization, file modes, identity and version checks, SQLite version, the one-process lock, snapshots, restores, corruption, busy handling, reads next to a writer | `test_storage.py` |
| Cryptography is byte-compatible | `test_vectors.py` with [`testdata/vectors`](testdata/vectors/README.md), shared with `frontend/src/lib/totp.test.js` |
| Imports cannot damage a vault | `test_imports.py` (including Hypothesis property tests), `test_hostile_files.py` |
| Failed or interrupted writes change nothing, also when the server is killed right before a commit with megabytes of uncommitted pages in the WAL | `test_failures.py`, `test_process_kill.py` (with `tests/paused_server.py`) |
| The CLI and `scripts/cip` keep their contracts | `test_cli.py` |

Tests authenticate the way clients do: `auth(token)` sends a session token from `create_vault()` or `unlock()`. `stored_vault_key()` derives the key from the database when a test needs the key itself (to check ciphertext, or to prove the API never returns or accepts it), and `retired_key_header(key)` builds the v1.4.x header that must always be refused.

`backend/tests/integrity.py` reads a vault and decrypts every field strictly, reporting what the application's lenient read path would hide. Use it whenever a change touches storage or encryption: `read_vault` before and after, then `assert_same_vault`. To hold SQLite's write lock from a test (a second process mid-write), use `write_lock_held()`; `wait_for_queued_requests(n)` waits until n requests are queued behind it.

Property tests run 25 derandomized examples by default so the suite is fast and reproducible; `make test-stress` (or `HYPOTHESIS_PROFILE=stress`) runs hundreds of random ones. Tests marked `@pytest.mark.stress` only run under `make test-stress`.

### The vault file and schema changes

The vault is one SQLite file (`vault.db` in `CIPHERMOTH_DATA_DIR`, `/data` in the image). `storage.py` owns everything about the file: the connection settings (WAL, `synchronous=FULL`, foreign keys, `secure_delete`, a 15 s busy timeout), creating the schema in an empty file in one transaction, the identity check (`application_id` and `user_version`), snapshots, restores and the folder lock. `crud/engine.py` turns it into SQLAlchemy sessions.

How writes stay correct without row locks: `GET`, `HEAD` and the routes listed in `api/endpoints/deps.py`'s `_READ_ONLY_ROUTES` start deferred transactions and see one consistent snapshot. Other requests start with `BEGIN IMMEDIATE`, holding SQLite's single write lock from their first statement (including the session key check) until they commit. Writers are therefore serialized, and a master password change can never interleave with another write. **A `GET` route must never write.** Key derivation runs outside the write transaction. Security-key assertions, including during unlock, advance their signature counters with a compare-and-set in a separate short write transaction. Session tokens are checked in memory before any database access, so a request without a live session never waits for or holds the write lock. A request that cannot get the lock within the busy timeout gets `503` with `"code": "busy"`.

The file records its schema in `PRAGMA user_version` (`storage.SCHEMA_VERSION`, currently 3). Schema 2 is upgraded at startup after an automatic snapshot; schema 1, newer and unknown schemas are refused without changing the file. Ordered steps in `storage._UPGRADES` run in one write transaction. Each future schema change must include an upgrade step, a raised `SCHEMA_VERSION`, and a test that upgrades a vault written by the previous release.

## Pull requests

- Keep a pull request focused on one change, and say why in its description.
- Run `make check` and `make test` before you push; CI runs the same checks plus the desktop and extension suites.
- Add or update tests with the change. For anything touching storage, crypto or sessions, read the matching section of [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) first and point out in the PR anything that could weaken a guarantee.
- Commit messages follow the style already in the history: `fix: ...`, `feat: ...`, `docs: ...`, `test: ...`, in the imperative.
- User-facing changes get a line in [CHANGELOG.md](CHANGELOG.md), and the README or docs if setup changes.
