# Contributing & running it your way

This doc is for people who want to **hack on CipherMoth** or **self-host it their own way**, on a real server, behind a proxy, with custom ports. If you just want to run it on your machine, the [README quick start](./README.md#get-started) is all you need; come back here when you want more.

## Desktop development

For the native application, see [desktop/README.md](desktop/README.md). [desktop/RELEASING.md](desktop/RELEASING.md) covers reproducible release builds, updater signing and recovery. The sections below cover the shared core and Docker edition.

## Development

Clone the repo, then start the dev stack. It builds from your working tree and hot-reloads, and it's a throwaway sandbox with its own vault, completely separate from any real vault.

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

## Configuration

Everything is optional, the defaults work fine for local use.

**Backend:**

| Variable | Default | Description |
|---|---|---|
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed frontend origins |
| `DISABLE_DOCS` | `false` | Set `true` to hide `/docs` and `/redoc` |
| `DEBUG` | `false` | FastAPI debug mode |
| `CIPHERMOTH_DATA_DIR` | `data` (`/data` in the image) | Folder that holds `vault.db` and `snapshots/`, created `0700` |
| `CIPHERMOTH_RATE_LIMIT` | unset | Overrides every route's own limit (e.g. `200/hour`). Unlocking defaults to `30/hour`; each CLI command unlocks once, so raise this if a batch of them trips it |

**Frontend:**

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000/api` | Backend API base URL: an `http(s)` URL, a `//host` URL, or a path such as `/api` when a proxy serves the API on the UI's own origin. The image allows browser connections only to this origin (plus GitHub's release address for the update check). A value with another scheme or with characters that could rewrite the policy or the app is refused: the UI then shows a page explaining what to fix. With an IPv6 address the policy can only restrict the scheme (`http:`/`https:`), so prefer a host name. In Compose it comes from `CIPHERMOTH_API_URL` |

**CLI:**

| Variable | Default | Description |
|---|---|---|
| `CIPHERMOTH_API_URL` | `http://localhost:8000/api` | Backend API base URL (baked to `http://localhost/api` inside the backend image) |
| `CIPHERMOTH_COMPOSE_FILE` | `<cip's folder>/docker-compose.prod.yml` | Compose file the `cip` wrapper drives |

The CLI warns before prompting if `CIPHERMOTH_API_URL` points at a remote host over plain HTTP, since the master password would cross the network unencrypted. See [docs/CLI.md](./docs/CLI.md).

## Putting it on a real server

CipherMoth is built to run on a machine you trust, your home server, a VPS behind a firewall, a Raspberry Pi in your closet, not to sit naked on the open internet. If you're deploying it somewhere reachable:

- Set `CIPHERMOTH_FRONTEND_ORIGIN` / `CORS_ORIGINS` to your actual domain and enable `DISABLE_DOCS=true`
- Put everything behind a reverse proxy (nginx, Caddy) with HTTPS, and have it pass request paths through **unchanged** (see below)
- Keep the `vault_data` volume on a local disk: SQLite's write-ahead log needs shared memory on one host, so network file systems and synced folders are not supported
- To keep the vault in a host folder instead of the volume, mount it and point `CIPHERMOTH_DATA_DIR` at it, and give the folder to the backend's user first (`sudo chown -R 1000:1000 <folder>`); otherwise the backend refuses to start and says so. Docker Desktop (macOS, Windows) does not enforce host-folder ownership, so this only bites on Linux

`docker-compose.prod.yml` publishes the UI and API on `127.0.0.1` only. That is what you want when the reverse proxy runs on the same host: the proxy can reach CipherMoth, nothing else on the network can. If other machines need to reach the ports directly (a proxy on another box, a LAN, a VPN such as Tailscale), set `CIPHERMOTH_BIND_ADDRESS=0.0.0.0` in your `.env`, or a specific interface address, and make sure HTTPS sits in front. Installs from before v1.4.6 keep whatever their own copy of the compose file says until it is replaced.

**Pass request paths through unchanged.** Entry names can contain `/`, which clients send as `%2F`. A proxy that decodes `%2F` before forwarding turns a request for the entry `x/purge` into a request to purge the entry `x`. Caddy's `reverse_proxy` (also inside `handle_path`) and nginx's `proxy_pass http://127.0.0.1:8000;` (no path after the address) pass the path unchanged. nginx's `proxy_pass http://127.0.0.1:8000/;` or `.../api/;` (with a path, including any path-prefix setup) decodes it. Since v1.4.7 the web UI and CLI also name the entry in a header, so the API refuses such a rewritten request instead of acting on another entry, but older clients get no such protection and the entries stay unreachable until the proxy is fixed.

Vault sessions live in the backend's memory. Run exactly one backend process (the image's `uvicorn --workers 1`); with several workers a session opened by one would be unknown to the others. A second backend on the same volume refuses to start (it cannot take the vault folder's lock). The session token travels in the `x-ciphermoth-session` header, which proxies forward by default; don't log it, because it opens the vault until the session ends. `Authorization` is left to the proxy, so Basic auth or a forward-auth login in front of CipherMoth keeps working.

One thing to know about rate limiting behind a proxy: the limits are keyed on the client IP, which the app reads from the network connection. Behind a reverse proxy every request looks like it comes from the proxy, so the limits become global instead of per client. If you want per-client rate limiting, configure your proxy to preserve the real client address (and only trust `X-Forwarded-For` from the proxy itself).

## Staying up to date

CipherMoth notices when a newer release is out and shows an **Update** chip in the app bar. The check runs **in your browser** against GitHub's public API, the server never phones home, and you can turn it off under Settings, "Check for updates", if you'd rather your instance talk to nobody at all.

**Updating:** take a snapshot, then pull and restart:

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin snapshot
docker compose -f docker-compose.prod.yml pull && \
docker compose -f docker-compose.prod.yml up -d
```

`CIPHERMOTH_VERSION` in your `.env` (or `latest`) decides which release runs. Docker updates remain manual. The desktop edition uses the signed Tauri update flow described in [docs/UPDATING.md](docs/UPDATING.md#desktop-updates).

Details, snapshots, restores and moving from a PostgreSQL release: [docs/UPDATING.md](docs/UPDATING.md).
