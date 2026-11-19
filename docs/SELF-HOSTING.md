# Self-hosting CipherMoth

Most people should use the [desktop app](../README.md#download). This guide is for the other edition: the same vault core as a small web app you run with Docker, on your own computer or a server you control. It is two containers (`backend`, `frontend`) and one SQLite file in a Docker volume. No database server, no account, nothing phoning home.

## Install

You need Docker with Compose v2. Then:

```shell
curl -fsSL https://raw.githubusercontent.com/mr-grj/ciphermoth/master/install.sh | sh
```

[`install.sh`](../install.sh) is short and safe to read first. It creates a `ciphermoth` folder, downloads [`docker-compose.prod.yml`](../docker-compose.prod.yml), the [`cip`](#the-command-line) wrapper and a starter `.env`, then pulls the signed release images and starts them. Running it again updates those files and keeps your `.env` (a changed compose file is backed up first). It does not verify the image signatures; [UPDATING.md](UPDATING.md#update) shows how.

Open [http://localhost:3000](http://localhost:3000) and create your master password. The API listens on port 8000 (`/docs` shows its reference).

Without the installer, put `docker-compose.prod.yml` in a folder, optionally copy [`.env.prod.example`](../.env.prod.example) next to it as `.env`, and run:

```shell
docker compose -f docker-compose.prod.yml up -d
```

Coming from CipherMoth 2.0 or a PostgreSQL release (v1.6.0 and older)? Read [the upgrade procedure](UPDATING.md#moving-from-ciphermoth-20-vault-format-1) first. Those vaults are never converted automatically.

## The command line

The installer leaves a `cip` script next to the compose file, so `./cip password list` works with no Python and no clone (`sudo ln -s "$PWD/cip" /usr/local/bin/cip` to use it from anywhere). It runs the `ciphermoth` CLI inside the backend container. Everything it can do is in [CLI.md](CLI.md).

## Configuration

Everything is optional; the defaults work for local use. In Compose, these go in the `.env` next to `docker-compose.prod.yml` ([`.env.prod.example`](../.env.prod.example) explains each one).

| Variable | Default | What it does |
|---|---|---|
| `CIPHERMOTH_VERSION` | `latest` | Which release runs, e.g. `3.9.3` (no leading `v`) |
| `CIPHERMOTH_API_URL` | `http://localhost:8000/api` | The address the *browser* uses to reach the API |
| `CIPHERMOTH_FRONTEND_ORIGIN` | `http://localhost:3000` | The address the browser loads the UI from |
| `CIPHERMOTH_BIND_ADDRESS` | `127.0.0.1` | Set `0.0.0.0` (or one interface) to reach the ports from other machines |
| `CIPHERMOTH_FRONTEND_PORT` / `CIPHERMOTH_BACKEND_PORT` | `3000` / `8000` | Published ports |
| `CIPHERMOTH_RATE_LIMIT` | unset | Overrides every route's own limit, e.g. `200/hour`. Unlocking defaults to `30/hour`, and each CLI command unlocks once, so raise this if a batch of them trips it |

The containers read the variables below. Compose sets `CORS_ORIGINS` and `VITE_API_URL` from the ones above; add any other to the service's `environment` in the compose file.

**Backend:**

| Variable | Default | Description |
|---|---|---|
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed frontend origins |
| `DISABLE_DOCS` | `false` | Set `true` to hide `/docs` and `/redoc` |
| `DEBUG` | `false` | FastAPI debug mode |
| `CIPHERMOTH_DATA_DIR` | `data` (`/data` in the image) | Folder that holds `vault.db` and `snapshots/`, created `0700` |
| `CIPHERMOTH_RATE_LIMIT` | unset | See above |

**Frontend:**

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000/api` | Backend API base URL: an `http(s)` URL, a `//host` URL, or a path such as `/api` when a proxy serves the API on the UI's own origin. The image allows browser connections only to this origin (plus GitHub's release address for the update check). A value with another scheme or with characters that could rewrite the policy or the app is refused: the UI then shows a page explaining what to fix. With an IPv6 address the policy can only restrict the scheme (`http:`/`https:`), so prefer a host name. In Compose it comes from `CIPHERMOTH_API_URL` |

**CLI:**

| Variable | Default | Description |
|---|---|---|
| `CIPHERMOTH_API_URL` | `http://localhost:8000/api` | Backend API base URL (baked to `http://localhost/api` inside the backend image) |
| `CIPHERMOTH_COMPOSE_FILE` | `<cip's folder>/docker-compose.prod.yml` | Compose file the `cip` wrapper drives |

The CLI warns before prompting if `CIPHERMOTH_API_URL` points at a remote host over plain HTTP, since the master password would cross the network unencrypted.

## Putting it on a real server

CipherMoth is built to run on a machine you trust: your home server, a VPS behind a firewall, a Raspberry Pi in your closet. It is not built to sit naked on the open internet. If you're deploying it somewhere reachable:

- Set `CIPHERMOTH_FRONTEND_ORIGIN` and `CIPHERMOTH_API_URL` to your actual domain, and hide the API reference with `DISABLE_DOCS: "true"` in the backend's `environment` (it is not read from `.env`)
- Put everything behind a reverse proxy (nginx, Caddy) with HTTPS, and have it pass request paths through **unchanged** (see below)
- Keep the `vault_data` volume on a local disk: SQLite's write-ahead log needs shared memory on one host, so network file systems and synced folders are not supported
- To keep the vault in a host folder instead of the volume, mount it and point `CIPHERMOTH_DATA_DIR` at it, and give the folder to the backend's user first (`sudo chown -R 1000:1000 <folder>`); otherwise the backend refuses to start and says so. Docker Desktop (macOS, Windows) does not enforce host-folder ownership, so this only bites on Linux

`docker-compose.prod.yml` publishes the UI and API on `127.0.0.1` only. That is what you want when the reverse proxy runs on the same host: the proxy can reach CipherMoth, nothing else on the network can. If other machines need to reach the ports directly (a proxy on another box, a LAN, a VPN such as Tailscale), set `CIPHERMOTH_BIND_ADDRESS=0.0.0.0` in your `.env`, or a specific interface address, and make sure HTTPS sits in front. Installs from before v1.4.6 keep whatever their own copy of the compose file says until it is replaced.

**Pass request paths through unchanged.** Entry names can contain `/`, which clients send as `%2F`. A proxy that decodes `%2F` before forwarding turns a request for the entry `x/purge` into a request to purge the entry `x`. Caddy's `reverse_proxy` (also inside `handle_path`) and nginx's `proxy_pass http://127.0.0.1:8000;` (no path after the address) pass the path unchanged. nginx's `proxy_pass http://127.0.0.1:8000/;` or `.../api/;` (with a path, including any path-prefix setup) decodes it. Since v1.4.7 the web UI and CLI also name the entry in a header, so the API refuses such a rewritten request instead of acting on another entry, but older clients get no such protection and the entries stay unreachable until the proxy is fixed.

**One backend process.** Vault sessions live in the backend's memory. Run exactly one backend process (the image's `uvicorn --workers 1`); with several workers a session opened by one would be unknown to the others. A second backend on the same volume refuses to start (it cannot take the vault folder's lock). The session token travels in the `x-ciphermoth-session` header, which proxies forward by default; don't log it, because it opens the vault until the session ends. `Authorization` is left to the proxy, so Basic auth or a forward-auth login in front of CipherMoth keeps working.

**Rate limits behind a proxy.** The limits are keyed on the client IP, which the app reads from the network connection. Behind a reverse proxy every request looks like it comes from the proxy, so the limits become global instead of per client. If you want per-client rate limiting, configure your proxy to preserve the real client address (and only trust `X-Forwarded-For` from the proxy itself).

**Passkeys and security keys need HTTPS** (or `localhost`), because browsers only offer WebAuthn on secure origins. A security key is registered for one host name, so register it on each name you use. Details in [SECURITY.md](../SECURITY.md#security-keys).

## Staying up to date

CipherMoth notices when a newer release is out and shows an **Update** chip in the app bar. The check runs **in your browser** against GitHub's public API; the server never phones home. Turn it off under **Settings → Check for updates** if you'd rather your instance talk to nobody at all.

Updates are manual. Take a snapshot, then pull and restart:

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin snapshot
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

Verifying image signatures, going back to a previous version, snapshots and restores are all in [UPDATING.md](UPDATING.md#docker-edition).
