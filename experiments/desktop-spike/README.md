# Desktop feasibility spike

Throwaway experiment for the desktop plan (PoCs H.1, H.2 and H.4): a Tauri 2 shell that runs the existing Python backend as a PyInstaller onedir sidecar and talks to it only over private stdin/stdout pipes. Nothing here is used by the Docker app, the CLI or the release workflows, and nothing here touches a real vault: the spike keeps its own synthetic SQLite file in a spike-only app data folder (`com.ciphermoth.desktop-spike`), or in a temporary folder when the harness runs it.

## Layout

| Path | What |
|---|---|
| `core/core_main.py`, `core/spike_core/` | The sidecar. `server.py` speaks the frame protocol, `asgi_bridge.py` routes each frame into the real `backend/main.py` FastAPI app in process, `spike_app.py` adds synthetic routes (vault create/unlock, encrypted attachments in aiosqlite, echo, sleep, crash hooks), `vectors.py` runs `testdata/vectors` inside the frozen binary, `hardening.py` keeps stdout private and disables core dumps |
| `core/core.spec`, `core/build_core.py` | PyInstaller onedir build from the backend's locked runtime dependencies plus `requirements-spike.txt` |
| `core/build_openssl.sh` | Checksum-verified static OpenSSL for targets where `cryptography` has no wheel (macOS x86_64) |
| `core/tests/` | Protocol tests that run against the source or the frozen core (`CORE_BIN=...`) |
| `app/` | Vite + React 19 + MUI 9 window and the Tauri 2 shell (`src-tauri/src/sidecar.rs` supervisor, `commands.rs` capability-scoped bridge, `job.rs` Windows job object) |
| `harness/lifecycle.py` | Launches the packaged app and checks the core at OS level: quit, window close, SIGKILL/TerminateProcess, SIGTERM/WM_CLOSE, core crash, startup failures, sockets, memory, canary scan |
| `harness/spike_ci.py` | The same build, test and measurement stages on every OS, used by `.github/workflows/desktop-spike.yml` |
| `harness/linux_docker.sh` | The Linux pipeline in a local Ubuntu 22.04 container |
| `harness/summarize.py` | Tables from result folders |

## Protocol (version 1)

Every frame is `"CM" | version u8 | kind u8 | request id u32 | header length u32 | body length u32 | header JSON | body`, big endian. Kinds: 1 request, 2 response, 3 cancel, 4 ready, 5 error, 6 shutdown. Headers are capped at 64 KiB and bodies at 24 MiB on both sides, and both sides check the lengths before allocating. An oversized or unknown frame is answered with an error for its id and its bytes are discarded in 64 KiB chunks, so the stream stays in sync; a bad magic or version is fatal. The core writes the protocol to a duplicated stdout descriptor and points file descriptor 1 at stderr, so a stray `print` cannot corrupt it. The core exits when stdin closes.

## Running it

```sh
cd experiments/desktop-spike/core
python3 build_core.py --python 3.13.15
CORE_BIN=$PWD/dist/ciphermoth-core/ciphermoth-core build/venv/bin/python -m pytest -q
./dist/ciphermoth-core/ciphermoth-core --check-vectors ../../../testdata/vectors

cd ../app && npm ci && npx tauri build --bundles app
cd .. && core/build/venv/bin/python harness/lifecycle.py \
  --app "app/src-tauri/target/release/bundle/macos/CipherMoth Spike.app/Contents/MacOS/ciphermoth-desktop-spike" \
  --out results/local/lifecycle.json
```

The whole pipeline on one machine: `uv run --no-project --python 3.13.15 harness/spike_ci.py --target <name> --bundles <tauri bundles> --out <dir> --install-root <dir>`.

## Selftest mode

When `CIPHERMOTH_SPIKE_SCENARIO` is set (`ipc`, `idle`, `quit`, `close`), the shell adds a second capability at runtime that lets the page report timings and, for `ipc`, run the IPC checks in the real webview and write the result to `CIPHERMOTH_SPIKE_REPORT`. `CIPHERMOTH_SPIKE_TEST_HOOKS=1` enables the crash routes in the core. A production build must ship neither: building the shell with `--no-default-features` turns the selftest mode off, and the core's test hooks and the shell's pass-through of the spike environment variables have to be removed.
