# CipherMoth desktop

A Tauri 2 window around the existing React UI and **the production v3 Python vault core**. Normal vault operations run offline. No Docker, terminal, database server, or backend TCP listener is needed to use the packaged app.

Installers and signed updater artifacts are built on six native GitHub runners. See [installation and updates](../docs/UPDATING.md#desktop-updates) and [release maintenance](RELEASING.md). Apple Developer ID/notarization and Windows Authenticode signing are not used.

## Launch on macOS

Build with `make desktop-build`, then open `desktop/src-tauri/target/release/bundle/macos/CipherMoth.app` in Finder. You may copy the complete `.app` to Applications. Do not copy its executable alone. The first screen creates a master password; subsequent launches unlock the persisted vault. Use **Log out**, or **Command/Ctrl+Shift+L**, to lock. Closing the window or quitting terminates the core.

macOS bundles are ad-hoc signed, not notarized, and Gatekeeper can reject an internet download. No library-validation bypass entitlement is added. Tauri updater signatures authorize updates independently of OS publisher signing.

## Data isolation

Application identity: `com.ciphermoth.desktop` (distinct from Alpha, the spike, server, and QA app). Tauri resolves the OS application-local directory:

- macOS: `~/Library/Application Support/com.ciphermoth.desktop/data/vault.db`.
- Windows: the user's Local AppData directory under that identity.
- Linux: `$XDG_DATA_HOME/com.ciphermoth.desktop/data/vault.db`, normally `~/.local/share/...`.

Debug builds use a separate `development/` subdirectory. QA builds require an explicit absolute synthetic-data root and use `com.ciphermoth.desktop.qa`. Release builds ignore environment overrides for the core executable and vault path. Reinstalling the bundle leaves data untouched. Never delete the data directory to fix a startup failure.

The production storage layer creates POSIX directories `0700` and files `0600`, takes the existing single-process vault lock, checks an existing file read-only before opening it, and uses SQLite WAL, FULL synchronous writes, and the production schema/format identity. Unsupported or damaged vaults are refused, not migrated or replaced. Windows uses the current user's application-local directory and inherited OS ACLs; the installer does not grant other users access.

## Development

Prerequisites: uv, Node 22+, Rust 1.99 (rustup), and native Tauri build prerequisites. On macOS, install Xcode Command Line Tools. On Linux, see the package list in `.github/workflows/desktop.yml`.

```sh
make desktop-setup
make desktop-dev
make desktop-test
make desktop-check
make check
```

`desktop-dev` runs Vite and the source Python core from the dedicated venv. Python edits require restarting the app, **not rebuilding PyInstaller**. Frontend edits hot reload. Debug Python and script paths are fixed relative to the checkout; the production binary selects only the bundled executable.

```sh
TAURI_SIGNING_PRIVATE_KEY=/path/to/owner-only/updater.key make desktop-build
```

This freezes Python 3.13.15 as PyInstaller **onedir**, then builds the real app. `requirements-desktop.lock` locks the dedicated runtime without uvicorn, PostgreSQL, CLI or Docker dependencies. `greenlet`, `aiosqlite`, and cryptography are explicit. The frozen runtime reports its actual SQLite version during the ready handshake; the production storage layer rejects an unpatched version. Local macOS builds use SQLite 3.53.1.

## Boundaries

- `backend/`: unchanged crypto, vault documents, backup format, SQL transactions, validation and endpoint behavior. One small app-factory fix preserves an explicitly injected empty session store.
- `desktop/core/desktop_core/`: framed pipe server and in-process ASGI adapter. It runs the actual app lifespan. Diagnostics use stderr; stdout is reserved using duplicated descriptors. Header/body lengths are checked before allocation (64 KiB / 24 MiB). Requests, queues and concurrent operations are bounded. Cancellation acknowledges even a task cancelled before it starts.
- `desktop/src-tauri/`: supervisor, capabilities, native dialogs, clipboard and OS lock events. The ready handshake checks both protocol and core version. At most three crash restarts per minute; startup failures show a retry screen. Windows Job Objects fail closed, Linux uses parent-death signals, and macOS uses pipe EOF plus parent monitoring.
- `frontend/src/platform/`: the only platform switch. Axios uses normal HTTP for web builds and binary native IPC for desktop. Desktop sessions stay in memory. No vault key enters Rust or React. Native file paths never enter React; selected backups use expiring, single-use opaque grants.

Manual/idle/native lock destroys the core process and all in-flight key derivations, clears owned clipboard content, invalidates file grants and pending saves, and returns to the locked UI. SQLite rolls back unfinished transactions. A native window hide/navigation removes the old decrypted view before renderer events are processed. The native watchdog enforces trusted core expiry and hidden-window policy even when JavaScript timers cannot execute. The Python core separately enforces idle and absolute expiry; desktop permits one session.

Production capabilities allow only the app's narrow commands and event subscription. No filesystem/shell plugin is exposed. CSP forbids remote scripts/connections; navigation and new windows are restricted. Release devtools are disabled. The webview is incognito and password fields disable autocomplete; these are best-effort webview controls, not guarantees against a compromised OS.

## Touch ID

`native/biometric.swift` keeps a Secure Enclave key as a CryptoKit blob, with access control `biometryCurrentSet`. CryptoKit is what makes this possible without Apple signing: the Keychain's biometric access control needs an entitlement an ad-hoc signed app cannot have. Each use first runs `LAContext.evaluatePolicy`, so a dismissed prompt is told apart from a key that no longer works. The resulting 32-byte secret goes through the renderer to the Python core, like a typed master password; the vault key stays in the core. The format is in [VAULT_FORMAT.md](../docs/VAULT_FORMAT.md#3-key-hierarchy) and the trade-offs in [SECURITY.md](../SECURITY.md#biometric-unlock).

Building on macOS needs `swiftc`, which the Xcode Command Line Tools include. Windows and Linux desktop builds report biometric unlock as unavailable.

## Files and backups

Attachment/CSV file inputs use the webview's OS picker. Downloads use a native Save dialog and create a new file with restricted permissions. Existing files are refused instead of silently overwritten. External entry links use a protocol allowlist and the system browser.

Backups use the **existing v3 `.cmbackup` implementation**. Export streams the response to a private encrypted staging file next to the native-selected destination, fsyncs it, then atomically creates the final filename without replacement. Import reads bounded ciphertext chunks through the same production multipart endpoint, preserving auth, validation and transactional rollback. Neither direction sends the whole backup through an IPC frame. Wrong passwords, damage, cancellation, disk errors and a destination creation race must not produce a successful partial export or partially restored records.

An abrupt OS kill can leave a hidden `.ciphermoth-*.partial` file containing ciphertext in the selected export folder. It is never presented as a completed backup and may be removed manually. No plaintext vault staging is used. Exported attachments and CSV source files are plaintext files explicitly chosen by the user.

Atomic backup publication requires a filesystem that supports hard links (for example APFS, NTFS or ext4). Export fails safely on filesystems without this support; choose a local supported folder and then copy the completed encrypted backup elsewhere. A full 1 GiB file has not been exercised locally; the regression test exceeds 25 MiB.

## Native security limits

The clipboard timer runs in Rust while other apps are focused and compares ownership/content before clearing. macOS uses pasteboard change count and the concealed-content history hint; Windows uses its sequence number and monitoring exclusion hint. Linux compares the copied value, and clipboard history/compositor behavior varies. Clipboard managers can ignore hints, and clipboard APIs do not provide a cross-application atomic compare-and-clear guarantee on every OS.

macOS observes workspace sleep, screen sleep and session resignation, plus the undocumented `com.apple.screenIsLocked` notification. Windows registers WTS session and power notifications. Linux listens for logind sleep/session lock and common GNOME/freedesktop screen-saver events; desktops without these services are not guaranteed to notify. A native wall-clock gap check also locks after resume. Linux handlers and Windows handlers require their own native validation; do not infer it from macOS results.

The native window requests content protection. It cannot guarantee capture prevention on Linux/Wayland or against every modern macOS capture API. Python cannot zeroize all key copies, and the renderer necessarily holds displayed plaintext while unlocked. OS compromise, same-user process memory access and malicious clipboard managers remain outside the vault encryption guarantee.

## Native validation

The production core tests can run from source or against a packaged binary:

```sh
CORE_BIN="$PWD/desktop/core/dist/ciphermoth-core/ciphermoth-core" \
  desktop/core/build/venv/bin/python -m pytest desktop/core/tests

desktop/core/dist/ciphermoth-core/ciphermoth-core --check-vectors testdata/vectors
```

The separate `gui-test` Rust feature and `desktop-qa` frontend build run the existing UI inside the real native webview. The QA report command and Cocoa notification injection are **absent from default production builds**. No synthetic core routes are present in either build. Never distribute a QA build.

```sh
cd desktop
npm run tauri build -- --features gui-test --config tauri.qa.json --bundles app
cd ..
desktop/core/build/venv/bin/python desktop/harness/native.py \
  --app "$PWD/desktop/src-tauri/target/release/bundle/macos/CipherMoth QA.app/Contents/MacOS/ciphermoth-desktop" \
  --root /private/tmp/ciphermoth-native-test-UNIQUE
```

Use a new synthetic root. Do not rebuild an app bundle while a test is using it; copying it to a temporary install folder first is preferable. The CI installer adapter does that on macOS. On Linux it installs the `.deb`; Windows installs the NSIS package on its disposable runner. PR builds use disposable signing keys and retain only evidence. Trusted release builds retain verified production packages; the release workflow publishes them only after all desktop and Docker gates pass.

An optional macOS dialog walkthrough is enabled by building QA with `VITE_DESKTOP_DIALOG_QA=1` and running `native.py --dialogs`. It drives the real Save/Open panels and restores through an opaque grant. It requires macOS Accessibility permission for the automation host; local automation was blocked by that permission. The maintainer completed the equivalent manual Save/Open and backup restoration walkthrough. The standard native suite does not require keystroke automation and verifies a large backup through the same Rust file workflow with a fixed QA destination.

## Provenance

Ported from `experiment/desktop-feasibility` at `9d3a4ea`: binary framing, ASGI adapter, stdout isolation, supervisor, platform process cleanup, onedir packaging, native CI matrix and harness structure. Synthetic storage/routes and the spike's production self-test mode were removed. The experimental branch/worktree and its evidence remain unchanged.

See [VALIDATION.md](VALIDATION.md) for measured results and documented acceptance limits.

## Updater boundary

The official Tauri updater runs only in Rust. Renderer capabilities expose `update_check`, `update_install` and `update_cancel`, with no endpoint, key, URL or installer arguments. The compiled configuration fixes the HTTPS GitHub endpoint and public key; there are no general updater plugin permissions. `requireSignedVersion` rejects version substitution, and a verified trusted-comment filename binds the artifact to its native target. Release collection renames artifacts before signing those canonical filenames. The plugin verifies before installation as well as after downloading.

The user confirms installation in the existing Update dialog. Only after verification does Rust invalidate native grants, remove decrypted UI, clear the owned clipboard and stop the core. Windows installs per user; macOS/Linux restart after replacement. Debian users receive manual package instructions. The QA-only HTTPS endpoint and host-controlled test commands are absent from production binaries.
