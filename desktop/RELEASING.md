# Maintaining a CipherMoth release

This is a maintainer guide. Never put a private signing key, password, test vault or credential in this repository or a workflow artifact.

## Trust and recovery

The production updater key is embedded in `src-tauri/tauri.conf.json`. Its minisign key ID is **1BF84A7870A3622C**. Preserve this key across releases: installed applications cannot learn a replacement key from an unsigned manifest. Apple/Microsoft publisher signing is unrelated.

The original key is stored in the maintainer's owner-only `~/.config/ciphermoth/release-signing/updater.key`; a second local copy is in `~/.local/share/ciphermoth-release-signing-backup/updater.key`. Both locations are outside Git. Keep the enclosing directories mode `0700` and private files `0600`. The key is not password-protected; filesystem access controls protect these copies. Back up the directory to encrypted offline storage that you control. Two locations on the same computer do not protect against losing that computer. Keep the matching `.pub` with the backup.

GitHub environment **desktop-release** holds `TAURI_SIGNING_PRIVATE_KEY`; no password secret is needed for this key. The workflow passes an empty `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` and writes the key only into its private runner-temporary directory. PR builds generate disposable keys, never receive the production key and never publish installers. Environment branch/tag policies restrict production signing; stable version tags cannot be updated or deleted. Do not grant forks or arbitrary branches access to this environment.

To recover on an owner-controlled machine, restore the key directory with restrictive permissions, compare the public key to the committed configuration, then upload without printing it:

```sh
gh secret set TAURI_SIGNING_PRIVATE_KEY --env desktop-release \
  --repo mr-grj/ciphermoth < ~/.config/ciphermoth/release-signing/updater.key
```

Verify continuity by signing a disposable file using `tauri signer sign --app-version X.Y.Z` and checking it with the `verify_update` example and committed public key. Do not rotate just because a new runner or computer is used. If a key is compromised, stop publication and assess recovery for installed users before changing trust.

## Build and publication

Use the existing maintainer Git identity, normal commits, and no bot co-author trailers. Merge tested implementation work to `master`. The desktop workflow reuses six native runners (macOS ARM/Intel, Windows ARM/x64, Linux ARM/x64), Python 3.13.15 and the committed dependency lockfiles. It runs the frozen core vectors/tests, native QA workflows, production package collection and installed-app updater acceptance. No synthetic vaults or QA installers are uploaded as public assets.

1. Update the changelog and run `PATH="$HOME/.cargo/bin:$PATH" python3 desktop/release/version.py X.Y.Z`. Review and commit the version change; `--check X.Y.Z` checks every version source without changing files.
2. Pass PR CI and the desktop matrix on the final source. Release CI exercises the protected production signing key and retains verified packages before publication. A missing production secret must fail, never fall back to a test key. If key provisioning needs a separate check, Desktop can also be dispatched on trusted `master` with `release=true`.
3. Create an annotated `vX.Y.Z` tag on the verified commit and push it once. `scripts/release.sh` validates this sequence; it does not publish an unchecked release.
4. The single Release workflow builds/signs the existing multi-architecture GHCR images and invokes the Desktop workflow. Published Docker smoke checks verify cosign identities/digests and exercise isolated Compose installs.
5. `artifacts.py` collects actual bundle output, assigns canonical names `CipherMoth_VERSION_OS-ARCH.EXT`, signs updater artifacts with the official CLI and verifies the signature, trusted filename and signed version. Production package provenance records the commit, version, target, byte sizes and hashes. Tauri `createUpdaterArtifacts` produces macOS `.app.tar.gz`, Windows NSIS `.exe` and Linux AppImage update bundles; DMGs and Debian packages remain regular downloads.
6. `manifest.py` refuses missing/duplicate targets, wrong commits/versions, missing packages or invalid signatures. It builds `latest.json` from the six actual signatures and generates `SHA256SUMS`. The endpoint is permanently `https://github.com/mr-grj/ciphermoth/releases/latest/download/latest.json`.
7. Only after all gates pass, `publish.py` creates one draft, uploads the complete set, downloads it again and checks every hash, then publishes it as a normal stable Latest release. Existing releases are never silently overwritten. If a failed upload leaves a draft, inspect the draft and failure before resuming; do not replace the tag.
8. Verify the public release and downloads without authentication, the Latest manifest, and a released app's no-update result. Keep the CI run and commit in the release validation report. Do not call the release complete while a platform or Docker gate is failing.

### The browser extension

The extension (`extension/`) is versioned with everything else: `version.py` also updates `extension/package.json`, its lockfile and `extension/manifest/base.json`, and `--check` covers them. Before tagging, run the manual checklist in `extension/VALIDATION.md` on the CI-built packages of the release commit (the `extension` job of a dispatched Release run, or `npm run package` on the exact commit, which is byte-identical).

The Release workflow's `extension` job (environment **extension-release**) checks the version, runs the type check, lint and unit tests, builds the packages (`chromium` to load unpacked, `chromium-store` for the Chrome Web Store, `firefox`), rebuilds them to prove the build reproducible (`scripts/verify.mjs`), runs `web-ext lint`, and attests build provenance. It does not sign anything with addons.mozilla.org: **never add `AMO_JWT_ISSUER`/`AMO_JWT_SECRET` to that environment.** AMO accepts each version number once across its listed and unlisted channels, so a CI signature would block the listed upload (design decision 64: 3.9.0 was signed unlisted that way and could never be listed). The publish job appends the extension files to `SHA256SUMS` after `manifest.py`, so they are uploaded, downloaded again and hash-checked with the rest.

After every published release, the maintainer submits the release's packages to the stores (never a local build; check each against the release's `SHA256SUMS` first). Every publisher account uses hardware-key 2FA. Store listings: Chrome Web Store item `gjdobbdnepjkgfpcmhjdagkcjholjkkd` (https://chromewebstore.google.com/detail/ciphermoth/gjdobbdnepjkgfpcmhjdagkcjholjkkd), AMO add-on `ciphermoth@mr-grj.github.io` (https://addons.mozilla.org/firefox/addon/ciphermoth/); the web app links to both (`STORE_LINKS` in `frontend/src/lib/extensionHandoff.js`).

- **Chrome Web Store** (Chrome, Brave, Edge, Vivaldi, Opera): Developer Dashboard → the item → **Package** → **Upload new package** → `ciphermoth-extension-chromium-store-X.Y.Z.zip` (the build without the manifest `key`, which the store refuses), then **Submit for review**. A new package cannot be uploaded while the previous one is still in review. Listing texts and permission justifications: `extension/store/chrome-web-store.md`; a new permission needs a justification there first.
- **addons.mozilla.org** (Firefox): **Upload a New Version** → "On this site" → `ciphermoth-extension-firefox-X.Y.Z.zip`, Firefox only, plus the source archive from `git archive` of the tag and the notes for reviewers. Exact steps and texts: `extension/store/firefox-amo.md`.
- Other stores (Edge Add-ons, Opera add-ons) are not used; an id one of them assigns goes into `CHROMIUM_IDS`.

Keep the Chrome extension signing key (which pins the extension ID through the manifest `key`, which desktop mode's native host trusts) offline.

**The Chromium id is the Chrome Web Store item's** (design decision 62): `gjdobbdnepjkgfpcmhjdagkcjholjkkd`, pinned by the public `key` in `extension/manifest/chromium.json`. The maintainer generated the pair (since 3.9.0); the private key lives only in the maintainer's own vault, never in the repo, CI or a release. It was made with:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
openssl pkey -in key.pem -pubout -outform DER | base64 | tr -d '\n'        # the manifest "key"
openssl pkey -in key.pem -pubout -outform DER | shasum -a 256 | head -c 32 | tr '0-9a-f' 'a-p'   # the id
```

`CHROMIUM_IDS` (`desktop/src-tauri/extension-link/src/ids.rs`) lists the store id first (`cargo test` and the extension's manifest test compute it from the key and fail until both agree), then ids that are only still accepted: the throwaway id of 3.6.0-3.8.x (decision 34), so copies loaded unpacked keep their pairing; drop it in a later major release. Ids assigned by other stores (Edge Add-ons, Opera) go into `CHROMIUM_IDS` too. Removing an id unpairs every browser using it.

Only the **first** Chrome Web Store upload carries the private key, as `key.pem` at the root of the `chromium-store` zip, so the store assigns the item our id; later uploads are that release asset unchanged. Add it to a copy outside the repo and delete the copy after the upload. The store refuses a manifest with `key` ("key field is not allowed in manifest", decision 63), which is why the store package exists.

### The native host

Every package ships `ciphermoth-native-host` next to the app executable (`bundle.externalBin`). `desktop/build-native-host.mjs` builds it for the runner's target before the app (`beforeBuildCommand`; `--qa` for the QA build, whose host has its own identity and never reaches a production app; `--debug` for `tauri dev`). A release build of the app refuses to compile without the real host (`build.rs`); debug builds get a stand-in that exits 3. `production.py` checks the installed host is there, has the right architecture, refuses a caller it does not trust and finds no production app on the runner; `native.py` drives the QA app's own host through pairing and a fill (`harness/extension.py`).

`requireSignedVersion` is mandatory. Do not disable TLS, allow downgrades, expose generic updater plugin capabilities, or sign arbitrary external payloads. Canonical filenames are part of the signature's trusted comment and bind architecture; re-sign after renaming, never edit a `.sig` by hand.

## Installed update tests

`build_update_fixtures.py` temporarily builds versions 3.0.98 and 3.0.99 of the separate QA application, then restores source files. It packages the same production core and updater implementation with an isolated QA identity. `harness/update.py` installs the old app and serves the signed newer package over local HTTPS using an ephemeral CA trusted only in that QA process. Production contains neither this endpoint override nor QA commands.

The host drives the native webview, creates a synthetic vault, quits/reopens it, tests negative manifests/downloads, installs through the real Tauri updater, and verifies the new version, original password, content/attachment fingerprints, encrypted backups and process cleanup. AppImage is tested separately from the Debian installation. This proves native updater mechanics; it does not simulate Gatekeeper internet quarantine, SmartScreen reputation or an organization's endpoint policy. Record actual OS limitations honestly. Never disable system protections for a passing result.

Use fresh absolute disposable roots. The normal application has no override for its vault directory. Do not test with a personal vault, installed Alpha app or real Docker volume. CI retains only selected JSON/XML evidence, never the full synthetic-data tree or signing directory.
