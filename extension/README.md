# CipherMoth browser extension

Fills a login from your own CipherMoth (your server, or the desktop app on the same
computer) into the page you are on, only when you ask. User guide:
[docs/EXTENSION.md](../docs/EXTENSION.md). Design and security decisions:
[SECURITY.md](../SECURITY.md).

Install it from the [Chrome Web Store](https://chromewebstore.google.com/detail/ciphermoth/gjdobbdnepjkgfpcmhjdagkcjholjkkd)
(Chrome, Brave, Edge, Vivaldi) or [addons.mozilla.org](https://addons.mozilla.org/firefox/addon/ciphermoth/)
(Firefox).

## Building the packages

The source is TypeScript and Preact, bundled by esbuild into plain IIFE files: no
minification, no source maps, no remote code. The build is reproducible: the same source
and lockfile give byte-identical zips on any machine.

Requirements: Node.js 22 and npm 10 on macOS or Linux. The build also reads
`../frontend/src/lib/brand.js` (it checks the extension's colours against the app's), so
keep the repository layout, or for a source archive the paths `extension/`,
`frontend/src/lib/brand.js` and `LICENSE`.

```sh
cd extension
npm ci                              # exact versions from package-lock.json
node scripts/build.mjs --package    # same as: npm run package
```

This writes:

| Folder | Package in `dist/packages/` | Use |
|---|---|---|
| `dist/chromium/` | `ciphermoth-extension-chromium-X.Y.Z.zip` | Load unpacked; its manifest `key` pins the extension id |
| `dist/store-chromium/` | `ciphermoth-extension-chromium-store-X.Y.Z.zip` | Uploaded to the Chrome Web Store (no `key`, which the store refuses) |
| `dist/firefox/` | `ciphermoth-extension-firefox-X.Y.Z.zip` | Uploaded to addons.mozilla.org |

plus `dist/packages/SHA256SUMS`. To check a release, rebuild its tag and compare with the
release's checksums:

```sh
git checkout vX.Y.Z && cd extension && npm ci
node scripts/verify.mjs path/to/SHA256SUMS
```

## Development

```sh
npm run typecheck && npm run lint && npm test   # types, ESLint, Vitest
npm run lint:firefox                            # web-ext lint, as addons.mozilla.org runs it
npm run test:e2e                                # Playwright (Chromium) against a live backend
```

`npm run test:e2e` needs the backend's Python environment (`uv`) and, for desktop mode,
Rust (`cargo`); `extension/VALIDATION.md` is the manual release checklist and
`extension/store/` holds the store listing texts.
