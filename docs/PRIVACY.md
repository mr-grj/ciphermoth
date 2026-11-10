# Privacy policy

CipherMoth (the server, the desktop app, the command-line client and the browser
extension) is self-hosted, open-source software. **The developer runs no service for it
and receives no data from it.** There is no CipherMoth account, no telemetry, no
analytics and no remote configuration.

## The browser extension

- **What it handles.** When you click its toolbar button or press its shortcut, it reads
  the current tab's origin (scheme, host and port) to find logins saved for that site,
  and fills or copies the login you pick. It reads the page's `<input>` fields only to
  place that login.
- **Where data goes.** Only to the CipherMoth you configured: your own CipherMoth server
  at the address you entered, or the CipherMoth desktop app on the same computer
  (through your browser's native messaging, no network). It sends the page's origin
  to find matches, never its path, query, title or contents. Nothing is sent to the
  developer or to any third party.
- **What it stores.** Its settings (the server address or the choice of the desktop app,
  your matching options and a random installation id) in the browser's extension
  storage. In server mode, the session token is kept only in memory-only session
  storage; in desktop mode, a pairing key that cannot be read back is kept in the
  extension's own storage. No passwords or vault contents are written to disk.
- **The clipboard.** Values you copy are cleared from the clipboard after 30 seconds.
  The optional "only clear what CipherMoth copied" setting reads the clipboard only to
  compare it with a hash of what CipherMoth copied; it is never stored or sent.
- **The browser's store** sees installs and update checks, like for any extension; that
  is covered by the store's own privacy policy.

## The server and the desktop app

Your vault lives on hardware you control, encrypted with a key derived from your master
password. The web app checks for new releases by asking GitHub's public API from your
browser (Settings → Check for updates, which you can turn off); the desktop app checks
GitHub Releases for signed updates. No vault data is part of either request.

Details: [SECURITY.md](../SECURITY.md), [docs/EXTENSION.md](EXTENSION.md).

Questions: open an issue at https://github.com/mr-grj/ciphermoth/issues.
