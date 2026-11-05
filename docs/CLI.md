# CipherMoth CLI

The CLI connects to the Docker/server API. Desktop vaults have no HTTP listener; use the native app and its encrypted backup/import UI for them.

Sometimes you just want to grab a password from the terminal without switching windows. That's what the CLI is for. It's a thin client that talks to the same API as the web UI, so everything stays encrypted the same way.

## Run it

### If you installed with `install.sh` (Docker only)

`install.sh` drops a small `cip` script next to your `docker-compose.prod.yml`. Nothing to install, no Python, no clone:

```shell
cd ~/ciphermoth
./cip password list
```

Make it work from anywhere by linking it onto your PATH:

```shell
sudo ln -s ~/ciphermoth/cip /usr/local/bin/cip
cip password get github
```

`cip` runs the CLI inside the backend container, which already knows where the API is, so there is nothing to configure. It tells you how to start the stack if it isn't running. If you'd rather not use the wrapper, the long form is:

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth password list
```

### From a clone

```shell
cd backend
uv tool install .
```

Or run it without installing:

```shell
cd backend
uv run ciphermoth <command>
```

This talks to `http://localhost:8000/api` by default. Point it somewhere else with the `CIPHERMOTH_API_URL` environment variable.

## Commands

Examples below use `ciphermoth`; on a Docker install substitute `cip` (or `./cip`) and everything else is identical.

```
ciphermoth password list                     List all entries
ciphermoth password get <name>               Reveal an entry (and its live 2FA code)
ciphermoth password create <name> [--kind]   Add a login or a secure note (interactive)
ciphermoth password update <name>            Edit an entry (interactive)
ciphermoth password delete <name>... [--yes] Move one or more entries to the trash
ciphermoth password move <name>... --folder <folder> | --no-folder  Move entries into a folder, or out of theirs
ciphermoth password history <name>          Reveal an entry's earlier passwords (last 10), newest first
ciphermoth password trash                    List entries currently in the trash
ciphermoth password restore <name> [--id]    Restore a trashed entry back to the vault
ciphermoth password purge <name> [--id] [--yes] Permanently delete a trashed entry
ciphermoth backup [--out <dir>]              Save a complete encrypted backup (.cmbackup)
ciphermoth import <file> [--on-conflict]     Restore a .cmbackup, or a backup ZIP from 2.0 or earlier (skip|overwrite)
ciphermoth import-csv <file> [--on-conflict] Import a CSV from another manager (skip|overwrite)
ciphermoth damaged [--remove] [--yes]        List (or remove) entries and attachments the vault cannot read
ciphermoth recover                           Forgot the master password? Set a new one with your recovery code
```

Every command that touches encrypted data prompts for the master password. Use `--help` on any command for details.

**Security keys.** When the vault requires a security key, the CLI asks for the key's PIN and then for a touch, talking to the key over USB (`backup` asks once more, to confirm). Run the CLI on the computer the key is plugged into: `cip` inside the Docker container cannot reach it. Registering and removing keys happens in the web UI or the desktop app.

**Recovery.** `recover` asks for the recovery code (hidden), a new master password twice, and, if the vault requires a security key, whether you lost your keys (answering yes removes them). The vault is re-keyed, every other session ends, and a new recovery code is printed: the old one no longer works.

`delete` with several names moves them together: if one of them is missing, none is moved (servers before 3.3.0 accept only one name per command).

`move` works the same way: every name moves into the folder, or none does if one is missing. The folder name is trimmed and may not be empty (use `--no-folder` to take entries out of their folder) or longer than 200 characters; entries already in it are left as they are. It needs a 3.5.0 server.

Trash may contain several entries with the same name, especially after overwriting an import. `password trash` shows their row IDs. Pass `--id <row-id>` to restore or purge that exact row; without it these commands select the most recently trashed entry of that name. The name must still match the selected row.

On `update`, leave a prompt blank to keep the current value: you can fix a URL without retyping the password, and the password history only records a genuine change.

`import` and `import-csv` are all-or-nothing: if a row is invalid nothing is imported, and the error names the row and column. Records that simply aren't importable (cards, identities, rows without a password) are listed after the summary with their row and reason, and so are rows imported under a new name because the file had another entry with the same name (`name (2)`). Bitwarden and Proton Pass secure notes import as secure notes. With `--on-conflict overwrite`, an entry that is replaced moves to the trash with its history and attachments.

## Examples

```shell
# Add a new login
$ ciphermoth password create github
Master password:
Password value:
Repeat for confirmation:
Username / email: alex@example.com
URL: https://github.com
TOTP secret:
Description: Personal account
Folder: Work
✓  Created github

# Add a secure note instead
$ ciphermoth password create wifi --kind note
Master password:
Note body:
Repeat for confirmation:
Description: Home network
Folder:
✓  Created wifi

# Reveal it
$ ciphermoth password get github
Master password:

  github
  Value        hunter2
  Username     alex@example.com
  URL          https://github.com
  Description  Personal account

# Change only the website, keeping the password
$ ciphermoth password update github
Master password:
New password value (blank to keep the current one):
Username / email [alex@example.com]:
URL [https://github.com]: https://github.com/settings
Description [Personal account]:
Folder [Work]:
✓  Updated github

# List everything
$ ciphermoth password list
Master password:
Name      Description
github    Personal account
gmail     Work email

# Create an encrypted backup
$ ciphermoth backup --out ~/backups
Master password:
✓  Backup saved to ~/backups/ciphermoth_backup_20260314_120000_<unique>.cmbackup

# Restore with overwrite (an overwritten entry moves to the trash)
$ ciphermoth import ciphermoth_backup_20260314_120000.cmbackup --on-conflict overwrite
Master password:
Backup password (Enter if it is the current master password):
✓  Import complete - 3 added, 1 overwritten, 0 skipped
✓  Also restored: 2 in the trash, 4 attachment(s)
```

## Backups from the Docker CLI

`--out` writes inside the container, so save to `/tmp` and copy the file out:

```shell
cip backup -o /tmp
docker compose -f docker-compose.prod.yml cp backend:/tmp/ciphermoth_backup_20260314_120000.cmbackup .
```

The **Backup** button in the web UI downloads the same file straight to your machine, which is usually easier.

Backup format 2 stores entry metadata and attachments in authenticated frames. A complete backup is limited to 1 GiB and 1,000,001 frames; each entry frame is limited to 64 MiB and each attachment to 5 MiB. The vault refuses changes that would exceed the complete-backup limits, so supported operations cannot silently create data that this version cannot back up. See [the vault format specification](VAULT_FORMAT.md) for details.

## Vault snapshots (`ciphermoth-admin`)

`ciphermoth-admin` is a second command in the backend image. It works on the vault file itself rather than through the API, so it needs no master password and runs where the file is:

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin snapshot   # complete, consistent copy into /data/snapshots
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin check      # integrity check of the vault (or of a snapshot path)
```

`restore` replaces the vault with a snapshot and runs only while CipherMoth is stopped. `set-aside` moves a vault this release cannot open (one from CipherMoth 2.0) into the snapshot folder so the next start creates a new one. A snapshot is a raw copy of this installation's vault file under the master password of the moment it was taken; a backup (`.cmbackup`) is the complete, portable copy you can restore anywhere. See [UPDATING.md](UPDATING.md#snapshots).

## What the CLI does with your secrets

It follows the same zero-trust rules as the web UI, and it's small enough to read in one sitting ([`backend/cli.py`](../backend/cli.py)).

- **Nothing is stored.** There is no token cache and no config file. Each command prompts for the master password, opens a vault session on the server for that one command, and locks it again when the command ends, even if it fails. The CLI never sees the vault key. That's also why every command asks again, even with biometric unlock turned on: that belongs to the web UI and the desktop app. It needs a CipherMoth server from v1.5.0 on; against an older one (recognized by its missing unlock route) it stops with a message instead of asking that server for the key. CLIs older than v1.5.0 are refused by servers from v1.6.0 on with a message to update.
- **Secrets are never arguments.** Passwords and note bodies are typed at a hidden prompt, so they don't reach your shell history, `ps`, or `docker inspect`. Only entry names are arguments, so `cip password get github` does reveal in your history that a `github` entry exists.
- **Redirects are never followed**, so the session token and the master password can't be replayed to another host.
- **Backups are written `0600`**, readable only by you, on top of being encrypted (AES-256-GCM under Argon2id with the backup's own salt and your master password). Downloads stream into a uniquely named `.partial` file; only a completed, flushed transfer is published as `.cmbackup`, without replacing an existing file. Interrupted transfers are removed on normal error or cancellation; after a process kill, a `.partial` file is incomplete and must not be used as a backup. Imports also stream from disk, so the CLI does not load a whole large backup into memory. The backup password `import` asks for is the master password the vault had when the backup was made; press Enter if it is the current one. It is prompted, never an argument.
- **You get warned about plaintext transport.** If `CIPHERMOTH_API_URL` points at a remote host over plain `http://`, the CLI says so before prompting, because your master password would cross the network unencrypted. Put the API behind HTTPS, or reach it over a VPN or SSH tunnel.

A note on entry names: any name works, including ones containing `/` (the CLI checks that the server routes them correctly and refuses them on older servers rather than risk acting on a different entry). New entries can't be named `.`, `..` or `trash`, because those can't be addressed in a web address; existing ones still work from the CLI, except that `get` and `update` can't open an entry named `trash`. Rename it in the web UI.

## Rate limits

Unlocking the vault is rate-limited to 30 attempts an hour per IP address to slow down anyone guessing your master password. Every CLI command unlocks once (twice if its session expires while you answer prompts), so a long batch of commands can run into it. Raise it on the backend if you hit it:

```shell
# in your .env, then: docker compose -f docker-compose.prod.yml up -d
CIPHERMOTH_RATE_LIMIT=200/hour
```

That single variable overrides the limit on every rate-limited route, so keep it sane.
