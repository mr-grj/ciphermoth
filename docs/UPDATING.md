# Updating CipherMoth

## Desktop updates

Download from [GitHub Releases](https://github.com/mr-grj/ciphermoth/releases/latest), choosing your CPU architecture. The desktop app includes its own Python runtime. No development tools or account are needed.

- **macOS:** open the DMG, drag CipherMoth to Applications, then launch the copied app. The app is ad-hoc signed for bundle integrity, but has no Apple Developer ID or notarization. Gatekeeper may block an internet download. After trying to open it, use **System Settings → Privacy & Security → Open Anyway** if macOS offers it and you trust the release. Managed Macs may disallow that exception. Do not disable Gatekeeper or remove quarantine globally. [Apple explains these exceptions](https://support.apple.com/en-us/102445).
- **Windows:** run the NSIS installer for x64 or ARM64. It installs for the current user. There is no Authenticode verified publisher; SmartScreen may warn. Inspect **More info**, confirm the download source, and choose **Run anyway** only if offered and you trust it. Organizational policies, Smart App Control or antivirus may block it; do not disable them to install CipherMoth. [Microsoft explains Smart App Control](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions).
- **Linux AppImage:** store the file somewhere writable by your user, make it executable (`chmod +x <file>.AppImage`), and open it. AppImage may require your distribution's FUSE compatibility package. Built-in updates replace this AppImage in place; do not keep it in a system-owned folder.
- **Debian/Ubuntu `.deb`:** use `sudo apt install ./<file>.deb`. To update, quit CipherMoth and install the newer package the same way. Built-in AppImage installation is disabled for this edition. There is no CipherMoth apt repository.

When **Settings → Check for updates** is on, CipherMoth checks after you unlock. A discreet **Update** chip opens the release version and notes. **Download and install** is your confirmation: the native Tauri 2 updater downloads over HTTPS from GitHub Releases, verifies the embedded trusted key and signed version/platform filename, locks the vault, closes Python, installs and restarts. You can cancel the download before installation starts. Closing the notice installs nothing. Turn checks off in Settings to stop contacting GitHub.

Checks send no vault contents, master password, session token or entry metadata. GitHub receives ordinary connection information, such as your IP address. Offline checks and rejected downloads leave the app usable. OS restrictions can still prevent installation: cryptographic updater authorization is separate from Apple/Microsoft publisher approval. Do not bypass a system policy to make an update work.

Updates replace application files, not the local SQLite vault. Use **Backup** periodically and keep the encrypted `.cmbackup` somewhere separate. If installation fails, relaunch the existing app or reinstall a compatible release from GitHub. Never delete the data folder to fix startup. Unsupported future vault schemas are refused unchanged; downgrades are not offered.

The production identity is `com.ciphermoth.desktop`. It never opens or migrates the old Alpha vault automatically. Export a complete encrypted backup in Alpha and import it into a newly created production vault if you choose to move your data. Docker remains independent. [Desktop data paths](../desktop/README.md#data-isolation) and [maintainer release instructions](../desktop/RELEASING.md) provide technical details.

## Docker edition

A self-hosted CipherMoth keeps the whole vault in one SQLite file, `vault.db`, in the `vault_data` Docker volume. Updating replaces the two containers; the volume stays. Snapshot and file-management commands do not need your master password; exporting or importing a portable backup does.

Docker updates are manual. The web app checks GitHub in the browser and shows the commands below; the backend never contacts GitHub.

## Update

**Coming from 2.0? Follow [Moving from CipherMoth 2.0](#moving-from-ciphermoth-20-vault-format-1) first.** The general commands below do not convert a 2.0 vault; 3.0 refuses it unchanged. For a compatible 3.x vault, in your CipherMoth folder:

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin snapshot
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

The first command writes a consistent, integrity-checked copy of the vault into the volume (next section) and prints its name; keep it until you have used the new version for a while. `CIPHERMOTH_VERSION` in `.env` decides which release runs (`latest`, or a pinned version such as `3.1.0`). Everyone is asked to unlock again after the restart, because sessions live in the server's memory.

To check that the images are CipherMoth's own before you start them, verify their signatures (see [SECURITY.md](../SECURITY.md)):

```shell
cosign verify ghcr.io/mr-grj/ciphermoth-backend:3.1.0 \
  --certificate-identity-regexp '^https://github.com/mr-grj/ciphermoth/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

(and the same for `ciphermoth-frontend`).

### Going back to the previous version

A release refuses to open a vault written by a newer release, so returning to an older version may need the snapshot you took before updating:

```shell
# 1. pin the previous version in .env, e.g. CIPHERMOTH_VERSION=2.0.0
docker compose -f docker-compose.prod.yml stop backend
docker compose -f docker-compose.prod.yml run --rm backend ciphermoth-admin restore /data/snapshots/vault-<time>.db
docker compose -f docker-compose.prod.yml up -d
```

Anything saved after that snapshot is lost by the restore (the vault it replaces is kept, see below).

**Schema upgrades are automatic and keep a copy first.** When a release changes the vault's table layout (3.4 adds the tables for security keys and the recovery code, schema 3), its first start copies the vault to `snapshots/before-schema-<n>-<time>.db`, then upgrades it in one transaction (a failed upgrade changes nothing). That copy is what you restore to go back: the previous release refuses the upgraded file. The desktop app does the same in its own data folder.

## Snapshots

```shell
docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin snapshot
```

- **Consistent while CipherMoth runs.** The copy goes through SQLite's online backup API, so it includes every committed change, also those still in the write-ahead log (`vault.db-wal`), and never a half-written one. Copying `vault.db` with `cp` or `docker cp` while CipherMoth runs is **not** safe: the file alone can miss recent changes.
- **Checked.** A snapshot is written to a temporary file, checked with SQLite's `integrity_check` and `foreign_key_check` and for the vault's identity, flushed to disk, and only then renamed into `/data/snapshots/vault-<time>.db` (mode `0600`). It is one self-contained file with no `-wal` or `-shm` next to it.
- **As safe as the vault.** A snapshot holds the same ciphertext as the vault and opens only with the master password that was current when it was taken. Like the vault, it shows only counts, timestamps and sizes, never entry content (see [VAULT_FORMAT.md](VAULT_FORMAT.md#4-sqlite-layout-schema-2)).
- Snapshots stay in the volume until you delete them. To keep one elsewhere, copy it out (it is a finished file, so this is safe):

  ```shell
  docker compose -f docker-compose.prod.yml cp backend:/data/snapshots/vault-<time>.db ./
  ```

- Check a vault or a snapshot at any time:

  ```shell
  docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin check
  docker compose -f docker-compose.prod.yml exec backend ciphermoth-admin check /data/snapshots/vault-<time>.db
  ```

A **backup** (`.cmbackup`, from the web UI's Backup button or `cip backup`) is a different thing: a complete, portable, password-protected copy of everything in the vault (entries, trash, history, attachments, settings) that you can restore into this vault or any other one, also on another machine. A **snapshot** is a raw copy of this installation's vault file, for getting this installation back to an earlier state. Keep both: snapshots for local recovery, backups somewhere else.

## Restore a snapshot

Restoring replaces the vault, so CipherMoth must be stopped: `restore` refuses while the backend runs, or while any other program has the vault open.

```shell
docker compose -f docker-compose.prod.yml stop backend
docker compose -f docker-compose.prod.yml run --rm backend ciphermoth-admin restore /data/snapshots/vault-<time>.db
docker compose -f docker-compose.prod.yml start backend
```

To restore a snapshot you kept outside the volume, copy it in first (`docker compose -f docker-compose.prod.yml cp ./vault-<time>.db backend:/data/snapshots/`).

What `restore` does:

1. Checks the snapshot (integrity, foreign keys, and that it is a CipherMoth vault of a schema this release understands) and refuses anything else without changing the vault.
2. Copies it next to the vault as `vault.db.restoring` and checks the copy.
3. Takes the current vault for itself (SQLite's exclusive locking mode). If anything else has it open, it stops here and changes nothing.
4. Keeps the current vault byte for byte, `vault.db` and its write-ahead log `vault.db-wal`, in a new folder `/data/snapshots/replaced-<time>/`. That folder is a complete vault: `ciphermoth-admin restore /data/snapshots/replaced-<time>/vault.db` brings it back.
5. Folds the current vault's write-ahead log into `vault.db` with SQLite's own checkpoint, so an old log can never be replayed into the restored file. A log SQLite cannot fold (a damaged vault) is moved into the kept folder as `vault.db-wal.unfolded`, never deleted.
6. Renames the copy over `vault.db` in one atomic step.

If the restore is interrupted at any point, `vault.db` is a complete vault, either the old one or the restored one, and the old vault is also in the kept folder once step 4 is done; run the restore again to finish it. After a restore, unlock with the master password the snapshot was taken with.

## When CipherMoth refuses to start

The backend checks the vault before serving anything, through a read-only connection that changes neither `vault.db` nor its write-ahead log, and stops with a message in `docker compose -f docker-compose.prod.yml logs backend` when one of the following is true. Docker keeps restarting the container until you fix the cause; nothing is written meanwhile.

- **"failed SQLite's integrity check" / "SQLite cannot open the vault file"**: the file is damaged (a failing disk, or a copy taken while it was being written). Restore the most recent snapshot.
- **"was created by CipherMoth 2.0 or earlier (vault format 1)"**: the vault uses the old format, see [Moving from CipherMoth 2.0](#moving-from-ciphermoth-20-vault-format-1). Nothing was changed.
- **"was written by a newer CipherMoth"** (a newer schema or vault format): you went back to an older release. Update again, or restore a snapshot taken by this release.
- **"is not a CipherMoth vault"**: the volume holds some other file as `vault.db`.
- **"... exists but vault.db is missing or empty"**: a write-ahead log or journal was left without its vault, for example by an interrupted `set-aside`. Run `ciphermoth-admin set-aside` again (it moves the journal next to the vault it belongs to) or put that vault file back.
- **"Another CipherMoth process is using /data"**: two backends share one volume. Run one.
- **"CipherMoth cannot write its vault in ..."**: the data folder belongs to another user. The backend runs as uid 1000; a host folder mounted instead of the volume must belong to it (`sudo chown -R 1000:1000 <folder>`). The message names the owner it found.
- **"no longer uses PostgreSQL"** (exit code 78): the container was started from a compose file of a PostgreSQL release; see the next section.

## When entries cannot be read

If part of the vault file is damaged (a failing disk) or was altered, the affected entries and attachments are left out of the vault and the web UI shows a warning (`cip damaged` lists them). Everything else keeps working, but backups and master password changes wait. Either restore a snapshot from before the damage (keeps everything), or intentionally remove the damaged items: the **Remove** button in the warning, or `cip damaged --remove`. Removing a damaged entry also permanently removes its attachments, including any that are still readable. Each requested row is checked again before removal; a readable entry cannot be removed through this recovery action.

## Moving from CipherMoth 2.0 (vault format 1)

CipherMoth 2.0 stored entry names, usernames and descriptions in plaintext and checked the master password with a separate bcrypt hash. This release uses vault format 2 ([VAULT_FORMAT.md](VAULT_FORMAT.md)), which encrypts every part of an entry, and **does not open or convert a 2.0 vault**. Started on one, the backend stops with "was created by CipherMoth 2.0 or earlier" and changes nothing; pin `CIPHERMOTH_VERSION=2.0.0` in `.env` and run `up -d` to get the old version back.

To move your entries:

1. **Before updating**, in CipherMoth 2.0, make a backup (web UI **Backup**, or `cip backup`). The 2.0 backup ZIP carries your active entries with their fields, not the trash, password history, attachments or settings; download attachments you want to keep from the entries themselves. If you already updated, pin `2.0.0` again to make it.
2. Take a snapshot as well (`ciphermoth-admin snapshot`), so the old vault can always be restored with 2.0.
3. Set `CIPHERMOTH_VERSION=3.0.0` in `.env` (including if you pinned `2.0.0` to export your entries). Pull the new images and verify their signatures as above, then move the old vault aside while the backend is stopped:

   ```shell
   docker compose -f docker-compose.prod.yml pull
   docker compose -f docker-compose.prod.yml stop backend
   docker compose -f docker-compose.prod.yml run --rm backend ciphermoth-admin set-aside
   docker compose -f docker-compose.prod.yml up -d
   ```

   `set-aside` asks for confirmation, then moves `vault.db` and its write-ahead log, unchanged, into `/data/snapshots/set-aside-<time>/`. Nothing is deleted.
4. Open the web UI, create a master password (a new vault), and import the ZIP from step 1 with its password (Import, "CipherMoth backup"). Then make a new backup: it is complete and much stronger than the old ZIP. Delete the old ZIP once you no longer need it; its entry names and the weak ZIP encryption stay readable to anyone who has it and the password.
5. Once you have used the new vault for a while and no longer want to go back, delete the old vault and the snapshots taken by 2.0 from the volume: they keep entry names, usernames and descriptions in plaintext.

   ```shell
   docker compose -f docker-compose.prod.yml exec backend sh -c 'rm -r /data/snapshots/set-aside-<time>'
   ```

   (and any `/data/snapshots/vault-<time>.db` or `replaced-<time>` folder from before the update).

A raw 2.0 SQLite snapshot cannot be opened or imported by 3.0; keep it for recovery with 2.0. Likewise, 2.0 cannot open a 3.0 vault. To go back to 2.0, use the 3.0 admin tool to move the new vault aside, put the old files back, and start 2.0:

```shell
docker compose -f docker-compose.prod.yml stop backend
docker compose -f docker-compose.prod.yml run --rm backend ciphermoth-admin set-aside
docker compose -f docker-compose.prod.yml run --rm --entrypoint sh backend -c 'mv /data/snapshots/set-aside-<time of the old vault>/vault.db* /data/'
# set CIPHERMOTH_VERSION=2.0.0 in .env, then:
docker compose -f docker-compose.prod.yml up -d
```

## Moving from a PostgreSQL release (v1.6.0 and older)

Releases up to v1.6.0 stored the vault in PostgreSQL. CipherMoth 2.0 and later keep it in SQLite and **require a fresh installation**: it starts a new, empty vault, does not read or convert the old database, and never deletes it. You can always go back.

What protects an existing install:

- **The new images refuse the old compose file.** A 2.0 backend started from a v1.6.0 `docker-compose.prod.yml` (for example with `CIPHERMOTH_VERSION=latest` and `pull`) exits with code 78 and the message "CipherMoth now keeps the vault in SQLite and no longer uses PostgreSQL". It creates no vault, and the PostgreSQL container and its volume keep running untouched. Pin `CIPHERMOTH_VERSION=1.6.0` in `.env` and run `up -d` again to return to your old vault.
- **One-click updates refuse 2.0.** The v1.6.0 app shows the update, but its updater stops with "needs updater protocol 3" before it changes anything. No updater can install 2.0; follow the steps below.
- **`install.sh` stops** when it finds an old `ciphermoth_postgres_data` volume, before downloading anything, unless you confirm.

Moving to 2.0:

1. If you want to bring entries along, make an encrypted backup in the old version first (Settings, "Back up", or `cip backup`). It carries your active entries, not the trash, password history, attachments or settings, and this release can still import it.
2. In your CipherMoth folder, stop the old stack, including the updater if you used it:

   ```shell
   docker compose -f docker-compose.prod.yml --profile autoupdate down
   ```

   (`down` without `-v` keeps the old `ciphermoth_postgres_data` volume.)
3. Keep a copy of `docker-compose.prod.yml` and `.env`, then replace `docker-compose.prod.yml` with the new one, and set `CIPHERMOTH_VERSION=latest` (or a 2.x version) in `.env`: a 1.x version there (one-click updates wrote it) would start a 1.x backend without its database. Running `install.sh` again in that folder does all of this and keeps the old files as `docker-compose.prod.yml.backup-<time>` and `.env.backup-<time>` (it never overwrites an earlier backup). `POSTGRES_*` lines in `.env` are no longer used and can be deleted.
4. Start it: `docker compose -f docker-compose.prod.yml up -d --remove-orphans`. Open the web UI, create a new master password, and import the backup from step 1 if you made one.
5. Once you are happy with the new vault, the old volumes can go: `docker volume rm ciphermoth_postgres_data ciphermoth_update_control ciphermoth_update_backups`.

To go back instead, stop the new stack, put the old compose file and `.env` back (the `.backup-<time>` copies), and start it again; the PostgreSQL volume is as you left it.
