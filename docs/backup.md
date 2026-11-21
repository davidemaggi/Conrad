# Backup and restore

Everything lives in one SQLite database in the data directory. Private keys inside it are encrypted with the CA passphrase, so **a backup is useless without the passphrase, and the passphrase is useless without a backup.** Store both, separately.

## Backup (online)

```sh
conrad backup /backups/conrad-$(date +%F).db
# Docker:
docker exec conrad conrad backup /data/backup.db && docker cp conrad:/data/backup.db .
```

This is a consistent snapshot taken while the server runs. Schedule it with cron or a systemd timer.

## Restore

Stop the server first.

```sh
systemctl stop conrad
conrad restore /backups/conrad-2026-11-21.db
systemctl start conrad
```

`restore` checks that the file is a Conrad database with a CA before replacing the current one, and keeps the previous database next to it.

## Lost admin password

```sh
CONRAD_ADMIN_PASSWORD='new password' conrad reset-admin
```

This sets the password, re-enables password login (useful if OIDC is broken) and ends all sessions. A lost CA passphrase cannot be recovered: create a new CA and re-enrol your clients.

## With PKCS#11

The database holds only references to keys inside the HSM. Back up the token with your HSM vendor's tools as well.
