# Installation

Conrad is one binary with no runtime dependencies. All state (SQLite database, encrypted keys) lives in the data directory.

## Docker / Compose

```sh
curl -O https://raw.githubusercontent.com/davidemaggi/conrad/main/deploy/docker-compose.yml
# edit CONRAD_HOSTNAMES, then:
docker compose up -d
docker compose logs conrad | grep setup_token
```

Images:

| Tag | Contents |
| --- | --- |
| `ghcr.io/davidemaggi/conrad:latest` | static binary on distroless, non-root (uid 65532) |
| `ghcr.io/davidemaggi/conrad:latest-pkcs11` | Debian slim, built with PKCS#11 support (see [pkcs11.md](pkcs11.md)) |

The container listens on 80 and 443 and stores everything in `/data`. Its `HEALTHCHECK` runs `conrad healthcheck`.

## Binary + systemd

Download the archive for your platform from the releases page, then:

```sh
sudo install -m 755 conrad /usr/local/bin/conrad
sudo useradd --system --home /var/lib/conrad --shell /usr/sbin/nologin conrad
sudo install -m 644 deploy/conrad.service /etc/systemd/system/conrad.service
sudo mkdir -p /etc/conrad && echo 'CONRAD_HOSTNAMES=ca.home.lab' | sudo tee /etc/conrad/conrad.env
sudo systemctl daemon-reload && sudo systemctl enable --now conrad
journalctl -u conrad | grep setup_token
```

The unit grants only `CAP_NET_BIND_SERVICE` and runs with a read-only filesystem except `/var/lib/conrad`.

## First run

On first start Conrad has no CA. It serves a temporary self-signed certificate and logs a one-time **setup token**. Open the URL from the log, enter the token, and choose:

- admin username and password;
- root CA subject, key algorithm and validity;
- the first issuer (intermediate CA) and its slug, which becomes the ACME path `/acme/<slug>/directory`;
- the **CA passphrase**, which encrypts every private key. Conrad cannot recover it.

### Headless setup

```sh
CONRAD_ADMIN_PASSWORD=... CONRAD_CA_PASSPHRASE=... conrad init -admin-user admin -cn "Home Lab Root CA" -issuer default
```

## Unlocking after a restart

Keys stay encrypted at rest. After a restart the CA is **locked** until you unlock it, either by entering the passphrase in the web UI or automatically from `CONRAD_CA_PASSPHRASE_FILE` (a Docker secret or a systemd credential). While locked, ACME and issuance return errors; the UI, `/roots` and CRLs keep working.

## DNS

Clients must resolve Conrad's hostname, and Conrad must resolve the names it validates. If those names exist only in your LAN DNS (Pi-hole, AdGuard, your router), set `CONRAD_DNS_RESOLVERS` to that server.
