<p align="center"><img src="web/public/favicon.svg" width="96" alt="Conrad"></p>

# Conrad

**A self-hosted certificate authority with an ACME server, for homelabs.** Every certificate gets its stamp.

Conrad gives your LAN its own private PKI: a root CA, one or more intermediate issuers, and an RFC 8555 ACME endpoint per issuer. Point certbot, acme.sh, Caddy, Traefik, cert-manager or lego at it and get real TLS for `nas.home.lab` the same way you would from Let's Encrypt. The web UI and the server ship as one static binary.

- **ACME (RFC 8555):** http-01, dns-01 and tls-alpn-01 challenges, External Account Binding, ARI (renewal info), revocation, key rollover.
- **Multiple issuers:** a root plus as many intermediate issuers as you like, each with its own policy (allowed domains, wildcards, IPs, key types, validity, rate limits) and its own ACME directory. Root rollover with cross-signing.
- **Web UI:** dashboard, issue/revoke, CSR signing, ACME accounts and EAB keys, audit log. English and Italian, light and dark themes.
- **Notifications:** expiry warnings and events via SMTP (none/STARTTLS/TLS, optional auth) or HMAC-signed webhooks.
- **Keys at rest:** encrypted with your passphrase (Argon2id + AES-GCM), or kept in an HSM through PKCS#11.
- **Login:** password, optionally OIDC (Authelia, Authentik, Keycloak, …).
- **Operations:** SQLite (pure Go, no CGO), online backup, CRLs, `/healthz`, systemd and Docker ready.

## Quick start

```sh
docker run -d --name conrad -p 80:80 -p 443:443 \
  -e CONRAD_HOSTNAMES=ca.home.lab -v conrad-data:/data \
  ghcr.io/davidemaggi/conrad:latest
docker logs conrad | grep setup_token
```

Open `https://ca.home.lab` (accept the temporary self-signed certificate once), paste the setup token, and create your admin, root and first issuer. Conrad then switches its own HTTPS to a certificate from your new CA. Install the root on your devices from **Authorities → Download**, or fetch it from `https://ca.home.lab/roots/current.crt`.

Then request a certificate:

```sh
certbot certonly --standalone -d nas.home.lab \
  --server https://ca.home.lab/acme/default/directory
```

More: [installation](docs/install.md) · [configuration](docs/configuration.md) · [ACME clients](docs/acme-clients.md) · [backup and restore](docs/backup.md) · [PKCS#11 / HSM](docs/pkcs11.md)

## Building from source

Requires Go 1.26+ and Node 24+.

```sh
make build      # web UI + static binary in bin/conrad
make test       # Go and web tests
make dev        # Vite dev server proxied to a local Conrad
```

PKCS#11 support needs CGO and is behind a build tag: `CGO_ENABLED=1 go build -tags pkcs11 ./cmd/conrad`.

## Scope

Conrad is built for a single administrator and a single node. High availability is planned for a later version. It is a private CA: certificates are trusted only by devices where you install its root.

## License

See [LICENSE](LICENSE).
