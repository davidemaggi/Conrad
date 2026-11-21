# Configuration

Conrad reads an optional YAML file (`-config file` or `CONRAD_CONFIG`) and then `CONRAD_*` environment variables. Environment variables win.

| Environment | YAML | Default | Description |
| --- | --- | --- | --- |
| `CONRAD_DATA_DIR` | `data_dir` | `./data` (`/data` in Docker) | database and key storage |
| `CONRAD_HOSTNAMES` | `hostnames` | — | names on Conrad's own TLS certificate, comma separated; the first is used in URLs |
| `CONRAD_EXTERNAL_URL` | `external_url` | `https://<first hostname>` | base URL used in ACME directories, CRL and AIA links; set it when behind a proxy or on a non-standard port |
| `CONRAD_HTTPS_ADDR` | `https_addr` | `:443` | main listener (UI, API, ACME) |
| `CONRAD_HTTP_ADDR` | `http_addr` | `:80` | plain HTTP: `/roots`, CRLs, `/healthz` and a redirect to HTTPS; `none` disables it |
| `CONRAD_TLS_MODE` | `tls_mode` | `self` | `self`: HTTPS with a certificate from the default issuer, renewed automatically. `off`: plain HTTP on `https_addr`, for use behind a TLS-terminating proxy |
| `CONRAD_DNS_RESOLVERS` | `dns_resolvers` | system | resolvers for challenge validation, e.g. `192.168.1.1:53` |
| `CONRAD_CA_PASSPHRASE` | — | — | unlock the CA at start (prefer the `_FILE` form) |
| `CONRAD_CA_PASSPHRASE_FILE` | `ca_passphrase_file` | — | file holding the passphrase |
| `CONRAD_LOG_LEVEL` | `log.level` | `info` | `debug`, `info`, `warn`, `error` |
| `CONRAD_LOG_FORMAT` | `log.format` | `text` | `text` or `json` |
| `CONRAD_PKCS11_MODULE` | `pkcs11.module` | — | path of the PKCS#11 library; enables the HSM key provider |
| `CONRAD_PKCS11_TOKEN_LABEL` | `pkcs11.token_label` | — | token to use |
| `CONRAD_PKCS11_PIN` / `_FILE` | `pkcs11.pin_file` | — | user PIN, used to unlock the CA at start |

Only for `conrad init` and `conrad reset-admin`: `CONRAD_ADMIN_PASSWORD`.

Everything else (issuers, policies, notifications, OIDC, password login) is configured from the web UI and stored in the database.

## Example

```yaml
data_dir: /var/lib/conrad
hostnames: [ca.home.lab, conrad.home.lab]
dns_resolvers: [192.168.1.1:53]
ca_passphrase_file: /etc/conrad/passphrase
log:
  format: json
```

## Behind a reverse proxy

Either let the proxy pass TLS through to Conrad (recommended: Conrad renews its own certificate), or terminate TLS at the proxy:

```sh
CONRAD_TLS_MODE=off CONRAD_HTTPS_ADDR=127.0.0.1:8080 CONRAD_HTTP_ADDR=none \
CONRAD_EXTERNAL_URL=https://ca.home.lab conrad serve
```

ACME clients reach Conrad through the proxy. Conrad's validators connect directly to the hosts being validated on port 80 (http-01) or 443 (tls-alpn-01), as RFC 8555 requires.
