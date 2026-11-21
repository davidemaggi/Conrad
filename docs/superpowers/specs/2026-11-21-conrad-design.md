# Conrad — Design Spec

**Date:** 2026-11-21
**Status:** Approved in brainstorming, pending spec review
**Scope:** V1 (HA/clustering deferred to V2)

Conrad is a self-hosted Certificate Authority with an RFC 8555 ACME server and a web UI, built for homelabs. It lets internal services get trusted HTTPS certificates through certbot (or any ACME client) without exposing anything to the internet or going through a tunnel. Named after Hermes Conrad, the Futurama bureaucrat: it stamps, files and approves certificates.

---

## 1. Goals and non-goals

### Goals (V1)
- One root CA with any number of intermediate CAs ("issuers"), created by a first-run wizard or imported. Each issuer has its own ACME directory, policy, EAB keys, CRL and OCSP.
- Standards-compliant ACME server working with certbot, acme.sh, lego, Caddy, Traefik and cert-manager.
- HTTP-01, DNS-01 and TLS-ALPN-01 challenges.
- Web UI that matters as much as the backend: polished, accessible, multilingual (English default + Italian), light/dark/system themes.
- Copy-ready instructions for installing the root CA on Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL, Arch), iOS, Android, Firefox, Docker and Java, plus ACME client snippets.
- Single admin user created during installation, with optional OIDC login.
- CA keys stored in an encrypted file or in an HSM via PKCS#11.
- Expiry notifications by SMTP (authenticated or not; none/STARTTLS/TLS) and HMAC-signed webhooks.
- CRL and OCSP.
- A single binary and Docker image, with SQLite storage.

### Non-goals (V1)
- Multiple users or roles.
- HA, clustering or external databases (planned for V2).
- Issuing certificates for public domains trusted by browsers by default (Conrad is a private CA).

---

## 2. Architecture

### Stack
- **Backend:** Go (latest stable), `net/http` + `chi` router, `log/slog`.
- **Storage:** SQLite through `modernc.org/sqlite` (pure Go, no CGO), WAL mode, embedded migrations.
- **Frontend:** React + Vite + TypeScript + Tailwind CSS + shadcn/ui (Radix), `react-i18next`, TanStack Query and TanStack Router. Built to static assets and embedded with `go:embed`.
- **Crypto:** Go stdlib `crypto/x509` and `crypto/ecdsa`, `go-jose/go-jose/v4` for JWS, `golang.org/x/crypto/argon2` and `x/crypto/ocsp`, `ThalesGroup/crypto11` for PKCS#11 (build tag `pkcs11`, needs CGO).

### Repository layout
```
cmd/conrad/              entrypoint; subcommands: serve, init, backup, restore, reset-admin, version
internal/config/         YAML + CONRAD_* env loading and validation
internal/store/          SQLite, migrations, repositories (one file per aggregate)
internal/crypto/signer/  Signer interface + software (encrypted file) and pkcs11 implementations
internal/ca/             CA hierarchy (root + issuers), issuance, rotation, revocation, CRL, OCSP responder
internal/acme/           RFC 8555 handlers, JWS verification, nonces, EAB, ARI
internal/challenge/      HTTP-01, DNS-01, TLS-ALPN-01 validators + async worker pool
internal/policy/         identifier and CSR policy evaluation
internal/auth/           local admin (argon2id), sessions, CSRF, OIDC, login rate limit
internal/notify/         expiry scheduler, SMTP sender, webhook sender, i18n email templates
internal/audit/          append-only audit log
internal/api/            JSON REST API for the UI (/api/v1)
internal/web/            embedded SPA serving with history fallback
web/                     React app
deploy/                  Dockerfiles, docker-compose.yml, systemd unit
docs/                    user documentation
```

Each `internal/` package exposes a small interface and depends only on interfaces from lower layers: `store` and `signer` at the bottom, then `ca` and `policy`, then `acme`, `challenge` and `notify`, with `api` and `web` on top.

### Listeners
- `:443` (configurable): TLS for the UI, `/api/v1`, `/acme/*`, `/ocsp`, `/crl` and `/roots`. The server certificate is issued by the default issuer and renewed automatically at two-thirds of its lifetime.
- `:80` (optional): plain HTTP, serving only `/roots/*` and `/crl/*` (needed before clients trust the CA) and redirecting everything else to HTTPS.

### CA unlock model
- Software keys are encrypted with AES-256-GCM using a key derived via argon2id from a passphrase.
- The passphrase comes from `CONRAD_CA_PASSPHRASE`, `CONRAD_CA_PASSPHRASE_FILE` (Docker secret) or interactive unlock in the UI after boot.
- While the CA is locked, ACME and issuance return 503 / `serverInternal` with a "CA locked" detail, `/readyz` fails, the UI shows a "CA locked" banner with an unlock form, and a "CA locked" notification is sent.
- With an HSM, the PKCS#11 PIN is supplied the same way as the passphrase.

### Data model (SQLite)
`settings`, `admin`, `sessions`, `ca_keys` (metadata + encrypted blob or PKCS#11 reference), `authorities` (id, slug, kind = root|intermediate, parent_id, status = active|retiring|retired|revoked, is_default, cert PEM, key_id; supports multiple roots at the data level; a slug is unique among active issuers only, so a successor takes it over during rotation while the old issuer moves to retiring), `acme_accounts`, `acme_eab_keys`, `acme_nonces`, `acme_orders`, `acme_authzs`, `acme_challenges`, `certificates` (serial, PEM, SANs, not_before/after, status, issuer_id, account_id, source = acme|manual), `revocations`, `policies` (one per issuer), `notification_channels`, `notification_log` (cert_id + threshold, for dedupe), `audit_log`.

---

## 3. CA

- **Root:** ECDSA P-384, 10 years by default, `pathLen=1`, name constraints optional (recommended: limit to the allowed domains).
- **Intermediates ("issuers"):** any number, created from the UI under the root. ECDSA P-256 by default (P-384 or RSA 3072 optional), 5 years by default, `pathLen=0`. Each issuer has:
  - a unique slug (e.g. `servers`, `k8s`, `devices`), display name and description;
  - its own ACME directory (`/acme/{slug}/directory`), policy, EAB keys, CRL (`/crl/{authorityID}.crl`) and OCSP responder (`/ocsp/{authorityID}`); these URLs use the immutable authority ID rather than the slug, because a slug moves to the successor on rotation while certificates already issued must keep pointing at their own issuer;
  - optional name constraints narrower than the root's.
- **Default issuer:** exactly one issuer is marked default. The wizard creates it as `default`. `/acme/directory` is an alias of the default issuer's directory, and the default issuer signs Conrad's own server certificate.
- **Issuer rotation:** "Rotate" creates a successor issuer with the same slug, policy and EAB keys. New orders on that slug are signed by the successor immediately; the old issuer moves to `retiring` (still serves CRL/OCSP and accepts revocations, issues nothing) until its last leaf certificate expires, then becomes `retired`. Clients need no change because they trust the root.
- **Issuer revocation:** revoking an issuer adds it to the root's CRL and marks all its leaf certificates revoked (reason `cACompromise`). Requires a two-step confirmation.
- **Root:** one active root in the V1 UI. The data model already allows several roots; the UI offers "Generate successor root" near the end of life (cross-signed by the old root while both are valid) so that clients can install the new root before the old one expires.
- **Import:** an existing root and/or intermediate as PEM cert + key, or PKCS#12. An imported intermediate becomes an issuer.
- **Leaf certificates:** SANs (DNS and optionally IP), EKU serverAuth (clientAuth optional), AIA (OCSP URL + CA Issuers URL), CDP (CRL URL), 128-bit random serial, lifetime taken from policy.
- **Revocation:** status set to revoked with a reason code. The CRL is regenerated immediately and then every 24 hours (7-day validity). Each issuer's OCSP responder signs responses with a dedicated delegated OCSP certificate issued by that issuer.
- **Downloads:** root in PEM, DER/CRT and `.mobileconfig` (Apple profile); the chain as PEM.

---

## 4. ACME server (RFC 8555)

**Base path:** `/acme/{slug}` per issuer, with `/acme` as an alias of the default issuer. Accounts, orders and EAB keys belong to one issuer; an account created on `/acme/k8s` cannot order on `/acme/servers`. Endpoints: `directory`, `new-nonce`, `new-account`, `new-order`, `authz/{id}`, `chall/{id}`, `order/{id}`, `order/{id}/finalize`, `cert/{id}`, `revoke-cert`, `key-change`, `renewal-info` (ARI, RFC 9773).

### Request handling
- JWS: ES256, ES384, RS256 and EdDSA. A request must carry either `kid` or `jwk`, never both. The protected `url` must match the request URL. The nonce must be valid and unused, and it is consumed on use.
- Nonces are stored in the DB with a 1-hour TTL and purged periodically. Every response carries `Replay-Nonce`.
- Errors use `application/problem+json` with the standard `urn:ietf:params:acme:error:*` types.
- Rate limits per account and per IP (token bucket, configurable).
- EAB (HS256) is optional globally; when required, `new-account` without valid EAB gets `externalAccountRequired`.

### Order lifecycle
1. `new-order`: every identifier is checked by `policy`; a rejection returns `rejectedIdentifier`.
2. One authz per identifier, with the challenges allowed by policy. Wildcards get DNS-01 only.
3. When a challenge is triggered, it is queued to the validation worker pool. The worker retries with backoff for up to about 60 seconds, then the challenge becomes `valid` or `invalid` with the error stored on the challenge.
4. `finalize`: the CSR must contain exactly the order identifiers and an allowed key type (RSA ≥ 2048, ECDSA P-256/P-384, Ed25519) and a valid signature. The certificate is issued by the issuer that owns the directory.
5. `cert/{id}` returns the leaf + issuer chain as PEM.

### Challenge validators
- **HTTP-01:** `GET http://{domain}/.well-known/acme-challenge/{token}` on port 80, at most 10 redirects, 10 s timeout, body must equal the key authorization.
- **DNS-01:** TXT `_acme-challenge.{domain}` queried through a configurable resolver list (default: system resolvers), following CNAMEs (acme-dns style delegation), 10 s timeout.
- **TLS-ALPN-01:** TLS handshake to `{domain}:443` with ALPN `acme-tls/1` and SNI set to the domain. The certificate must carry a critical `id-pe-acmeIdentifier` extension with the SHA-256 of the key authorization.

### Policy (one per issuer, editable from the UI)
- Allowed domain globs (e.g. `*.home.lab`, `*.lan`); everything else is rejected.
- Allow wildcards (yes/no); allow IP identifiers (yes/no, private ranges only).
- Default lifetime 90 days, maximum 397 days.
- Allowed key types; enabled challenge types; EAB required (yes/no); rate limits.

---

## 5. Authentication and security

- **Single admin**, created in the setup wizard. Password hashed with argon2id (OWASP parameters).
- **Sessions:** a random 256-bit token is stored hashed in the DB and sent as a `HttpOnly; Secure; SameSite=Strict` cookie, with a 12-hour idle timeout and a 7-day absolute lifetime.
- **CSRF:** double-submit token on every mutating API request.
- **Login rate limit:** exponential backoff per IP and per user.
- **OIDC:** authorization code flow + PKCE, using `coreos/go-oidc`. Only the configured `sub` or `email` is accepted. The local password login can be disabled once OIDC works, with `conrad reset-admin` as the recovery path.
- **Setup lock:** the wizard is reachable only while no admin exists, and it is protected by a one-time setup token printed in the startup logs.
- **Audit log** (append-only) for logins, issuance, revocation, policy/settings changes and CA unlock.
- **Security headers:** strict CSP, HSTS, `X-Content-Type-Options` and `Referrer-Policy`.

---

## 6. Notifications

- A daily scheduler, plus a run at startup, checks certificates against thresholds (default 30/14/7/1 days, configurable). Each (certificate, threshold) pair is notified once, deduplicated through `notification_log`.
- **SMTP:** host, port, security = `none` | `starttls` | `tls`, optional auth (PLAIN/LOGIN; empty credentials mean no AUTH, for internal relays), optional skip-verify, from/to addresses. A "send test email" button is available. HTML + text templates are localized.
- **Webhooks:** POST of a JSON event (`id`, `type`, `occurredAt`, `data`, localized `title`/`text`), headers `X-Conrad-Event`, `X-Conrad-Delivery`, `X-Conrad-Timestamp` and `X-Conrad-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`, 3 retries with exponential backoff, plus a test button.
- Expiry checks skip certificates superseded by a renewal (same issuer and names, later expiry). CA thresholds are fixed at 90/30/7/1 days. A dedupe record is dropped when no channel received the notification, so it is retried. `acme.failed` (final challenge/order failure) is an extra subscribable event.
- **Events:** `cert.expiring`, `cert.issued`, `cert.revoked`, `ca.expiring` (root or any issuer), `ca.locked`.

---

## 7. Web UI

### Brand
- **Logo:** an original "bureaucratic stamp" seal: a green circle with a dashed inner ring, the ring text `CONRAD · CERTIFIED · APPROVED ·`, and in the center a padlock with dreadlocks as its shackle (dreadlocks are "locks") and bureaucrat glasses on the body.
- **Simplified mark** for favicon and small sizes: the circle and the dreadlocked padlock only, no ring text.
- The logo is an original design and must not reproduce Futurama artwork.
- **Palette** (taken from the character's outfit):

| Token | Light ("Bureau") | Dark ("Night shift") | Source |
|---|---|---|---|
| primary | `#3F6B35` | `#7FB069` | suit green |
| background | `#FAF7EE` | `#141A13` | shirt cream |
| surface | `#FFFFFF` | `#1D251B` | — |
| info | `#5B8FB9` | `#8FC1E3` | clipboard blue |
| danger | `#B0332A` | `#E0574B` | shoes red |
| warning (fill) | `#C08A2E` | `#E3B25A` | — |
| warning (text on light) | `#8A5E14` | `#E9C47D` | WCAG AA |
| ink / accent | `#4A3424` | `#A0754F` | hair brown |

- **Fonts:** Inter for the UI, JetBrains Mono for serials, fingerprints, PEM blocks and commands.

### Layout
- Green left sidebar holding the logo and navigation (Dashboard, Authorities, Certificates, ACME accounts, Install CA, ACME clients, Notifications, Settings). It collapses to a drawer on mobile.
- Top bar: page title, language selector, theme toggle (light/dark/system), admin menu.
- ⌘K command palette; "CA locked" banner when the CA needs unlocking.

### Pages
- **Setup wizard:** language and theme → admin account → CA (generate root + `default` issuer / import / HSM) → base policy for the default issuer → summary with root download and install links.
- **Dashboard:** counters (active, expiring within 14 days, revoked, accounts), expiring-soon list, recent activity, status and expiry of the root and every issuer.
- **Certificates:** searchable, filterable (including by issuer), sortable table.
  - Detail view: SANs, serial, fingerprints, chain, copyable PEM, download and revoke (two-step confirmation where the user types the domain).
  - Manual issuance: pick an issuer, then paste a CSR, or generate the key server-side and download it as PEM or PFX.
- **ACME accounts:** list, contacts, orders, deactivate; manage EAB keys.
- **Authorities:** a tree view of the root and its issuers, each with status, expiry, certificate count and directory URL (copy button).
  - Create issuer: slug, name, key type, lifetime, name constraints, initial policy (cloned from an existing issuer or blank).
  - Issuer detail with tabs: Overview, Policy (every option in §4), EAB keys, Certificates, Rotate, Revoke.
  - Root detail: download, fingerprint, expiry, "Generate successor root".
- **Install CA:** one tab per platform (Windows: `certutil` + PowerShell `Import-Certificate`; macOS: `security add-trusted-cert` + `.mobileconfig`; Debian/Ubuntu: `update-ca-certificates`; Fedora/RHEL: `update-ca-trust`; Arch: `trust anchor`; iOS; Android; Firefox enterprise roots / policies.json; Docker; Java `keytool`).
  - Commands are pre-filled with the real Conrad URL and the root fingerprint.
  - An optional one-liner install script is offered; its source is shown before use.
- **ACME clients:** snippets for certbot (including `--server` and EAB flags and the `REQUESTS_CA_BUNDLE` note), acme.sh, Caddy, Traefik, nginx+certbot and cert-manager `ClusterIssuer`, pre-filled with the directory URL of the issuer chosen in an issuer selector at the top of the page.
- **Notifications:** SMTP, webhooks, thresholds, test buttons.
- **Settings:** OIDC, HSM, backup/restore, audit log, system info.
- **Empty states** may use light bureaucratic humor, kept restrained.

### i18n
- `react-i18next` with one JSON namespace file per language under `web/src/locales/{lang}/`. English is the default and the fallback; Italian ships in V1.
- Language is detected from the browser and persisted after the user picks one. Dates and durations are formatted with `Intl`.
- Server errors carry an i18n key so the UI shows translated messages. Notification emails use the admin's chosen language.

### Theming and accessibility
- Three-layer tokens (primitive → semantic → component) exposed as CSS variables and mapped to shadcn variables.
- An inline `<head>` script applies the theme before first paint, so there is no flash.
- WCAG AA contrast, full keyboard navigation, visible focus, `prefers-reduced-motion` respected, labelled form controls.
- The UI is implemented with the ui-ux-pro-max and ui-styling skills.

---

## 8. API

- JSON REST at `/api/v1`, session cookie + CSRF.
- Resources: `setup`, `auth`, `authorities` (root + issuers, with nested `policy` and `eab-keys`), `certificates`, `accounts`, `notifications`, `settings`, `audit`, `system`.
- Error shape: `{ "code": "cert.not_found", "message": "...", "details": {} }`; `code` doubles as the i18n key.

---

## 9. Error handling and observability

- Challenge failures are stored with a human-readable cause (e.g. "TXT record not found via 192.168.1.53") and shown both in the UI and in the ACME error returned to the client.
- `slog` logging, JSON or text format, configurable level.
- `/healthz` (process alive) and `/readyz` (DB reachable and CA unlocked).
- Prometheus metrics at `/metrics`: certificates issued and revoked, challenge results, ACME request latency, days to CA expiry.

---

## 10. Testing

- **Unit:** JWS and nonce handling, policy, CSR validation, CA issuance and CRL/OCSP, auth (hashing, sessions, CSRF), notification dedupe and SMTP modes.
- **Integration:** issuer isolation (an account on one directory cannot order on another) and rotation (new orders signed by the successor, old certificates still verifiable through OCSP/CRL); an in-process `lego` client runs the full flow for HTTP-01, DNS-01 (fake DNS server with `miekg/dns`) and TLS-ALPN-01; SMTP against a mock server in each security mode; PKCS#11 against SoftHSM2 (CI job with the `pkcs11` tag).
- **E2E:** Playwright drives the wizard, issuer creation and rotation, manual issuance, revocation, language and theme switching, and the Install CA page.
- **Compatibility:** a CI job runs real certbot in Docker to obtain and renew a certificate from Conrad.
- **Frontend:** Vitest + Testing Library for components; a check that every locale has the same keys as `en`.

---

## 11. Build and deployment

- Multi-stage Dockerfile: Node builds `web/`, Go builds the binary with embedded assets, final image is distroless.
  - Images: `conrad` (CGO off) and `conrad-pkcs11` (CGO on, includes the PKCS#11 build tag).
- `docker-compose.yml` example with a `/data` volume, ports 443/80 and the passphrase as a Docker secret.
- GoReleaser builds for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 and windows/amd64.
- systemd unit example.
- README in English with a quickstart (run → wizard → install root → certbot); detailed docs in `docs/`, including DNS setup for `conrad.home.lab`.

---

## 12. V2 (out of scope)

- HA/clustering: Postgres backend, shared nonce store, distributed locks for the scheduler and CRL generation.
