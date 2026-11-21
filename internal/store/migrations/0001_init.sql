-- All timestamps are unix seconds (UTC).

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE admin (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    username       TEXT    NOT NULL,
    password_hash  TEXT    NOT NULL DEFAULT '',
    language       TEXT    NOT NULL DEFAULT 'en',
    created_at     INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash  BLOB    PRIMARY KEY,
    csrf_token  TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    ip          TEXT    NOT NULL DEFAULT '',
    user_agent  TEXT    NOT NULL DEFAULT '',
    method      TEXT    NOT NULL DEFAULT 'password'
);

CREATE TABLE ca_keys (
    id          TEXT    PRIMARY KEY,
    provider    TEXT    NOT NULL,          -- software | pkcs11
    algorithm   TEXT    NOT NULL,          -- ecdsa-p256 | ecdsa-p384 | rsa-2048 | rsa-3072
    blob        BLOB    NOT NULL,          -- encrypted PKCS#8 or PKCS#11 reference
    created_at  INTEGER NOT NULL
);

CREATE TABLE authorities (
    id             TEXT    PRIMARY KEY,
    slug           TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    description    TEXT    NOT NULL DEFAULT '',
    kind           TEXT    NOT NULL,               -- root | intermediate
    parent_id      TEXT    REFERENCES authorities(id),
    status         TEXT    NOT NULL,               -- active | retiring | retired | revoked
    is_default     INTEGER NOT NULL DEFAULT 0,
    cert_pem       TEXT    NOT NULL,
    key_id         TEXT    NOT NULL REFERENCES ca_keys(id),
    ocsp_cert_pem  TEXT    NOT NULL DEFAULT '',
    ocsp_key_id    TEXT    REFERENCES ca_keys(id),
    serial         TEXT    NOT NULL,
    not_before     INTEGER NOT NULL,
    not_after      INTEGER NOT NULL,
    crl_number     INTEGER NOT NULL DEFAULT 0,
    crl_der        BLOB,
    crl_updated_at INTEGER NOT NULL DEFAULT 0,
    revoked_at     INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL
);
-- A slug belongs to exactly one active issuer; retiring issuers keep it for history.
CREATE UNIQUE INDEX authorities_active_slug ON authorities(slug) WHERE status = 'active';

CREATE TABLE policies (
    issuer_slug TEXT PRIMARY KEY,
    json        TEXT NOT NULL
);

CREATE TABLE acme_eab_keys (
    id               TEXT    PRIMARY KEY,
    issuer_slug      TEXT    NOT NULL,
    name             TEXT    NOT NULL,
    hmac_key         BLOB    NOT NULL,
    bound_account_id TEXT    NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    revoked_at       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE acme_accounts (
    id             TEXT    PRIMARY KEY,
    issuer_slug    TEXT    NOT NULL,
    jwk_thumbprint TEXT    NOT NULL,
    jwk_json       TEXT    NOT NULL,
    contacts       TEXT    NOT NULL DEFAULT '[]',
    status         TEXT    NOT NULL,      -- valid | deactivated | revoked
    eab_key_id     TEXT    NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);
CREATE UNIQUE INDEX acme_accounts_key ON acme_accounts(issuer_slug, jwk_thumbprint);

CREATE TABLE acme_nonces (
    nonce      TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE acme_orders (
    id             TEXT    PRIMARY KEY,
    account_id     TEXT    NOT NULL REFERENCES acme_accounts(id),
    issuer_slug    TEXT    NOT NULL,
    status         TEXT    NOT NULL,      -- pending | ready | processing | valid | invalid
    identifiers    TEXT    NOT NULL,      -- JSON [{type,value}]
    not_before     INTEGER NOT NULL DEFAULT 0,
    not_after      INTEGER NOT NULL DEFAULT 0,
    expires_at     INTEGER NOT NULL,
    error          TEXT    NOT NULL DEFAULT '',
    certificate_id TEXT    NOT NULL DEFAULT '',
    replaces       TEXT    NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);
CREATE INDEX acme_orders_account ON acme_orders(account_id);

CREATE TABLE acme_authzs (
    id         TEXT    PRIMARY KEY,
    order_id   TEXT    NOT NULL REFERENCES acme_orders(id),
    account_id TEXT    NOT NULL,
    id_type    TEXT    NOT NULL,
    id_value   TEXT    NOT NULL,
    wildcard   INTEGER NOT NULL DEFAULT 0,
    status     TEXT    NOT NULL,          -- pending | valid | invalid | deactivated | expired | revoked
    expires_at INTEGER NOT NULL
);
CREATE INDEX acme_authzs_order ON acme_authzs(order_id);

CREATE TABLE acme_challenges (
    id           TEXT    PRIMARY KEY,
    authz_id     TEXT    NOT NULL REFERENCES acme_authzs(id),
    type         TEXT    NOT NULL,
    token        TEXT    NOT NULL,
    status       TEXT    NOT NULL,        -- pending | processing | valid | invalid
    validated_at INTEGER NOT NULL DEFAULT 0,
    error        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX acme_challenges_authz ON acme_challenges(authz_id);

CREATE TABLE certificates (
    id                 TEXT    PRIMARY KEY,
    serial             TEXT    NOT NULL UNIQUE,
    issuer_id          TEXT    NOT NULL REFERENCES authorities(id),
    issuer_slug        TEXT    NOT NULL,
    account_id         TEXT    NOT NULL DEFAULT '',
    order_id           TEXT    NOT NULL DEFAULT '',
    source             TEXT    NOT NULL,  -- acme | manual | system
    common_name        TEXT    NOT NULL DEFAULT '',
    sans               TEXT    NOT NULL,  -- JSON array of strings
    key_algorithm      TEXT    NOT NULL DEFAULT '',
    fingerprint_sha256 TEXT    NOT NULL,
    aki                TEXT    NOT NULL DEFAULT '',
    cert_pem           TEXT    NOT NULL,
    chain_pem          TEXT    NOT NULL,
    not_before         INTEGER NOT NULL,
    not_after          INTEGER NOT NULL,
    status             TEXT    NOT NULL,  -- valid | revoked
    revoked_at         INTEGER NOT NULL DEFAULT 0,
    revocation_reason  INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL
);
CREATE INDEX certificates_issuer ON certificates(issuer_id);
CREATE INDEX certificates_not_after ON certificates(not_after);

CREATE TABLE notification_channels (
    id          TEXT    PRIMARY KEY,
    kind        TEXT    NOT NULL,         -- smtp | webhook
    name        TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE notification_log (
    subject   TEXT    NOT NULL,          -- certificate id or authority id
    threshold INTEGER NOT NULL,          -- days
    sent_at   INTEGER NOT NULL,
    PRIMARY KEY (subject, threshold)
);

CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      INTEGER NOT NULL,
    actor   TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    target  TEXT    NOT NULL DEFAULT '',
    details TEXT    NOT NULL DEFAULT '{}',
    ip      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log(at);
