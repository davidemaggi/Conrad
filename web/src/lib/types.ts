export interface SystemStatus {
  setupRequired: boolean;
  caInitialized: boolean;
  caLocked: boolean;
  authenticated: boolean;
  passwordLogin: boolean;
  oidcEnabled: boolean;
  keyProvider: string;
  defaultLanguage: string;
  version: string;
}

export interface Admin {
  username: string;
  language: string;
  createdAt: string;
}

export interface Me {
  admin: Admin;
  method: string;
  csrfToken: string;
  sessionExpires: string;
}

export interface Subject {
  commonName: string;
  organization: string;
  country: string;
}

export interface Authority {
  id: string;
  slug: string;
  name: string;
  description: string;
  kind: "root" | "intermediate";
  parentId: string;
  status: string;
  isDefault: boolean;
  subject: string;
  algorithm: string;
  serial: string;
  fingerprintSha256: string;
  notBefore: string;
  notAfter: string;
  revokedAt: string;
  createdAt: string;
  nameConstraints: string[] | null;
  certPem: string;
  directoryUrl: string;
  downloadUrl: string;
  crlUrl: string;
  crlUpdatedAt: string;
  activeCertificates: number;
}

export interface Policy {
  allowedDomains: string[];
  allowWildcards: boolean;
  allowIPs: boolean;
  defaultValidityDays: number;
  maxValidityDays: number;
  keyTypes: string[];
  challenges: string[];
  requireEAB: boolean;
  clientAuth: boolean;
  rateLimits: { ordersPerAccountPerHour: number; newAccountsPerIPPerHour: number };
}

export interface EABKey {
  id: string;
  issuerSlug: string;
  name: string;
  boundAccountId: string;
  createdAt: string;
  revokedAt: string;
}

export interface Certificate {
  id: string;
  serial: string;
  issuerId: string;
  issuerSlug: string;
  accountId: string;
  orderId: string;
  source: string;
  commonName: string;
  sans: string[] | null;
  keyAlgorithm: string;
  fingerprintSha256: string;
  aki: string;
  certPem: string;
  chainPem: string;
  notBefore: string;
  notAfter: string;
  status: string;
  revokedAt: string;
  revocationReason: number;
  createdAt: string;
}

export interface Account {
  id: string;
  issuerSlug: string;
  jwkThumbprint: string;
  contacts: string[] | null;
  status: string;
  eabKeyId: string;
  createdAt: string;
  orderCount: number;
  certCount: number;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  details: Record<string, unknown> | null;
  ip: string;
}

export interface Dashboard {
  stats: { active: number; expiring: number; expired: number; revoked: number };
  accounts: number;
  expiring: Certificate[];
  recentActivity: AuditEntry[];
  authorities: Authority[] | null;
  caLocked: boolean;
}

export interface SMTPConfig {
  host: string;
  port: number;
  security: "none" | "starttls" | "tls";
  username: string;
  password?: string;
  authMethod: "plain" | "login";
  skipVerify: boolean;
  from: string;
  to: string[];
}

export interface Channel {
  id: string;
  kind: "smtp" | "webhook";
  name: string;
  enabled: boolean;
  events: string[];
  smtp?: SMTPConfig;
  webhook?: { url: string; secret?: string };
  secretSet: boolean;
}

export interface AuthSettings {
  passwordLoginEnabled: boolean;
  oidc: {
    enabled: boolean;
    issuer: string;
    clientId: string;
    clientSecret?: string;
    allowedSubject: string;
    allowedEmail: string;
  };
  oidcClientSecretSet?: boolean;
  oidcRedirectUrl?: string;
}

export interface SystemInfo {
  version: string;
  goVersion: string;
  os: string;
  uptimeSec: number;
  startedAt: string;
  baseUrl: string;
  dataDir: string;
  keyProvider: string;
  caLocked: boolean;
}

export const KEY_TYPES = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ed25519"] as const;
export const CA_ALGORITHMS = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export const CHALLENGES = ["http-01", "dns-01", "tls-alpn-01"] as const;
export const REVOCATION_REASONS: Record<number, string> = {
  0: "unspecified",
  1: "keyCompromise",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  9: "privilegeWithdrawn",
};
