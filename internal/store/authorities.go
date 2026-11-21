package store

import (
	"context"
	"database/sql"
	"time"
)

// Authority kinds and statuses.
const (
	KindRoot         = "root"
	KindIntermediate = "intermediate"

	StatusActive   = "active"
	StatusRetiring = "retiring"
	StatusRetired  = "retired"
	StatusRevoked  = "revoked"
)

// CAKey is a persisted CA key reference.
type CAKey struct {
	ID        string
	Provider  string
	Algorithm string
	Blob      []byte
	CreatedAt time.Time
}

// Authority is a root or intermediate ("issuer") CA.
type Authority struct {
	ID           string
	Slug         string
	Name         string
	Description  string
	Kind         string
	ParentID     string
	Status       string
	IsDefault    bool
	CertPEM      string
	KeyID        string
	OCSPCertPEM  string
	OCSPKeyID    string
	Serial       string
	NotBefore    time.Time
	NotAfter     time.Time
	CRLNumber    int64
	CRLDER       []byte
	CRLUpdatedAt time.Time
	RevokedAt    time.Time
	CreatedAt    time.Time
}

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromTS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// InsertKey stores a CA key.
func (s *Store) InsertKey(ctx context.Context, k *CAKey) error {
	if k.ID == "" {
		k.ID = NewID()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = s.now()
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO ca_keys(id, provider, algorithm, blob, created_at) VALUES(?,?,?,?,?)`,
		k.ID, k.Provider, k.Algorithm, k.Blob, ts(k.CreatedAt))
	return err
}

// GetKey loads a CA key.
func (s *Store) GetKey(ctx context.Context, id string) (*CAKey, error) {
	k := &CAKey{}
	var created int64
	err := s.DB.QueryRowContext(ctx, `SELECT id, provider, algorithm, blob, created_at FROM ca_keys WHERE id = ?`, id).
		Scan(&k.ID, &k.Provider, &k.Algorithm, &k.Blob, &created)
	if err != nil {
		return nil, notFound(err)
	}
	k.CreatedAt = fromTS(created)
	return k, nil
}

const authorityCols = `id, slug, name, description, kind, COALESCE(parent_id,''), status, is_default, cert_pem, key_id,
	ocsp_cert_pem, COALESCE(ocsp_key_id,''), serial, not_before, not_after, crl_number, crl_der, crl_updated_at, revoked_at, created_at`

func scanAuthority(row interface{ Scan(...any) error }) (*Authority, error) {
	a := &Authority{}
	var nb, na, crlAt, revAt, created int64
	var isDef int
	err := row.Scan(&a.ID, &a.Slug, &a.Name, &a.Description, &a.Kind, &a.ParentID, &a.Status, &isDef, &a.CertPEM, &a.KeyID,
		&a.OCSPCertPEM, &a.OCSPKeyID, &a.Serial, &nb, &na, &a.CRLNumber, &a.CRLDER, &crlAt, &revAt, &created)
	if err != nil {
		return nil, notFound(err)
	}
	a.IsDefault = isDef == 1
	a.NotBefore, a.NotAfter, a.CRLUpdatedAt, a.RevokedAt, a.CreatedAt = fromTS(nb), fromTS(na), fromTS(crlAt), fromTS(revAt), fromTS(created)
	return a, nil
}

// InsertAuthority stores a new authority.
func (s *Store) InsertAuthority(ctx context.Context, a *Authority) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = s.now()
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO authorities(id, slug, name, description, kind, parent_id, status, is_default,
		cert_pem, key_id, ocsp_cert_pem, ocsp_key_id, serial, not_before, not_after, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Slug, a.Name, a.Description, a.Kind, nullStr(a.ParentID), a.Status, boolInt(a.IsDefault),
		a.CertPEM, a.KeyID, a.OCSPCertPEM, nullStr(a.OCSPKeyID), a.Serial, ts(a.NotBefore), ts(a.NotAfter), ts(a.CreatedAt))
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetAuthority loads an authority by id.
func (s *Store) GetAuthority(ctx context.Context, id string) (*Authority, error) {
	return scanAuthority(s.DB.QueryRowContext(ctx, `SELECT `+authorityCols+` FROM authorities WHERE id = ?`, id))
}

// ActiveIssuer returns the active intermediate holding slug.
func (s *Store) ActiveIssuer(ctx context.Context, slug string) (*Authority, error) {
	return scanAuthority(s.DB.QueryRowContext(ctx,
		`SELECT `+authorityCols+` FROM authorities WHERE slug = ? AND kind = 'intermediate' AND status = 'active'`, slug))
}

// DefaultIssuer returns the active default intermediate.
func (s *Store) DefaultIssuer(ctx context.Context) (*Authority, error) {
	return scanAuthority(s.DB.QueryRowContext(ctx,
		`SELECT `+authorityCols+` FROM authorities WHERE kind = 'intermediate' AND status = 'active' AND is_default = 1`))
}

// ActiveRoot returns the active root (the newest one if several exist).
func (s *Store) ActiveRoot(ctx context.Context) (*Authority, error) {
	return scanAuthority(s.DB.QueryRowContext(ctx,
		`SELECT `+authorityCols+` FROM authorities WHERE kind = 'root' AND status = 'active' ORDER BY not_after DESC LIMIT 1`))
}

// ListAuthorities returns every authority, roots first, newest first.
func (s *Store) ListAuthorities(ctx context.Context) ([]*Authority, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+authorityCols+` FROM authorities ORDER BY kind DESC, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Authority
	for rows.Next() {
		a, err := scanAuthority(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// HasAuthorities reports whether the CA has been initialized.
func (s *Store) HasAuthorities(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorities`).Scan(&n)
	return n > 0, err
}

// UpdateAuthority persists mutable fields (name, description, status, default, revoked_at).
func (s *Store) UpdateAuthority(ctx context.Context, a *Authority) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE authorities SET name=?, description=?, status=?, is_default=?, revoked_at=? WHERE id=?`,
		a.Name, a.Description, a.Status, boolInt(a.IsDefault), ts(a.RevokedAt), a.ID)
	return err
}

// SetDefaultIssuer marks id as the only default issuer.
func (s *Store) SetDefaultIssuer(ctx context.Context, id string) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE authorities SET is_default = 0 WHERE kind = 'intermediate'`); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE authorities SET is_default = 1 WHERE id = ? AND kind = 'intermediate' AND status = 'active'`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// UpdateCRL stores a freshly generated CRL.
func (s *Store) UpdateCRL(ctx context.Context, id string, number int64, der []byte, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE authorities SET crl_number=?, crl_der=?, crl_updated_at=? WHERE id=?`, number, der, ts(at), id)
	return err
}

// GetPolicyJSON returns the raw policy JSON for an issuer slug.
func (s *Store) GetPolicyJSON(ctx context.Context, slug string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT json FROM policies WHERE issuer_slug = ?`, slug).Scan(&v)
	return v, notFound(err)
}

// SetPolicyJSON upserts the policy JSON for an issuer slug.
func (s *Store) SetPolicyJSON(ctx context.Context, slug, v string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO policies(issuer_slug, json) VALUES(?,?)
		ON CONFLICT(issuer_slug) DO UPDATE SET json = excluded.json`, slug, v)
	return err
}
