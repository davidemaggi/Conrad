package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Certificate statuses (expiry is derived from NotAfter, not stored).
const (
	CertValid   = "valid"
	CertRevoked = "revoked"
)

// Certificate is an issued leaf certificate.
type Certificate struct {
	ID               string    `json:"id"`
	Serial           string    `json:"serial"`
	IssuerID         string    `json:"issuerId"`
	IssuerSlug       string    `json:"issuerSlug"`
	AccountID        string    `json:"accountId"`
	OrderID          string    `json:"orderId"`
	Source           string    `json:"source"`
	CommonName       string    `json:"commonName"`
	SANs             []string  `json:"sans"`
	KeyAlgorithm     string    `json:"keyAlgorithm"`
	Fingerprint      string    `json:"fingerprintSha256"`
	AKI              string    `json:"aki"`
	CertPEM          string    `json:"certPem"`
	ChainPEM         string    `json:"chainPem"`
	NotBefore        time.Time `json:"notBefore"`
	NotAfter         time.Time `json:"notAfter"`
	Status           string    `json:"status"`
	RevokedAt        time.Time `json:"revokedAt"`
	RevocationReason int       `json:"revocationReason"`
	CreatedAt        time.Time `json:"createdAt"`
}

const certCols = `id, serial, issuer_id, issuer_slug, account_id, order_id, source, common_name, sans, key_algorithm,
	fingerprint_sha256, aki, cert_pem, chain_pem, not_before, not_after, status, revoked_at, revocation_reason, created_at`

func scanCert(row interface{ Scan(...any) error }) (*Certificate, error) {
	c := &Certificate{}
	var sans string
	var nb, na, rev, created int64
	err := row.Scan(&c.ID, &c.Serial, &c.IssuerID, &c.IssuerSlug, &c.AccountID, &c.OrderID, &c.Source, &c.CommonName, &sans,
		&c.KeyAlgorithm, &c.Fingerprint, &c.AKI, &c.CertPEM, &c.ChainPEM, &nb, &na, &c.Status, &rev, &c.RevocationReason, &created)
	if err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(sans), &c.SANs)
	c.NotBefore, c.NotAfter, c.RevokedAt, c.CreatedAt = fromTS(nb), fromTS(na), fromTS(rev), fromTS(created)
	return c, nil
}

// InsertCertificate stores a newly issued certificate.
func (s *Store) InsertCertificate(ctx context.Context, c *Certificate) error {
	if c.ID == "" {
		c.ID = NewID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = s.now()
	}
	if c.Status == "" {
		c.Status = CertValid
	}
	sans, _ := json.Marshal(c.SANs)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO certificates(`+certCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Serial, c.IssuerID, c.IssuerSlug, c.AccountID, c.OrderID, c.Source, c.CommonName, string(sans), c.KeyAlgorithm,
		c.Fingerprint, c.AKI, c.CertPEM, c.ChainPEM, ts(c.NotBefore), ts(c.NotAfter), c.Status, ts(c.RevokedAt), c.RevocationReason, ts(c.CreatedAt))
	return err
}

// GetCertificate loads a certificate by id.
func (s *Store) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	return scanCert(s.DB.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE id = ?`, id))
}

// GetCertificateBySerial loads a certificate by hex serial.
func (s *Store) GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error) {
	return scanCert(s.DB.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE serial = ?`, strings.ToLower(serial)))
}

// CertFilter narrows ListCertificates.
type CertFilter struct {
	Status     string // valid | revoked | expiring | expired | "" (all)
	IssuerSlug string
	AccountID  string
	Query      string // substring match on common name / SANs / serial
	Within     time.Duration
	Limit      int
	Offset     int
}

// ListCertificates returns certificates matching f, soonest expiry first, plus the total count.
func (s *Store) ListCertificates(ctx context.Context, f CertFilter) ([]*Certificate, int, error) {
	where := []string{"1=1"}
	var args []any
	now := s.now().Unix()
	switch f.Status {
	case CertValid:
		where = append(where, "status = 'valid' AND not_after > ?")
		args = append(args, now)
	case CertRevoked:
		where = append(where, "status = 'revoked'")
	case "expiring":
		within := f.Within
		if within == 0 {
			within = 14 * 24 * time.Hour
		}
		where = append(where, "status = 'valid' AND not_after > ? AND not_after <= ?")
		args = append(args, now, now+int64(within.Seconds()))
	case "expired":
		where = append(where, "status = 'valid' AND not_after <= ?")
		args = append(args, now)
	}
	if f.IssuerSlug != "" {
		where = append(where, "issuer_slug = ?")
		args = append(args, f.IssuerSlug)
	}
	if f.AccountID != "" {
		where = append(where, "account_id = ?")
		args = append(args, f.AccountID)
	}
	if f.Query != "" {
		q := "%" + strings.ToLower(f.Query) + "%"
		where = append(where, "(lower(common_name) LIKE ? OR lower(sans) LIKE ? OR serial LIKE ?)")
		args = append(args, q, q, q)
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+certCols+` FROM certificates WHERE `+cond+` ORDER BY not_after ASC LIMIT ? OFFSET ?`,
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// RevokeCertificate marks a certificate revoked. Returns ErrNotFound if it
// does not exist or is already revoked.
func (s *Store) RevokeCertificate(ctx context.Context, id string, reason int, at time.Time) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE certificates SET status='revoked', revoked_at=?, revocation_reason=? WHERE id=? AND status='valid'`,
		ts(at), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAllByIssuer revokes every valid certificate signed by issuerID.
func (s *Store) RevokeAllByIssuer(ctx context.Context, issuerID string, reason int, at time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE certificates SET status='revoked', revoked_at=?, revocation_reason=? WHERE issuer_id=? AND status='valid'`,
		ts(at), reason, issuerID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokedEntry is a CRL entry.
type RevokedEntry struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

// RevokedByIssuer lists revoked, not-yet-expired certificates of an issuer.
func (s *Store) RevokedByIssuer(ctx context.Context, issuerID string) ([]RevokedEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT serial, revoked_at, revocation_reason FROM certificates
		WHERE issuer_id = ? AND status = 'revoked' AND not_after > ?`, issuerID, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedEntry
	for rows.Next() {
		var e RevokedEntry
		var at int64
		if err := rows.Scan(&e.Serial, &at, &e.Reason); err != nil {
			return nil, err
		}
		e.RevokedAt = fromTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// LatestValidExpiry returns the max not_after of valid certs for an issuer (zero if none).
func (s *Store) LatestValidExpiry(ctx context.Context, issuerID string) (time.Time, error) {
	var v int64
	err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(not_after),0) FROM certificates WHERE issuer_id = ? AND status='valid'`, issuerID).Scan(&v)
	return fromTS(v), err
}

// CertStats summarizes certificates for the dashboard.
type CertStats struct {
	Active   int `json:"active"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
	Revoked  int `json:"revoked"`
}

// CertificateStats counts certificates by state; expiring = within window.
func (s *Store) CertificateStats(ctx context.Context, window time.Duration) (CertStats, error) {
	now := s.now().Unix()
	var st CertStats
	err := s.DB.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(status='valid' AND not_after > ?),0),
		COALESCE(SUM(status='valid' AND not_after > ? AND not_after <= ?),0),
		COALESCE(SUM(status='valid' AND not_after <= ?),0),
		COALESCE(SUM(status='revoked'),0)
		FROM certificates`, now, now, now+int64(window.Seconds()), now).Scan(&st.Active, &st.Expiring, &st.Expired, &st.Revoked)
	return st, err
}

// CountByIssuer returns valid certificate counts keyed by issuer id.
func (s *Store) CountByIssuer(ctx context.Context) (map[string]int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT issuer_id, COUNT(*) FROM certificates WHERE status='valid' AND not_after > ? GROUP BY issuer_id`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
