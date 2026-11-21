package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Account is an ACME account bound to one issuer slug.
type Account struct {
	ID            string    `json:"id"`
	IssuerSlug    string    `json:"issuerSlug"`
	JWKThumbprint string    `json:"jwkThumbprint"`
	JWKJSON       string    `json:"-"`
	Contacts      []string  `json:"contacts"`
	Status        string    `json:"status"`
	EABKeyID      string    `json:"eabKeyId"`
	CreatedAt     time.Time `json:"createdAt"`
	OrderCount    int       `json:"orderCount"`
	CertCount     int       `json:"certCount"`
}

// EABKey is an External Account Binding key.
type EABKey struct {
	ID             string    `json:"id"`
	IssuerSlug     string    `json:"issuerSlug"`
	Name           string    `json:"name"`
	HMACKey        []byte    `json:"-"`
	BoundAccountID string    `json:"boundAccountId"`
	CreatedAt      time.Time `json:"createdAt"`
	RevokedAt      time.Time `json:"revokedAt"`
}

// Identifier is an ACME identifier.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order is an ACME order.
type Order struct {
	ID            string
	AccountID     string
	IssuerSlug    string
	Status        string
	Identifiers   []Identifier
	NotBefore     time.Time
	NotAfter      time.Time
	ExpiresAt     time.Time
	Error         string // JSON problem document
	CertificateID string
	Replaces      string
	CreatedAt     time.Time
}

// Authz is an ACME authorization.
type Authz struct {
	ID        string
	OrderID   string
	AccountID string
	IDType    string
	IDValue   string
	Wildcard  bool
	Status    string
	ExpiresAt time.Time
}

// Challenge is an ACME challenge.
type Challenge struct {
	ID          string
	AuthzID     string
	Type        string
	Token       string
	Status      string
	ValidatedAt time.Time
	Error       string // JSON problem document
}

// ---- accounts ----

const accountCols = `id, issuer_slug, jwk_thumbprint, jwk_json, contacts, status, eab_key_id, created_at`

func scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	a := &Account{}
	var contacts string
	var created int64
	if err := row.Scan(&a.ID, &a.IssuerSlug, &a.JWKThumbprint, &a.JWKJSON, &contacts, &a.Status, &a.EABKeyID, &created); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(contacts), &a.Contacts)
	a.CreatedAt = fromTS(created)
	return a, nil
}

// InsertAccount creates an account; if eabKeyID is set the key is bound atomically.
func (s *Store) InsertAccount(ctx context.Context, a *Account) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	a.CreatedAt = s.now()
	contacts, _ := json.Marshal(nonNil(a.Contacts))
	return s.Tx(ctx, func(tx *sql.Tx) error {
		if a.EABKeyID != "" {
			res, err := tx.ExecContext(ctx, `UPDATE acme_eab_keys SET bound_account_id=? WHERE id=? AND bound_account_id='' AND revoked_at=0`, a.ID, a.EABKeyID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO acme_accounts(`+accountCols+`) VALUES(?,?,?,?,?,?,?,?)`,
			a.ID, a.IssuerSlug, a.JWKThumbprint, a.JWKJSON, string(contacts), a.Status, a.EABKeyID, ts(a.CreatedAt))
		return err
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetAccount loads an account.
func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM acme_accounts WHERE id=?`, id))
}

// AccountByThumbprint finds an account by key thumbprint within an issuer slug.
func (s *Store) AccountByThumbprint(ctx context.Context, slug, thumb string) (*Account, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM acme_accounts WHERE issuer_slug=? AND jwk_thumbprint=?`, slug, thumb))
}

// UpdateAccount persists contacts, status and key.
func (s *Store) UpdateAccount(ctx context.Context, a *Account) error {
	contacts, _ := json.Marshal(nonNil(a.Contacts))
	_, err := s.DB.ExecContext(ctx, `UPDATE acme_accounts SET contacts=?, status=?, jwk_thumbprint=?, jwk_json=? WHERE id=?`,
		string(contacts), a.Status, a.JWKThumbprint, a.JWKJSON, a.ID)
	return err
}

// ListAccounts returns accounts (optionally for one slug) with counts.
func (s *Store) ListAccounts(ctx context.Context, slug string) ([]*Account, error) {
	q := `SELECT ` + accountCols + `,
		(SELECT COUNT(*) FROM acme_orders o WHERE o.account_id = acme_accounts.id),
		(SELECT COUNT(*) FROM certificates c WHERE c.account_id = acme_accounts.id)
		FROM acme_accounts`
	var args []any
	if slug != "" {
		q += ` WHERE issuer_slug=?`
		args = append(args, slug)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a := &Account{}
		var contacts string
		var created int64
		if err := rows.Scan(&a.ID, &a.IssuerSlug, &a.JWKThumbprint, &a.JWKJSON, &contacts, &a.Status, &a.EABKeyID, &created, &a.OrderCount, &a.CertCount); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(contacts), &a.Contacts)
		a.CreatedAt = fromTS(created)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAccounts returns the number of valid accounts.
func (s *Store) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM acme_accounts WHERE status='valid'`).Scan(&n)
	return n, err
}

// ---- EAB ----

// CreateEABKey generates a new 256-bit HMAC key.
func (s *Store) CreateEABKey(ctx context.Context, slug, name string) (*EABKey, error) {
	k := &EABKey{ID: NewID(), IssuerSlug: slug, Name: name, HMACKey: make([]byte, 32), CreatedAt: s.now()}
	if _, err := rand.Read(k.HMACKey); err != nil {
		return nil, err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO acme_eab_keys(id, issuer_slug, name, hmac_key, created_at) VALUES(?,?,?,?,?)`,
		k.ID, k.IssuerSlug, k.Name, k.HMACKey, ts(k.CreatedAt))
	return k, err
}

// EncodedHMAC returns the key as base64url, as expected by ACME clients.
func (k *EABKey) EncodedHMAC() string { return base64.RawURLEncoding.EncodeToString(k.HMACKey) }

// GetEABKey loads an EAB key.
func (s *Store) GetEABKey(ctx context.Context, id string) (*EABKey, error) {
	k := &EABKey{}
	var created, revoked int64
	err := s.DB.QueryRowContext(ctx, `SELECT id, issuer_slug, name, hmac_key, bound_account_id, created_at, revoked_at FROM acme_eab_keys WHERE id=?`, id).
		Scan(&k.ID, &k.IssuerSlug, &k.Name, &k.HMACKey, &k.BoundAccountID, &created, &revoked)
	if err != nil {
		return nil, notFound(err)
	}
	k.CreatedAt, k.RevokedAt = fromTS(created), fromTS(revoked)
	return k, nil
}

// ListEABKeys lists EAB keys for a slug.
func (s *Store) ListEABKeys(ctx context.Context, slug string) ([]*EABKey, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, issuer_slug, name, bound_account_id, created_at, revoked_at FROM acme_eab_keys WHERE issuer_slug=? ORDER BY created_at DESC`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EABKey
	for rows.Next() {
		k := &EABKey{}
		var created, revoked int64
		if err := rows.Scan(&k.ID, &k.IssuerSlug, &k.Name, &k.BoundAccountID, &created, &revoked); err != nil {
			return nil, err
		}
		k.CreatedAt, k.RevokedAt = fromTS(created), fromTS(revoked)
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeEABKey marks an EAB key unusable.
func (s *Store) RevokeEABKey(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE acme_eab_keys SET revoked_at=? WHERE id=? AND revoked_at=0`, ts(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- nonces ----

// NewNonce creates and stores a nonce valid for ttl.
func (s *Store) NewNonce(ctx context.Context, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO acme_nonces(nonce, expires_at) VALUES(?,?)`, n, s.now().Add(ttl).Unix())
	return n, err
}

// ConsumeNonce deletes a valid nonce; returns false if unknown/expired/used.
func (s *Store) ConsumeNonce(ctx context.Context, n string) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM acme_nonces WHERE nonce=? AND expires_at>?`, n, s.now().Unix())
	if err != nil {
		return false, err
	}
	c, _ := res.RowsAffected()
	return c == 1, nil
}

// PurgeNonces removes expired nonces.
func (s *Store) PurgeNonces(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM acme_nonces WHERE expires_at<=?`, s.now().Unix())
	return err
}

// ---- orders / authzs / challenges ----

// CreateOrder inserts an order with its authorizations and challenges atomically.
func (s *Store) CreateOrder(ctx context.Context, o *Order, authzs []*Authz, chals [][]*Challenge) error {
	o.ID = NewID()
	o.CreatedAt = s.now()
	ids, _ := json.Marshal(o.Identifiers)
	return s.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO acme_orders(id, account_id, issuer_slug, status, identifiers, not_before, not_after, expires_at, replaces, created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, o.ID, o.AccountID, o.IssuerSlug, o.Status, string(ids), ts(o.NotBefore), ts(o.NotAfter), ts(o.ExpiresAt), o.Replaces, ts(o.CreatedAt)); err != nil {
			return err
		}
		for i, a := range authzs {
			a.ID = NewID()
			a.OrderID = o.ID
			if _, err := tx.ExecContext(ctx, `INSERT INTO acme_authzs(id, order_id, account_id, id_type, id_value, wildcard, status, expires_at) VALUES(?,?,?,?,?,?,?,?)`,
				a.ID, a.OrderID, a.AccountID, a.IDType, a.IDValue, boolInt(a.Wildcard), a.Status, ts(a.ExpiresAt)); err != nil {
				return err
			}
			for _, c := range chals[i] {
				c.ID = NewID()
				c.AuthzID = a.ID
				if _, err := tx.ExecContext(ctx, `INSERT INTO acme_challenges(id, authz_id, type, token, status) VALUES(?,?,?,?,?)`,
					c.ID, c.AuthzID, c.Type, c.Token, c.Status); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

const orderCols = `id, account_id, issuer_slug, status, identifiers, not_before, not_after, expires_at, error, certificate_id, replaces, created_at`

func scanOrder(row interface{ Scan(...any) error }) (*Order, error) {
	o := &Order{}
	var ids string
	var nb, na, exp, created int64
	if err := row.Scan(&o.ID, &o.AccountID, &o.IssuerSlug, &o.Status, &ids, &nb, &na, &exp, &o.Error, &o.CertificateID, &o.Replaces, &created); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(ids), &o.Identifiers)
	o.NotBefore, o.NotAfter, o.ExpiresAt, o.CreatedAt = fromTS(nb), fromTS(na), fromTS(exp), fromTS(created)
	return o, nil
}

// GetOrder loads an order.
func (s *Store) GetOrder(ctx context.Context, id string) (*Order, error) {
	return scanOrder(s.DB.QueryRowContext(ctx, `SELECT `+orderCols+` FROM acme_orders WHERE id=?`, id))
}

// ListOrderIDs returns order ids for an account, newest first.
func (s *Store) ListOrderIDs(ctx context.Context, accountID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM acme_orders WHERE account_id=? AND status IN ('pending','ready','processing') ORDER BY created_at DESC LIMIT 1000`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CountOrdersSince counts orders created by an account since t.
func (s *Store) CountOrdersSince(ctx context.Context, accountID string, t time.Time) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM acme_orders WHERE account_id=? AND created_at>=?`, accountID, t.Unix()).Scan(&n)
	return n, err
}

// UpdateOrder persists status, error and certificate id.
func (s *Store) UpdateOrder(ctx context.Context, o *Order) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE acme_orders SET status=?, error=?, certificate_id=? WHERE id=?`, o.Status, o.Error, o.CertificateID, o.ID)
	return err
}

// TransitionOrder atomically changes status from -> to; returns false if not in from.
func (s *Store) TransitionOrder(ctx context.Context, id, from, to string) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE acme_orders SET status=? WHERE id=? AND status=?`, to, id, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

const authzCols = `id, order_id, account_id, id_type, id_value, wildcard, status, expires_at`

func scanAuthz(row interface{ Scan(...any) error }) (*Authz, error) {
	a := &Authz{}
	var wc int
	var exp int64
	if err := row.Scan(&a.ID, &a.OrderID, &a.AccountID, &a.IDType, &a.IDValue, &wc, &a.Status, &exp); err != nil {
		return nil, notFound(err)
	}
	a.Wildcard, a.ExpiresAt = wc == 1, fromTS(exp)
	return a, nil
}

// GetAuthz loads an authorization.
func (s *Store) GetAuthz(ctx context.Context, id string) (*Authz, error) {
	return scanAuthz(s.DB.QueryRowContext(ctx, `SELECT `+authzCols+` FROM acme_authzs WHERE id=?`, id))
}

// AuthzsForOrder lists an order's authorizations.
func (s *Store) AuthzsForOrder(ctx context.Context, orderID string) ([]*Authz, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+authzCols+` FROM acme_authzs WHERE order_id=? ORDER BY rowid`, orderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Authz
	for rows.Next() {
		a, err := scanAuthz(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAuthzStatus sets an authorization status.
func (s *Store) UpdateAuthzStatus(ctx context.Context, id, status string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE acme_authzs SET status=? WHERE id=?`, status, id)
	return err
}

const chalCols = `id, authz_id, type, token, status, validated_at, error`

func scanChal(row interface{ Scan(...any) error }) (*Challenge, error) {
	c := &Challenge{}
	var v int64
	if err := row.Scan(&c.ID, &c.AuthzID, &c.Type, &c.Token, &c.Status, &v, &c.Error); err != nil {
		return nil, notFound(err)
	}
	c.ValidatedAt = fromTS(v)
	return c, nil
}

// GetChallenge loads a challenge.
func (s *Store) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	return scanChal(s.DB.QueryRowContext(ctx, `SELECT `+chalCols+` FROM acme_challenges WHERE id=?`, id))
}

// ChallengesForAuthz lists an authorization's challenges.
func (s *Store) ChallengesForAuthz(ctx context.Context, authzID string) ([]*Challenge, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+chalCols+` FROM acme_challenges WHERE authz_id=? ORDER BY rowid`, authzID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Challenge
	for rows.Next() {
		c, err := scanChal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TransitionChallenge atomically moves a challenge from -> to.
func (s *Store) TransitionChallenge(ctx context.Context, id, from, to string) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE acme_challenges SET status=? WHERE id=? AND status=?`, to, id, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// FinishChallenge records the validation outcome.
func (s *Store) FinishChallenge(ctx context.Context, id, status, problem string) error {
	var v int64
	if status == "valid" {
		v = s.now().Unix()
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE acme_challenges SET status=?, error=?, validated_at=? WHERE id=?`, status, problem, v, id)
	return err
}

// ProcessingChallenges returns challenges left in "processing" (e.g. after a restart).
func (s *Store) ProcessingChallenges(ctx context.Context) ([]*Challenge, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+chalCols+` FROM acme_challenges WHERE status='processing'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Challenge
	for rows.Next() {
		c, err := scanChal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CertificateByOrder returns the certificate issued for an order.
func (s *Store) CertificateByOrder(ctx context.Context, orderID string) (*Certificate, error) {
	return scanCert(s.DB.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE order_id=?`, orderID))
}
