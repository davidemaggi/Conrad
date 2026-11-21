package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrAdminExists is returned when creating a second admin.
var ErrAdminExists = errors.New("admin already exists")

// Admin is the single administrator.
type Admin struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Language     string    `json:"language"`
	CreatedAt    time.Time `json:"createdAt"`
}

// GetAdmin returns the admin or ErrNotFound.
func (s *Store) GetAdmin(ctx context.Context) (*Admin, error) {
	a := &Admin{}
	var created int64
	err := s.DB.QueryRowContext(ctx, `SELECT username, password_hash, language, created_at FROM admin WHERE id=1`).
		Scan(&a.Username, &a.PasswordHash, &a.Language, &created)
	if err != nil {
		return nil, notFound(err)
	}
	a.CreatedAt = fromTS(created)
	return a, nil
}

// HasAdmin reports whether setup has created the admin.
func (s *Store) HasAdmin(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin`).Scan(&n)
	return n > 0, err
}

// CreateAdmin inserts the admin; fails with ErrAdminExists if one exists.
func (s *Store) CreateAdmin(ctx context.Context, a *Admin) error {
	a.CreatedAt = s.now()
	res, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO admin(id, username, password_hash, language, created_at) VALUES(1,?,?,?,?)`,
		a.Username, a.PasswordHash, a.Language, ts(a.CreatedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAdminExists
	}
	return nil
}

// UpdateAdmin persists username, password hash and language.
func (s *Store) UpdateAdmin(ctx context.Context, a *Admin) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE admin SET username=?, password_hash=?, language=? WHERE id=1`, a.Username, a.PasswordHash, a.Language)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Session is a logged-in browser session.
type Session struct {
	TokenHash []byte
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
	Method    string
}

// InsertSession stores a session.
func (s *Store) InsertSession(ctx context.Context, x *Session) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash, csrf_token, created_at, last_seen, expires_at, ip, user_agent, method) VALUES(?,?,?,?,?,?,?,?)`,
		x.TokenHash, x.CSRFToken, ts(x.CreatedAt), ts(x.LastSeen), ts(x.ExpiresAt), x.IP, x.UserAgent, x.Method)
	return err
}

// GetSession loads a session by token hash.
func (s *Store) GetSession(ctx context.Context, hash []byte) (*Session, error) {
	x := &Session{TokenHash: hash}
	var c, l, e int64
	err := s.DB.QueryRowContext(ctx, `SELECT csrf_token, created_at, last_seen, expires_at, ip, user_agent, method FROM sessions WHERE token_hash=?`, hash).
		Scan(&x.CSRFToken, &c, &l, &e, &x.IP, &x.UserAgent, &x.Method)
	if err != nil {
		return nil, notFound(err)
	}
	x.CreatedAt, x.LastSeen, x.ExpiresAt = fromTS(c), fromTS(l), fromTS(e)
	return x, nil
}

// TouchSession updates last_seen.
func (s *Store) TouchSession(ctx context.Context, hash []byte, t time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen=? WHERE token_hash=?`, ts(t), hash)
	return err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash)
	return err
}

// DeleteAllSessions logs everybody out.
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

// PurgeSessions removes sessions past their absolute expiry or idle cutoff.
func (s *Store) PurgeSessions(ctx context.Context, idleCutoff time.Time) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=? OR last_seen<=?`, ts(s.now()), ts(idleCutoff))
	return err
}

// AuditEntry is one append-only audit record.
type AuditEntry struct {
	ID      int64          `json:"id"`
	At      time.Time      `json:"at"`
	Actor   string         `json:"actor"`
	Action  string         `json:"action"`
	Target  string         `json:"target"`
	Details map[string]any `json:"details"`
	IP      string         `json:"ip"`
}

// InsertAudit appends an audit entry.
func (s *Store) InsertAudit(ctx context.Context, e *AuditEntry) error {
	if e.At.IsZero() {
		e.At = s.now()
	}
	d, _ := json.Marshal(e.Details)
	if e.Details == nil {
		d = []byte("{}")
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO audit_log(at, actor, action, target, details, ip) VALUES(?,?,?,?,?,?)`,
		ts(e.At), e.Actor, e.Action, e.Target, string(d), e.IP)
	if err == nil {
		e.ID, _ = res.LastInsertId()
	}
	return err
}

// ListAudit returns entries newest first, optionally filtered by action prefix.
func (s *Store) ListAudit(ctx context.Context, actionPrefix string, limit, offset int) ([]*AuditEntry, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	where, args := "", []any{}
	if actionPrefix != "" {
		where, args = ` WHERE action LIKE ?`, append(args, actionPrefix+"%")
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, at, actor, action, target, details, ip FROM audit_log`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var at int64
		var d string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &d, &e.IP); err != nil {
			return nil, 0, err
		}
		e.At = fromTS(at)
		_ = json.Unmarshal([]byte(d), &e.Details)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Backup writes a consistent copy of the database to path.
func (s *Store) Backup(ctx context.Context, path string) error {
	_, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

// Ping checks DB reachability.
func (s *Store) Ping(ctx context.Context) error { return s.DB.PingContext(ctx) }
