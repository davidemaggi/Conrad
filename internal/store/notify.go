package store

import (
	"context"
	"time"
)

// Channel is a notification channel (smtp | webhook); ConfigJSON is owned by package notify.
type Channel struct {
	ID         string
	Kind       string
	Name       string
	Enabled    bool
	ConfigJSON string
	CreatedAt  time.Time
}

const chanCols = `id, kind, name, enabled, config_json, created_at`

func scanChannel(row interface{ Scan(...any) error }) (*Channel, error) {
	c := &Channel{}
	var en int
	var created int64
	if err := row.Scan(&c.ID, &c.Kind, &c.Name, &en, &c.ConfigJSON, &created); err != nil {
		return nil, notFound(err)
	}
	c.Enabled, c.CreatedAt = en == 1, fromTS(created)
	return c, nil
}

// InsertChannel stores a new channel (ID and CreatedAt are filled in).
func (s *Store) InsertChannel(ctx context.Context, c *Channel) error {
	c.ID, c.CreatedAt = NewID(), s.now()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO notification_channels (`+chanCols+`) VALUES (?,?,?,?,?,?)`,
		c.ID, c.Kind, c.Name, boolInt(c.Enabled), c.ConfigJSON, ts(c.CreatedAt))
	return err
}

// GetChannel loads a channel.
func (s *Store) GetChannel(ctx context.Context, id string) (*Channel, error) {
	return scanChannel(s.DB.QueryRowContext(ctx, `SELECT `+chanCols+` FROM notification_channels WHERE id=?`, id))
}

// ListChannels returns every channel, oldest first.
func (s *Store) ListChannels(ctx context.Context) ([]*Channel, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+chanCols+` FROM notification_channels ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateChannel saves name, enabled and config.
func (s *Store) UpdateChannel(ctx context.Context, c *Channel) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE notification_channels SET name=?, enabled=?, config_json=? WHERE id=?`,
		c.Name, boolInt(c.Enabled), c.ConfigJSON, c.ID)
	return affected(res, err)
}

// DeleteChannel removes a channel.
func (s *Store) DeleteChannel(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM notification_channels WHERE id=?`, id)
	return affected(res, err)
}

// MarkNotified records that subject was notified for threshold; false if it already was.
func (s *Store) MarkNotified(ctx context.Context, subject string, threshold int) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO notification_log (subject, threshold, sent_at) VALUES (?,?,?)`,
		subject, threshold, s.now().Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// UnmarkNotified forgets a dedupe record (used when every delivery failed).
func (s *Store) UnmarkNotified(ctx context.Context, subject string, threshold int) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM notification_log WHERE subject=? AND threshold=?`, subject, threshold)
	return err
}

func affected(res interface{ RowsAffected() (int64, error) }, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
