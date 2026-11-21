// Package notify sends expiry and lifecycle notifications by email (SMTP) and HMAC-signed webhooks.
package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/davidemaggi/conrad/internal/store"
)

// Event types.
const (
	CertExpiring = "cert.expiring"
	CertIssued   = "cert.issued"
	CertRevoked  = "cert.revoked"
	CAExpiring   = "ca.expiring"
	CALocked     = "ca.locked"
	ACMEFailed   = "acme.failed"
	Test         = "test"
)

// AllEvents lists subscribable events.
var AllEvents = []string{CertExpiring, CertIssued, CertRevoked, CAExpiring, CALocked, ACMEFailed}

// DefaultEvents is what a new channel subscribes to.
var DefaultEvents = []string{CertExpiring, CAExpiring, CALocked, ACMEFailed}

// SMTPConfig configures an email channel. Empty Username means no AUTH (internal relays).
type SMTPConfig struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Security   string   `json:"security"` // none | starttls | tls
	Username   string   `json:"username"`
	Password   string   `json:"password,omitempty"`
	AuthMethod string   `json:"authMethod"` // plain | login
	SkipVerify bool     `json:"skipVerify"`
	From       string   `json:"from"`
	To         []string `json:"to"`
}

// WebhookConfig configures a webhook channel.
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

// Channel is the decoded form of store.Channel.
type Channel struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"` // smtp | webhook
	Name     string         `json:"name"`
	Enabled  bool           `json:"enabled"`
	Events   []string       `json:"events"`
	SMTP     *SMTPConfig    `json:"smtp,omitempty"`
	Webhook  *WebhookConfig `json:"webhook,omitempty"`
	SecretOK bool           `json:"secretSet"` // password/secret is stored (never returned)
}

type channelConfig struct {
	Events  []string       `json:"events"`
	SMTP    *SMTPConfig    `json:"smtp,omitempty"`
	Webhook *WebhookConfig `json:"webhook,omitempty"`
}

// Decode converts a stored channel.
func Decode(sc *store.Channel) (*Channel, error) {
	var cfg channelConfig
	if err := json.Unmarshal([]byte(sc.ConfigJSON), &cfg); err != nil {
		return nil, fmt.Errorf("channel %s: %w", sc.ID, err)
	}
	return &Channel{ID: sc.ID, Kind: sc.Kind, Name: sc.Name, Enabled: sc.Enabled, Events: cfg.Events, SMTP: cfg.SMTP, Webhook: cfg.Webhook}, nil
}

// Encode converts to the stored form.
func (c *Channel) Encode() *store.Channel {
	b, _ := json.Marshal(channelConfig{Events: c.Events, SMTP: c.SMTP, Webhook: c.Webhook})
	return &store.Channel{ID: c.ID, Kind: c.Kind, Name: c.Name, Enabled: c.Enabled, ConfigJSON: string(b)}
}

// Redacted returns a copy without secrets, for the API.
func (c *Channel) Redacted() *Channel {
	r := *c
	if c.SMTP != nil {
		s := *c.SMTP
		r.SecretOK, s.Password = s.Password != "", ""
		r.SMTP = &s
	}
	if c.Webhook != nil {
		w := *c.Webhook
		r.SecretOK, w.Secret = w.Secret != "", ""
		r.Webhook = &w
	}
	return &r
}

// KeepSecrets copies secrets from old where c leaves them empty (API updates).
// Secrets are only reused for the same destination, so a stored password can't be redirected elsewhere.
func (c *Channel) KeepSecrets(old *Channel) {
	if c.SMTP != nil && old.SMTP != nil && c.SMTP.Password == "" &&
		c.SMTP.Username == old.SMTP.Username && strings.EqualFold(c.SMTP.Host, old.SMTP.Host) {
		c.SMTP.Password = old.SMTP.Password
	}
	if c.Webhook != nil && old.Webhook != nil && c.Webhook.Secret == "" && c.Webhook.URL == old.Webhook.URL {
		c.Webhook.Secret = old.Webhook.Secret
	}
}

// Subscribed reports whether the channel wants event typ (tests always go through).
func (c *Channel) Subscribed(typ string) bool {
	return typ == Test || slices.Contains(c.Events, typ)
}

// Normalize fills defaults and validates.
func (c *Channel) Normalize() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("name is required")
	}
	for _, e := range c.Events {
		if !slices.Contains(AllEvents, e) {
			return fmt.Errorf("unknown event %q", e)
		}
	}
	switch c.Kind {
	case "smtp":
		s := c.SMTP
		if s == nil {
			return errors.New("smtp settings are required")
		}
		c.Webhook = nil
		if s.Security == "" {
			s.Security = "starttls"
		}
		if s.Port == 0 {
			s.Port = map[string]int{"none": 25, "starttls": 587, "tls": 465}[s.Security]
		}
		if s.AuthMethod == "" {
			s.AuthMethod = "plain"
		}
		switch {
		case s.Host == "":
			return errors.New("smtp host is required")
		case s.Security != "none" && s.Security != "starttls" && s.Security != "tls":
			return errors.New("smtp security must be none, starttls or tls")
		case s.AuthMethod != "plain" && s.AuthMethod != "login":
			return errors.New("smtp authMethod must be plain or login")
		case s.Port < 1 || s.Port > 65535:
			return errors.New("invalid smtp port")
		}
		if _, err := mail.ParseAddress(s.From); err != nil {
			return fmt.Errorf("invalid from address: %w", err)
		}
		if len(s.To) == 0 {
			return errors.New("at least one recipient is required")
		}
		for _, t := range s.To {
			if _, err := mail.ParseAddress(t); err != nil {
				return fmt.Errorf("invalid recipient %q", t)
			}
		}
	case "webhook":
		w := c.Webhook
		if w == nil {
			return errors.New("webhook settings are required")
		}
		c.SMTP = nil
		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("webhook url must be an absolute http(s) URL")
		}
	default:
		return errors.New("kind must be smtp or webhook")
	}
	return nil
}
