package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/davidemaggi/conrad/internal/store"
)

// OIDCConfig is stored in the "oidc.config" setting.
type OIDCConfig struct {
	Enabled        bool   `json:"enabled"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	AllowedSubject string `json:"allowedSubject"`
	AllowedEmail   string `json:"allowedEmail"`
}

const oidcSetting = "oidc.config"

// Validate checks required fields when enabled.
func (c OIDCConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Issuer == "" || c.ClientID == "" {
		return errors.New("issuer and clientId are required")
	}
	if c.AllowedSubject == "" && c.AllowedEmail == "" {
		return errors.New("allowedSubject or allowedEmail is required")
	}
	return nil
}

// LoadOIDC reads the OIDC configuration.
func LoadOIDC(ctx context.Context, st *store.Store) (OIDCConfig, error) {
	var c OIDCConfig
	raw, err := st.GetSetting(ctx, oidcSetting)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal([]byte(raw), &c)
}

// SaveOIDC stores the OIDC configuration; an empty secret keeps the previous one.
func SaveOIDC(ctx context.Context, st *store.Store, c OIDCConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ClientSecret == "" {
		if old, err := LoadOIDC(ctx, st); err == nil {
			c.ClientSecret = old.ClientSecret
		}
	}
	b, _ := json.Marshal(c)
	return st.SetSetting(ctx, oidcSetting, string(b))
}

// OIDC runs the authorization code + PKCE flow.
type OIDC struct {
	Store       *store.Store
	RedirectURL string

	mu      sync.Mutex
	pending map[string]pendingAuth
	prov    *oidc.Provider
	provIss string
}

type pendingAuth struct {
	verifier, nonce string
	expires         time.Time
}

// NewOIDC creates the flow handler.
func NewOIDC(st *store.Store, redirectURL string) *OIDC {
	return &OIDC{Store: st, RedirectURL: redirectURL, pending: map[string]pendingAuth{}}
}

func (o *OIDC) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.prov != nil && o.provIss == issuer {
		return o.prov, nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	o.prov, o.provIss = p, issuer
	return p, nil
}

func (o *OIDC) oauth(p *oidc.Provider, c OIDCConfig) *oauth2.Config {
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: o.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
}

// AuthURL starts a login and returns the provider URL to redirect to.
func (o *OIDC) AuthURL(ctx context.Context) (string, error) {
	c, err := LoadOIDC(ctx, o.Store)
	if err != nil {
		return "", err
	}
	if !c.Enabled {
		return "", errors.New("OIDC is not enabled")
	}
	p, err := o.provider(ctx, c.Issuer)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery failed: %w", err)
	}
	state, nonce, verifier := RandomToken(24), RandomToken(24), oauth2.GenerateVerifier()
	o.mu.Lock()
	now := time.Now()
	for k, v := range o.pending {
		if now.After(v.expires) {
			delete(o.pending, k)
		}
	}
	o.pending[state] = pendingAuth{verifier: verifier, nonce: nonce, expires: now.Add(10 * time.Minute)}
	o.mu.Unlock()
	return o.oauth(p, c).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

// Identity is the verified OIDC user.
type Identity struct {
	Subject string
	Email   string
}

// Callback completes the flow and checks the identity is the allowed admin.
func (o *OIDC) Callback(ctx context.Context, state, code string) (*Identity, error) {
	o.mu.Lock()
	pa, ok := o.pending[state]
	delete(o.pending, state)
	o.mu.Unlock()
	if !ok || time.Now().After(pa.expires) {
		return nil, errors.New("unknown or expired login state")
	}
	c, err := LoadOIDC(ctx, o.Store)
	if err != nil || !c.Enabled {
		return nil, errors.New("OIDC is not enabled")
	}
	p, err := o.provider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	tok, err := o.oauth(p, c).Exchange(ctx, code, oauth2.VerifierOption(pa.verifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("no id_token in response")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid id_token: %w", err)
	}
	if idt.Nonce != pa.nonce {
		return nil, errors.New("id_token nonce mismatch")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	_ = idt.Claims(&claims)
	id := &Identity{Subject: idt.Subject, Email: claims.Email}
	switch {
	case c.AllowedSubject != "" && idt.Subject == c.AllowedSubject:
		return id, nil
	case c.AllowedEmail != "" && strings.EqualFold(claims.Email, c.AllowedEmail) && (claims.EmailVerified == nil || *claims.EmailVerified):
		return id, nil
	}
	return nil, fmt.Errorf("identity %q (%s) is not the configured administrator", idt.Subject, claims.Email)
}
