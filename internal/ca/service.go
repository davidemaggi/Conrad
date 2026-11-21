// Package ca implements Conrad's certificate authority: a root with any
// number of intermediate issuers, leaf issuance, revocation, CRL and OCSP.
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

// Errors returned by the service.
var (
	ErrLocked          = errors.New("ca is locked")
	ErrNotInitialized  = errors.New("ca is not initialized")
	ErrAlreadyInit     = errors.New("ca is already initialized")
	ErrIssuerNotFound  = errors.New("issuer not found")
	ErrIssuerInactive  = errors.New("issuer is not active")
	ErrInvalidSlug     = errors.New("slug must be 2-32 chars of a-z, 0-9 and '-'")
	ErrSlugTaken       = errors.New("slug already in use")
	ErrCannotRevokeDef = errors.New("cannot revoke the default issuer; set another default first")
)

const settingKDF = "ca.kdf_params"

// Service is the CA. It is safe for concurrent use.
type Service struct {
	store   *store.Store
	keys    signer.Provider
	baseURL string
	log     *slog.Logger

	mu      sync.Mutex
	signers map[string]crypto.Signer // ca_keys.id -> signer
	certs   map[string]*x509.Certificate

	// OnCRLChange is called after a CRL is regenerated (optional).
	OnCRLChange func(authorityID string)
}

// New creates the service. baseURL is the externally reachable base URL used
// in AIA/CDP extensions, e.g. "https://conrad.home.lab".
func New(st *store.Store, keys signer.Provider, baseURL string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		store:   st,
		keys:    keys,
		baseURL: strings.TrimRight(baseURL, "/"),
		log:     log,
		signers: map[string]crypto.Signer{},
		certs:   map[string]*x509.Certificate{},
	}
}

// BaseURL returns the configured external base URL.
func (s *Service) BaseURL() string { return s.baseURL }

// Store exposes the underlying store.
func (s *Service) Store() *store.Store { return s.store }

// Provider exposes the key provider.
func (s *Service) Provider() signer.Provider { return s.keys }

// Initialized reports whether a root exists.
func (s *Service) Initialized(ctx context.Context) (bool, error) {
	return s.store.HasAuthorities(ctx)
}

// Locked reports whether CA keys are unavailable.
func (s *Service) Locked() bool { return !s.keys.Unlocked() }

// pinLogin is implemented by HSM providers.
type pinLogin interface{ Login(pin string) error }

// Unlock unlocks the key provider with the passphrase (software) or PIN (HSM).
func (s *Service) Unlock(ctx context.Context, secret string) error {
	switch p := s.keys.(type) {
	case *signer.Software:
		raw, err := s.store.GetSetting(ctx, settingKDF)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotInitialized
		}
		if err != nil {
			return err
		}
		params, err := signer.ParseKDFParams(raw)
		if err != nil {
			return err
		}
		return p.Unlock(secret, params)
	case pinLogin:
		return p.Login(secret)
	}
	return fmt.Errorf("provider %s cannot be unlocked", s.keys.Name())
}

// prepareProvider makes sure the provider is usable for a fresh CA.
func (s *Service) prepareProvider(ctx context.Context, secret string) error {
	switch p := s.keys.(type) {
	case *signer.Software:
		params, err := p.Initialize(secret)
		if err != nil {
			return err
		}
		return s.store.SetSetting(ctx, settingKDF, params.String())
	case pinLogin:
		return p.Login(secret)
	}
	return nil
}

func (s *Service) signerFor(ctx context.Context, keyID string) (crypto.Signer, error) {
	if s.Locked() {
		return nil, ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sg, ok := s.signers[keyID]; ok {
		return sg, nil
	}
	k, err := s.store.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("load key %s: %w", keyID, err)
	}
	sg, err := s.keys.Load(k.Blob)
	if errors.Is(err, signer.ErrLocked) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, err
	}
	s.signers[keyID] = sg
	return sg, nil
}

// certOf parses (and caches) an authority certificate.
func (s *Service) certOf(a *store.Authority) (*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.certs[a.ID]; ok {
		return c, nil
	}
	c, err := parsePEMCert(a.CertPEM)
	if err != nil {
		return nil, err
	}
	s.certs[a.ID] = c
	return c, nil
}

// newKey generates a CA key with the provider and stores it.
func (s *Service) newKey(ctx context.Context, alg signer.Algorithm, label string) (string, crypto.Signer, error) {
	blob, sg, err := s.keys.Generate(alg, label)
	if err != nil {
		return "", nil, err
	}
	k := &store.CAKey{Provider: s.keys.Name(), Algorithm: string(alg), Blob: blob}
	if err := s.store.InsertKey(ctx, k); err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	s.signers[k.ID] = sg
	s.mu.Unlock()
	return k.ID, sg, nil
}

func (s *Service) importKey(ctx context.Context, key crypto.Signer) (string, error) {
	blob, err := s.keys.Import(key)
	if err != nil {
		return "", err
	}
	k := &store.CAKey{Provider: s.keys.Name(), Algorithm: signer.AlgorithmOf(key.Public()), Blob: blob}
	if err := s.store.InsertKey(ctx, k); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.signers[k.ID] = key
	s.mu.Unlock()
	return k.ID, nil
}

// Authorities lists every authority.
func (s *Service) Authorities(ctx context.Context) ([]*store.Authority, error) {
	return s.store.ListAuthorities(ctx)
}

// Issuer returns the active issuer for slug ("" = default).
func (s *Service) Issuer(ctx context.Context, slug string) (*store.Authority, error) {
	var a *store.Authority
	var err error
	if slug == "" {
		a, err = s.store.DefaultIssuer(ctx)
	} else {
		a, err = s.store.ActiveIssuer(ctx, slug)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrIssuerNotFound
	}
	return a, err
}

// Root returns the active root.
func (s *Service) Root(ctx context.Context) (*store.Authority, error) {
	a, err := s.store.ActiveRoot(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotInitialized
	}
	return a, err
}

func (s *Service) now() time.Time { return s.store.Now() }
