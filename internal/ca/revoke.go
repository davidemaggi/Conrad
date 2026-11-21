package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

// RFC 5280 revocation reason codes used by Conrad.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
)

const (
	crlValidity = 7 * 24 * time.Hour
	crlRefresh  = 24 * time.Hour
)

// ValidReason reports whether r is an allowed reason code for leaf revocation.
func ValidReason(r int) bool { return r >= 0 && r <= 10 && r != 7 && r != 8 }

// Revoke revokes a leaf certificate and refreshes its issuer's CRL.
func (s *Service) Revoke(ctx context.Context, certID string, reason int) error {
	if !ValidReason(reason) {
		return fmt.Errorf("invalid revocation reason %d", reason)
	}
	c, err := s.store.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}
	if err := s.store.RevokeCertificate(ctx, c.ID, reason, s.now()); err != nil {
		return err
	}
	s.log.Info("certificate revoked", "serial", c.Serial, "reason", reason)
	if _, err := s.RefreshCRL(ctx, c.IssuerID); err != nil && !errors.Is(err, ErrLocked) {
		return err
	}
	return nil
}

// RevokeIssuer revokes an intermediate and every certificate it signed.
func (s *Service) RevokeIssuer(ctx context.Context, id string) error {
	a, err := s.store.GetAuthority(ctx, id)
	if err != nil {
		return err
	}
	if a.Kind != store.KindIntermediate {
		return errors.New("only intermediates can be revoked")
	}
	if a.IsDefault && a.Status == store.StatusActive {
		return ErrCannotRevokeDef
	}
	now := s.now()
	a.Status = store.StatusRevoked
	a.RevokedAt = now
	a.IsDefault = false
	if err := s.store.UpdateAuthority(ctx, a); err != nil {
		return err
	}
	n, err := s.store.RevokeAllByIssuer(ctx, a.ID, ReasonCACompromise, now)
	if err != nil {
		return err
	}
	s.log.Warn("issuer revoked", "slug", a.Slug, "id", a.ID, "leaves", n)
	if _, err := s.RefreshCRL(ctx, a.ParentID); err != nil && !errors.Is(err, ErrLocked) {
		return err
	}
	if _, err := s.RefreshCRL(ctx, a.ID); err != nil && !errors.Is(err, ErrLocked) {
		return err
	}
	return nil
}

// CRL returns the DER CRL for an authority, regenerating it when stale.
func (s *Service) CRL(ctx context.Context, authorityID string) ([]byte, error) {
	a, err := s.store.GetAuthority(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	if len(a.CRLDER) > 0 && s.now().Sub(a.CRLUpdatedAt) < crlRefresh {
		return a.CRLDER, nil
	}
	der, err := s.RefreshCRL(ctx, authorityID)
	if errors.Is(err, ErrLocked) && len(a.CRLDER) > 0 {
		return a.CRLDER, nil // serve the last one while locked
	}
	return der, err
}

// RefreshCRL regenerates and stores the CRL for an authority.
func (s *Service) RefreshCRL(ctx context.Context, authorityID string) ([]byte, error) {
	a, err := s.store.GetAuthority(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	cert, err := s.certOf(a)
	if err != nil {
		return nil, err
	}
	key, err := s.signerFor(ctx, a.KeyID)
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	if a.Kind == store.KindRoot {
		all, err := s.store.ListAuthorities(ctx)
		if err != nil {
			return nil, err
		}
		for _, child := range all {
			if child.ParentID == a.ID && child.Status == store.StatusRevoked {
				sn, _ := new(big.Int).SetString(child.Serial, 16)
				entries = append(entries, x509.RevocationListEntry{SerialNumber: sn, RevocationTime: child.RevokedAt, ReasonCode: ReasonCACompromise})
			}
		}
	} else {
		revoked, err := s.store.RevokedByIssuer(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range revoked {
			sn, _ := new(big.Int).SetString(r.Serial, 16)
			entries = append(entries, x509.RevocationListEntry{SerialNumber: sn, RevocationTime: r.RevokedAt, ReasonCode: r.Reason})
		}
	}
	now := s.now()
	number := a.CRLNumber + 1
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: entries,
	}, cert, key)
	if err != nil {
		return nil, fmt.Errorf("create crl: %w", err)
	}
	if err := s.store.UpdateCRL(ctx, a.ID, number, der, now); err != nil {
		return nil, err
	}
	if s.OnCRLChange != nil {
		s.OnCRLChange(a.ID)
	}
	return der, nil
}
