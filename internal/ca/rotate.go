package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

// RotateIssuer replaces the active issuer for slug with a freshly signed
// successor. The old issuer becomes "retiring": it stops issuing but keeps
// serving CRL/OCSP until its last certificate expires.
func (s *Service) RotateIssuer(ctx context.Context, slug string) (*store.Authority, error) {
	old, err := s.Issuer(ctx, slug)
	if err != nil {
		return nil, err
	}
	root, err := s.Root(ctx)
	if err != nil {
		return nil, err
	}
	oldCert, err := s.certOf(old)
	if err != nil {
		return nil, err
	}
	req := IssuerRequest{
		Slug:            old.Slug,
		Name:            old.Name,
		Description:     old.Description,
		Subject:         Subject{CommonName: oldCert.Subject.CommonName},
		Algorithm:       signer.Algorithm(signer.AlgorithmOf(oldCert.PublicKey)),
		Validity:        oldCert.NotAfter.Sub(oldCert.NotBefore),
		NameConstraints: oldCert.PermittedDNSDomains,
	}
	if len(oldCert.Subject.Organization) > 0 {
		req.Subject.Organization = oldCert.Subject.Organization[0]
	}
	successor, err := s.signIssuer(ctx, root, req)
	if err != nil {
		return nil, err
	}
	wasDefault := old.IsDefault
	old.Status = store.StatusRetiring
	old.IsDefault = false
	if err := s.store.UpdateAuthority(ctx, old); err != nil {
		return nil, err
	}
	if err := s.store.InsertAuthority(ctx, successor); err != nil {
		old.Status, old.IsDefault = store.StatusActive, wasDefault
		_ = s.store.UpdateAuthority(ctx, old)
		return nil, err
	}
	if wasDefault {
		if err := s.store.SetDefaultIssuer(ctx, successor.ID); err != nil {
			return nil, err
		}
		successor.IsDefault = true
	}
	s.log.Info("issuer rotated", "slug", slug, "old", old.ID, "new", successor.ID)
	return successor, nil
}

// RetireExpired moves retiring issuers with no remaining valid certificates to retired.
func (s *Service) RetireExpired(ctx context.Context) error {
	all, err := s.store.ListAuthorities(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, a := range all {
		if a.Status != store.StatusRetiring || a.Kind != store.KindIntermediate {
			continue
		}
		last, err := s.store.LatestValidExpiry(ctx, a.ID)
		if err != nil {
			return err
		}
		if last.IsZero() || last.Before(now) {
			a.Status = store.StatusRetired
			if err := s.store.UpdateAuthority(ctx, a); err != nil {
				return err
			}
			s.log.Info("issuer retired", "slug", a.Slug, "id", a.ID)
		}
	}
	return nil
}

const settingCrossPrefix = "ca.cross_cert."

// SuccessorRoot creates a new root with the same subject/key type as the
// current one, plus a cross-certificate (new root key signed by the old root)
// so clients trusting only the old root can validate chains during migration.
func (s *Service) SuccessorRoot(ctx context.Context, validity time.Duration) (*store.Authority, error) {
	old, err := s.Root(ctx)
	if err != nil {
		return nil, err
	}
	oldCert, err := s.certOf(old)
	if err != nil {
		return nil, err
	}
	oldKey, err := s.signerFor(ctx, old.KeyID)
	if err != nil {
		return nil, err
	}
	subj := Subject{CommonName: oldCert.Subject.CommonName}
	if len(oldCert.Subject.Organization) > 0 {
		subj.Organization = oldCert.Subject.Organization[0]
	}
	if len(oldCert.Subject.Country) > 0 {
		subj.Country = oldCert.Subject.Country[0]
	}
	nr, err := s.createRoot(ctx, subj, signer.Algorithm(signer.AlgorithmOf(oldCert.PublicKey)), validity, oldCert.PermittedDNSDomains)
	if err != nil {
		return nil, err
	}
	newCert, err := s.certOf(nr)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := newCert.NotAfter
	if notAfter.After(oldCert.NotAfter) {
		notAfter = oldCert.NotAfter
	}
	cross := *newCert
	cross.SerialNumber = serial
	cross.NotAfter = notAfter
	cross.AuthorityKeyId = nil
	der, err := x509.CreateCertificate(rand.Reader, &cross, oldCert, newCert.PublicKey, oldKey)
	if err != nil {
		return nil, fmt.Errorf("cross-sign: %w", err)
	}
	if err := s.store.SetSetting(ctx, settingCrossPrefix+nr.ID, EncodePEM("CERTIFICATE", der)); err != nil {
		return nil, err
	}
	// The old root stays trusted (existing issuers chain to it) but no longer
	// signs new issuers.
	old.Status = store.StatusRetiring
	if err := s.store.UpdateAuthority(ctx, old); err != nil {
		return nil, err
	}
	s.log.Info("successor root created", "old", old.ID, "new", nr.ID)
	return nr, nil
}

// CrossCertificate returns the cross-signed certificate for a root, if any.
func (s *Service) CrossCertificate(ctx context.Context, rootID string) (string, error) {
	v, err := s.store.GetSetting(ctx, settingCrossPrefix+rootID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return v, err
}
