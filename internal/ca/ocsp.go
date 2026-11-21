package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/davidemaggi/conrad/internal/store"
)

// OCSPRespond builds a signed OCSP response for a DER request addressed to
// the issuer with authorityID. Unknown serials get an "unknown" status.
func (s *Service) OCSPRespond(ctx context.Context, authorityID string, reqDER []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return ocsp.MalformedRequestErrorResponse, nil
	}
	a, err := s.store.GetAuthority(ctx, authorityID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.Kind != store.KindIntermediate) {
		return ocsp.UnauthorizedErrorResponse, nil
	}
	if err != nil {
		return nil, err
	}
	issuerCert, err := s.certOf(a)
	if err != nil {
		return nil, err
	}
	responderCert, err := parsePEMCert(a.OCSPCertPEM)
	if err != nil {
		return nil, err
	}
	key, err := s.signerFor(ctx, a.OCSPKeyID)
	if errors.Is(err, ErrLocked) {
		return ocsp.TryLaterErrorResponse, nil
	}
	if err != nil {
		return nil, err
	}

	now := s.now()
	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   now.Add(24 * time.Hour),
		Certificate:  responderCert,
		Status:       ocsp.Unknown,
	}
	c, err := s.store.GetCertificateBySerial(ctx, SerialHex(req.SerialNumber))
	switch {
	case err == nil && c.IssuerID == a.ID:
		if c.Status == store.CertRevoked {
			tmpl.Status = ocsp.Revoked
			tmpl.RevokedAt = c.RevokedAt
			tmpl.RevocationReason = c.RevocationReason
		} else {
			tmpl.Status = ocsp.Good
		}
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	if a.Status == store.StatusRevoked {
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = a.RevokedAt
		tmpl.RevocationReason = ReasonCACompromise
	}
	return ocsp.CreateResponse(issuerCert, responderCert, tmpl, key)
}

// IssuerCertificate returns the parsed certificate of an authority.
func (s *Service) IssuerCertificate(ctx context.Context, authorityID string) (*x509.Certificate, error) {
	a, err := s.store.GetAuthority(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	return s.certOf(a)
}
