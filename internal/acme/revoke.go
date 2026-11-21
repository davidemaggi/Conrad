package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/store"
)

// revokeCert implements RFC 8555 §7.6 (account owner or certificate key).
func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, anyKey)
	if p != nil {
		return p
	}
	var in struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if p := req.decode(&in); p != nil {
		return p
	}
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(in.Certificate, "="))
	if err != nil {
		return malformed("certificate is not base64url")
	}
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return malformed("cannot parse certificate")
	}
	ctx := r.Context()
	c, err := s.Store.GetCertificateBySerial(ctx, ca.SerialHex(x.SerialNumber))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (c.IssuerSlug != slug || ca.Fingerprint(der) != c.Fingerprint)) {
		return notFoundP("certificate was not issued by this directory")
	} else if err != nil {
		return serverErr("%v", err)
	}
	switch {
	case req.account != nil:
		if c.AccountID != req.account.ID {
			return unauthorized("account is not authorized to revoke this certificate")
		}
	case req.jwk != nil:
		a, _ := thumbprint(req.jwk)
		b, err := thumbprint(&jose.JSONWebKey{Key: x.PublicKey})
		if err != nil || a != b {
			return unauthorized("JWS key does not match the certificate key")
		}
	}
	reason := 0
	if in.Reason != nil {
		reason = *in.Reason
	}
	if !ca.ValidReason(reason) {
		return prob(400, "badRevocationReason", "revocation reason %d is not allowed", reason)
	}
	if c.Status == store.CertRevoked {
		return prob(400, "alreadyRevoked", "certificate is already revoked")
	}
	if err := s.CA.Revoke(ctx, c.ID, reason); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return prob(400, "alreadyRevoked", "certificate is already revoked")
		}
		return serverErr("%v", err)
	}
	acctID := ""
	if req.account != nil {
		acctID = req.account.ID
	}
	s.emit(ctx, Event{Type: "cert.revoked", IssuerSlug: slug, AccountID: acctID, Target: c.ID, Detail: map[string]any{"serial": c.Serial, "reason": reason}})
	w.WriteHeader(http.StatusOK)
	return nil
}

// certByARIID resolves an RFC 9773 certID ("base64url(AKI).base64url(serial)").
func (s *Server) certByARIID(ctx context.Context, id string) (*store.Certificate, *Problem) {
	akiPart, serialPart, ok := strings.Cut(id, ".")
	if !ok {
		return nil, malformed("invalid ARI certificate identifier")
	}
	aki, err1 := base64.RawURLEncoding.DecodeString(strings.TrimRight(akiPart, "="))
	serial, err2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(serialPart, "="))
	if err1 != nil || err2 != nil || len(serial) == 0 {
		return nil, malformed("invalid ARI certificate identifier")
	}
	c, err := s.Store.GetCertificateBySerial(ctx, ca.SerialHex(new(big.Int).SetBytes(serial)))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !strings.EqualFold(c.AKI, hex.EncodeToString(aki))) {
		return nil, notFoundP("unknown certificate")
	}
	if err != nil {
		return nil, serverErr("%v", err)
	}
	return c, nil
}

// renewalInfo implements RFC 9773 (ACME Renewal Information).
func (s *Server) renewalInfo(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	c, p := s.certByARIID(r.Context(), r.PathValue("certid"))
	if p != nil {
		return p
	}
	now := s.Store.Now()
	life := c.NotAfter.Sub(c.NotBefore)
	start, end := c.NotAfter.Add(-life/3), c.NotAfter.Add(-life/6)
	if c.Status == store.CertRevoked {
		// Renew immediately.
		start, end = now.Add(-time.Hour), now
	}
	w.Header().Set("Retry-After", "21600")
	writeJSON(w, 200, map[string]any{
		"suggestedWindow": map[string]string{"start": rfc3339(start), "end": rfc3339(end)},
	})
	return nil
}
