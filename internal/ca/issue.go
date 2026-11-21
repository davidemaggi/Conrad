package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

// Leaf lifetime defaults (spec §4).
const (
	DefaultLeafValidity = 90 * 24 * time.Hour
	MaxLeafValidity     = 397 * 24 * time.Hour
)

// IssueRequest describes a leaf certificate.
type IssueRequest struct {
	PublicKey  crypto.PublicKey
	DNSNames   []string
	IPs        []net.IP
	CommonName string // optional; must be one of the SANs
	NotBefore  time.Time
	NotAfter   time.Time
	Validity   time.Duration // used when NotAfter is zero
	ClientAuth bool
	Source     string // acme | manual | system
	AccountID  string
	OrderID    string
}

// FromCSR fills PublicKey and SANs from a CSR whose signature is verified.
func FromCSR(csr *x509.CertificateRequest) (IssueRequest, error) {
	if err := csr.CheckSignature(); err != nil {
		return IssueRequest{}, fmt.Errorf("invalid CSR signature: %w", err)
	}
	r := IssueRequest{PublicKey: csr.PublicKey, DNSNames: csr.DNSNames, IPs: csr.IPAddresses, CommonName: csr.Subject.CommonName}
	if len(r.DNSNames) == 0 && len(r.IPs) == 0 && r.CommonName != "" {
		r.DNSNames = []string{r.CommonName}
	}
	return r, nil
}

// Issue signs a leaf with the active issuer for slug ("" = default).
func (s *Service) Issue(ctx context.Context, slug string, req IssueRequest) (*store.Certificate, error) {
	issuer, err := s.Issuer(ctx, slug)
	if err != nil {
		return nil, err
	}
	return s.issueWith(ctx, issuer, req)
}

func (s *Service) issueWith(ctx context.Context, issuer *store.Authority, req IssueRequest) (*store.Certificate, error) {
	if issuer.Status != store.StatusActive {
		return nil, ErrIssuerInactive
	}
	if len(req.DNSNames) == 0 && len(req.IPs) == 0 {
		return nil, errors.New("certificate needs at least one DNS name or IP")
	}
	if req.PublicKey == nil {
		return nil, errors.New("public key is required")
	}
	issuerCert, err := s.certOf(issuer)
	if err != nil {
		return nil, err
	}
	key, err := s.signerFor(ctx, issuer.KeyID)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	nb := req.NotBefore
	if nb.IsZero() || nb.Before(now.Add(-time.Hour)) {
		nb = now.Add(-time.Minute)
	}
	na := req.NotAfter
	if na.IsZero() {
		v := req.Validity
		if v <= 0 {
			v = DefaultLeafValidity
		}
		na = nb.Add(v)
	}
	if na.After(issuerCert.NotAfter) {
		na = issuerCert.NotAfter
	}
	if !na.After(nb) {
		return nil, errors.New("notAfter must be after notBefore")
	}

	dns := dedupeLower(req.DNSNames)
	if err := checkConstraints(s.constraintSets(ctx, issuer), dns); err != nil {
		return nil, err
	}
	cn := req.CommonName
	if cn != "" && !contains(dns, strings.ToLower(cn)) {
		cn = ""
	}
	if cn == "" && len(dns) > 0 {
		cn = dns[0]
	}
	if cn == "" && len(req.IPs) > 0 {
		cn = req.IPs[0].String()
	}

	ku := x509.KeyUsageDigitalSignature
	if _, ok := req.PublicKey.(*rsa.PublicKey); ok {
		ku |= x509.KeyUsageKeyEncipherment
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if req.ClientAuth {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           req.IPs,
		OCSPServer:            []string{s.baseURL + "/ocsp/" + issuer.ID},
		IssuingCertificateURL: []string{s.baseURL + "/issuers/" + issuer.ID + ".crt"},
		CRLDistributionPoints: []string{s.baseURL + "/crl/" + issuer.ID + ".crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, req.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sans := append([]string{}, dns...)
	for _, ip := range req.IPs {
		sans = append(sans, ip.String())
	}
	leafPEM := EncodePEM("CERTIFICATE", der)
	rec := &store.Certificate{
		Serial:       SerialHex(serial),
		IssuerID:     issuer.ID,
		IssuerSlug:   issuer.Slug,
		AccountID:    req.AccountID,
		OrderID:      req.OrderID,
		Source:       req.Source,
		CommonName:   cn,
		SANs:         sans,
		KeyAlgorithm: signer.AlgorithmOf(req.PublicKey),
		Fingerprint:  Fingerprint(der),
		AKI:          hex.EncodeToString(cert.AuthorityKeyId),
		CertPEM:      leafPEM,
		ChainPEM:     leafPEM + s.chainPEM(ctx, issuer),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Status:       store.CertValid,
	}
	if rec.Source == "" {
		rec.Source = "manual"
	}
	if err := s.store.InsertCertificate(ctx, rec); err != nil {
		return nil, err
	}
	s.log.Info("certificate issued", "serial", rec.Serial, "cn", cn, "issuer", issuer.Slug, "source", rec.Source)
	return rec, nil
}

// IssueWithKey generates a key server-side and issues a certificate for it.
// Used for manual issuance for devices that cannot create a CSR.
func (s *Service) IssueWithKey(ctx context.Context, slug string, alg signer.Algorithm, req IssueRequest) (*store.Certificate, crypto.Signer, error) {
	if alg == "" {
		alg = signer.ECDSAP256
	}
	key, err := signer.GenerateKey(alg)
	if err != nil {
		return nil, nil, err
	}
	req.PublicKey = key.Public()
	c, err := s.Issue(ctx, slug, req)
	return c, key, err
}

// ServerCertificate issues a TLS certificate for Conrad itself from the default issuer.
func (s *Service) ServerCertificate(ctx context.Context, hosts []string) (*tls.Certificate, error) {
	var dns []string
	var ips []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else if h != "" {
			dns = append(dns, h)
		}
	}
	rec, key, err := s.IssueWithKey(ctx, "", signer.ECDSAP256, IssueRequest{DNSNames: dns, IPs: ips, Source: "system", Validity: DefaultLeafValidity})
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	tc, err := tls.X509KeyPair([]byte(rec.ChainPEM), []byte(EncodePEM("PRIVATE KEY", keyDER)))
	if err != nil {
		return nil, err
	}
	return &tc, nil
}

func dedupeLower(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
