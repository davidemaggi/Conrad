package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

// Defaults from the spec.
const (
	DefaultRootValidity   = 10 * 365 * 24 * time.Hour
	DefaultIssuerValidity = 5 * 365 * 24 * time.Hour
	DefaultRootAlgorithm  = signer.ECDSAP384
	DefaultIssuerAlg      = signer.ECDSAP256
)

// Subject holds naming details shared by root and issuers.
type Subject struct {
	CommonName   string `json:"commonName"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
}

func (s Subject) name(fallbackCN string) pkix.Name {
	n := pkix.Name{CommonName: s.CommonName}
	if n.CommonName == "" {
		n.CommonName = fallbackCN
	}
	if s.Organization != "" {
		n.Organization = []string{s.Organization}
	}
	if s.Country != "" {
		n.Country = []string{s.Country}
	}
	return n
}

// IssuerRequest describes a new intermediate.
type IssuerRequest struct {
	Slug            string           `json:"slug"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	Subject         Subject          `json:"subject"`
	Algorithm       signer.Algorithm `json:"algorithm"`
	Validity        time.Duration    `json:"validity"`
	NameConstraints []string         `json:"nameConstraints"`
	Default         bool             `json:"default"`
}

// InitRequest bootstraps a brand new CA.
type InitRequest struct {
	Secret          string           // passphrase (software) or PIN (HSM)
	Subject         Subject          // root subject
	Algorithm       signer.Algorithm // root key
	Validity        time.Duration
	NameConstraints []string // permitted DNS domains for the whole hierarchy (optional)
	Issuer          IssuerRequest
}

// Init creates the root and the first (default) issuer.
func (s *Service) Init(ctx context.Context, req InitRequest) (root, issuer *store.Authority, err error) {
	if ok, err := s.Initialized(ctx); err != nil {
		return nil, nil, err
	} else if ok {
		return nil, nil, ErrAlreadyInit
	}
	if req.Issuer.Slug == "" {
		req.Issuer.Slug = "default"
	}
	if !ValidSlug(req.Issuer.Slug) {
		return nil, nil, ErrInvalidSlug
	}
	if err := s.prepareProvider(ctx, req.Secret); err != nil {
		return nil, nil, err
	}
	root, err = s.createRoot(ctx, req.Subject, req.Algorithm, req.Validity, req.NameConstraints)
	if err != nil {
		return nil, nil, err
	}
	req.Issuer.Default = true
	issuer, err = s.CreateIssuer(ctx, req.Issuer)
	return root, issuer, err
}

func (s *Service) createRoot(ctx context.Context, subj Subject, alg signer.Algorithm, validity time.Duration, constraints []string) (*store.Authority, error) {
	if alg == "" {
		alg = DefaultRootAlgorithm
	}
	if validity <= 0 {
		validity = DefaultRootValidity
	}
	keyID, key, err := s.newKey(ctx, alg, "conrad-root")
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj.name("Conrad Root CA"),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	applyNameConstraints(tmpl, constraints)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}
	id := store.NewID()
	a := &store.Authority{
		ID:        id,
		Slug:      "root-" + id[:6],
		Name:      tmpl.Subject.CommonName,
		Kind:      store.KindRoot,
		Status:    store.StatusActive,
		CertPEM:   EncodePEM("CERTIFICATE", der),
		KeyID:     keyID,
		Serial:    SerialHex(serial),
		NotBefore: tmpl.NotBefore,
		NotAfter:  tmpl.NotAfter,
	}
	if err := s.store.InsertAuthority(ctx, a); err != nil {
		return nil, err
	}
	s.log.Info("root CA created", "id", a.ID, "cn", a.Name)
	return a, nil
}

// issuerCN is the fallback common name of an issuer: its name, with " Issuer"
// appended unless the name already ends with it.
func issuerCN(name string) string {
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), "issuer") {
		return strings.TrimSpace(name)
	}
	return "Conrad " + strings.TrimSpace(name) + " Issuer"
}

func applyNameConstraints(tmpl *x509.Certificate, domains []string) {
	var clean []string
	for _, d := range domains {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
		if d != "" {
			clean = append(clean, d)
		}
	}
	if len(clean) > 0 {
		tmpl.PermittedDNSDomains = clean
		tmpl.PermittedDNSDomainsCritical = true
	}
}

// CreateIssuer creates a new intermediate signed by the active root.
func (s *Service) CreateIssuer(ctx context.Context, req IssuerRequest) (*store.Authority, error) {
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if !ValidSlug(req.Slug) {
		return nil, ErrInvalidSlug
	}
	if _, err := s.store.ActiveIssuer(ctx, req.Slug); err == nil {
		return nil, ErrSlugTaken
	}
	root, err := s.Root(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.signIssuer(ctx, root, req)
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertAuthority(ctx, a); err != nil {
		return nil, err
	}
	if req.Default {
		if err := s.store.SetDefaultIssuer(ctx, a.ID); err != nil {
			return nil, err
		}
		a.IsDefault = true
	}
	s.log.Info("issuer created", "slug", a.Slug, "id", a.ID)
	return a, nil
}

// signIssuer builds (but does not persist) an intermediate under root.
func (s *Service) signIssuer(ctx context.Context, root *store.Authority, req IssuerRequest) (*store.Authority, error) {
	if req.Algorithm == "" {
		req.Algorithm = DefaultIssuerAlg
	}
	if req.Validity <= 0 {
		req.Validity = DefaultIssuerValidity
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	rootCert, err := s.certOf(root)
	if err != nil {
		return nil, err
	}
	rootKey, err := s.signerFor(ctx, root.KeyID)
	if err != nil {
		return nil, err
	}
	keyID, key, err := s.newKey(ctx, req.Algorithm, "conrad-issuer-"+req.Slug)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	notAfter := now.Add(req.Validity)
	if notAfter.After(rootCert.NotAfter) {
		notAfter = rootCert.NotAfter
	}
	id := store.NewID()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject.name(issuerCN(req.Name)),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		IssuingCertificateURL: []string{s.baseURL + "/roots/" + root.ID + ".crt"},
		CRLDistributionPoints: []string{s.baseURL + "/crl/" + root.ID + ".crl"},
	}
	applyNameConstraints(tmpl, req.NameConstraints)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, key.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign issuer: %w", err)
	}
	cert, _ := x509.ParseCertificate(der)

	ocspPEM, ocspKeyID, err := s.createOCSPSigner(ctx, cert, key, id)
	if err != nil {
		return nil, err
	}
	return &store.Authority{
		ID:          id,
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		Kind:        store.KindIntermediate,
		ParentID:    root.ID,
		Status:      store.StatusActive,
		CertPEM:     EncodePEM("CERTIFICATE", der),
		KeyID:       keyID,
		OCSPCertPEM: ocspPEM,
		OCSPKeyID:   ocspKeyID,
		Serial:      SerialHex(serial),
		NotBefore:   tmpl.NotBefore,
		NotAfter:    tmpl.NotAfter,
	}, nil
}

var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// createOCSPSigner issues a delegated OCSP responder certificate for issuer.
func (s *Service) createOCSPSigner(ctx context.Context, issuer *x509.Certificate, issuerKey crypto.Signer, issuerID string) (string, string, error) {
	keyID, key, err := s.newKey(ctx, signer.ECDSAP256, "conrad-ocsp-"+issuerID)
	if err != nil {
		return "", "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: issuer.Subject.CommonName + " OCSP Responder"},
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        issuer.NotAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidOCSPNoCheck, Value: []byte{0x05, 0x00}}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	if err != nil {
		return "", "", fmt.Errorf("sign ocsp responder: %w", err)
	}
	return EncodePEM("CERTIFICATE", der), keyID, nil
}

// ImportRequest imports an existing hierarchy. RootKeyPEM is required so new
// issuers can be created; the intermediate is optional.
type ImportRequest struct {
	Secret        string
	RootCertPEM   string
	RootKeyPEM    string
	IssuerCertPEM string
	IssuerKeyPEM  string
	IssuerSlug    string
	IssuerName    string
}

// Import bootstraps the CA from existing material.
func (s *Service) Import(ctx context.Context, req ImportRequest) (root, issuer *store.Authority, err error) {
	if ok, err := s.Initialized(ctx); err != nil {
		return nil, nil, err
	} else if ok {
		return nil, nil, ErrAlreadyInit
	}
	rootCerts, err := ParseCertificatesPEM([]byte(req.RootCertPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("root certificate: %w", err)
	}
	rootCert := rootCerts[0]
	if !rootCert.IsCA {
		return nil, nil, errors.New("root certificate is not a CA")
	}
	rootKey, err := ParsePrivateKeyPEM([]byte(req.RootKeyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("root key: %w", err)
	}
	if !publicKeysEqual(rootCert.PublicKey, rootKey.Public()) {
		return nil, nil, errors.New("root key does not match root certificate")
	}
	if err := s.prepareProvider(ctx, req.Secret); err != nil {
		return nil, nil, err
	}
	rootKeyID, err := s.importKey(ctx, rootKey)
	if err != nil {
		return nil, nil, err
	}
	id := store.NewID()
	root = &store.Authority{
		ID: id, Slug: "root-" + id[:6], Name: rootCert.Subject.CommonName, Kind: store.KindRoot, Status: store.StatusActive,
		CertPEM: EncodePEM("CERTIFICATE", rootCert.Raw), KeyID: rootKeyID, Serial: SerialHex(rootCert.SerialNumber),
		NotBefore: rootCert.NotBefore, NotAfter: rootCert.NotAfter,
	}
	if err := s.store.InsertAuthority(ctx, root); err != nil {
		return nil, nil, err
	}

	slug := req.IssuerSlug
	if slug == "" {
		slug = "default"
	}
	if req.IssuerCertPEM == "" {
		issuer, err = s.CreateIssuer(ctx, IssuerRequest{Slug: slug, Name: req.IssuerName, Default: true})
		return root, issuer, err
	}
	if !ValidSlug(slug) {
		return nil, nil, ErrInvalidSlug
	}
	ic, err := ParseCertificatesPEM([]byte(req.IssuerCertPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("issuer certificate: %w", err)
	}
	issuerCert := ic[0]
	if err := issuerCert.CheckSignatureFrom(rootCert); err != nil {
		return nil, nil, fmt.Errorf("issuer is not signed by root: %w", err)
	}
	issuerKey, err := ParsePrivateKeyPEM([]byte(req.IssuerKeyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("issuer key: %w", err)
	}
	if !publicKeysEqual(issuerCert.PublicKey, issuerKey.Public()) {
		return nil, nil, errors.New("issuer key does not match issuer certificate")
	}
	issuerKeyID, err := s.importKey(ctx, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	iid := store.NewID()
	ocspPEM, ocspKeyID, err := s.createOCSPSigner(ctx, issuerCert, issuerKey, iid)
	if err != nil {
		return nil, nil, err
	}
	name := req.IssuerName
	if name == "" {
		name = slug
	}
	issuer = &store.Authority{
		ID: iid, Slug: slug, Name: name, Kind: store.KindIntermediate, ParentID: root.ID, Status: store.StatusActive,
		CertPEM: EncodePEM("CERTIFICATE", issuerCert.Raw), KeyID: issuerKeyID, OCSPCertPEM: ocspPEM, OCSPKeyID: ocspKeyID,
		Serial: SerialHex(issuerCert.SerialNumber), NotBefore: issuerCert.NotBefore, NotAfter: issuerCert.NotAfter,
	}
	if err := s.store.InsertAuthority(ctx, issuer); err != nil {
		return nil, nil, err
	}
	if err := s.store.SetDefaultIssuer(ctx, issuer.ID); err != nil {
		return nil, nil, err
	}
	issuer.IsDefault = true
	return root, issuer, nil
}

// SetDefault makes the active issuer with slug the default.
func (s *Service) SetDefault(ctx context.Context, slug string) error {
	a, err := s.Issuer(ctx, slug)
	if err != nil {
		return err
	}
	return s.store.SetDefaultIssuer(ctx, a.ID)
}

// UpdateIssuerInfo changes display name and description.
func (s *Service) UpdateIssuerInfo(ctx context.Context, id, name, description string) (*store.Authority, error) {
	a, err := s.store.GetAuthority(ctx, id)
	if err != nil {
		return nil, err
	}
	if name != "" {
		a.Name = name
	}
	a.Description = description
	return a, s.store.UpdateAuthority(ctx, a)
}

// Chain returns the PEM chain for an authority up to (excluding) the root.
func (s *Service) chainPEM(ctx context.Context, issuer *store.Authority) string {
	return issuer.CertPEM
}
