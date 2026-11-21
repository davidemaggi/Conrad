package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

const pass = "a very long passphrase"

func newCA(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, signer.NewSoftware(), "https://conrad.test", nil)
	_, _, err = svc.Init(context.Background(), InitRequest{
		Secret:  pass,
		Subject: Subject{CommonName: "Test Root", Organization: "Homelab"},
		Issuer:  IssuerRequest{Slug: "default", Name: "Default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, st
}

func leafKey(t *testing.T) *IssueRequest {
	k, err := signer.GenerateKey(signer.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return &IssueRequest{PublicKey: k.Public(), DNSNames: []string{"nas.home.lab", "NAS.home.lab"}, Source: "manual"}
}

func verifyChain(t *testing.T, svc *Service, rec *store.Certificate) {
	t.Helper()
	ctx := context.Background()
	root, _ := svc.Root(ctx)
	rootCert, _ := parsePEMCert(root.CertPEM)
	certs, err := ParseCertificatesPEM([]byte(rec.ChainPEM))
	if err != nil {
		t.Fatal(err)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(rootCert)
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "nas.home.lab"}); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}
}

func TestIssueVerifiesAgainstRoot(t *testing.T) {
	svc, _ := newCA(t)
	rec, err := svc.Issue(context.Background(), "", *leafKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.SANs) != 1 || rec.SANs[0] != "nas.home.lab" {
		t.Errorf("SANs should be deduped/lowercased, got %v", rec.SANs)
	}
	if d := rec.NotAfter.Sub(rec.NotBefore); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("default validity = %v", d)
	}
	verifyChain(t, svc, rec)
}

func TestLockedRefusesIssuance(t *testing.T) {
	svc, st := newCA(t)
	locked := New(st, signer.NewSoftware(), "https://conrad.test", nil)
	if _, err := locked.Issue(context.Background(), "", *leafKey(t)); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := locked.Unlock(context.Background(), "nope nope nope"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := locked.Unlock(context.Background(), pass); err != nil {
		t.Fatal(err)
	}
	if _, err := locked.Issue(context.Background(), "", *leafKey(t)); err != nil {
		t.Fatal(err)
	}
	_ = svc
}

func TestRevokeUpdatesCRLAndOCSP(t *testing.T) {
	svc, _ := newCA(t)
	ctx := context.Background()
	rec, _ := svc.Issue(ctx, "", *leafKey(t))
	issuer, _ := svc.Issuer(ctx, "")
	issuerCert, _ := parsePEMCert(issuer.CertPEM)
	leaf, _ := parsePEMCert(rec.CertPEM)

	status := func() int {
		reqDER, err := ocsp.CreateRequest(leaf, issuerCert, nil)
		if err != nil {
			t.Fatal(err)
		}
		respDER, err := svc.OCSPRespond(ctx, issuer.ID, reqDER)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := ocsp.ParseResponseForCert(respDER, leaf, issuerCert)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Status
	}
	if s := status(); s != ocsp.Good {
		t.Fatalf("OCSP before revoke = %d", s)
	}
	if err := svc.Revoke(ctx, rec.ID, ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	if s := status(); s != ocsp.Revoked {
		t.Fatalf("OCSP after revoke = %d", s)
	}
	der, err := svc.CRL(ctx, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuerCert); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("CRL entries = %+v", crl.RevokedCertificateEntries)
	}
	if err := svc.Revoke(ctx, rec.ID, ReasonKeyCompromise); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double revoke should fail with ErrNotFound, got %v", err)
	}
}

func TestMultipleIssuersAndRotation(t *testing.T) {
	svc, st := newCA(t)
	ctx := context.Background()
	if _, err := svc.CreateIssuer(ctx, IssuerRequest{Slug: "k8s", NameConstraints: []string{"k8s.home.lab"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateIssuer(ctx, IssuerRequest{Slug: "k8s"}); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("want ErrSlugTaken, got %v", err)
	}
	if _, err := svc.CreateIssuer(ctx, IssuerRequest{Slug: "Bad Slug"}); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("want ErrInvalidSlug, got %v", err)
	}

	req := *leafKey(t)
	req.DNSNames = []string{"api.k8s.home.lab"}
	old, err := svc.Issue(ctx, "k8s", req)
	if err != nil {
		t.Fatal(err)
	}
	// Name constraints are enforced by verifiers: a name outside must fail verification.
	bad := *leafKey(t)
	bad.DNSNames = []string{"nas.home.lab"}
	badRec, err := svc.Issue(ctx, "k8s", bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyErr(svc, badRec, "nas.home.lab"); err == nil {
		t.Fatal("certificate outside name constraints should not verify")
	}

	oldIssuer, _ := svc.Issuer(ctx, "k8s")
	successor, err := svc.RotateIssuer(ctx, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	if successor.ID == oldIssuer.ID || successor.Slug != "k8s" {
		t.Fatal("rotation should create a new issuer with the same slug")
	}
	rec, err := svc.Issue(ctx, "k8s", req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IssuerID != successor.ID {
		t.Fatal("new certificates must be signed by the successor")
	}
	got, _ := st.GetAuthority(ctx, oldIssuer.ID)
	if got.Status != store.StatusRetiring {
		t.Fatalf("old issuer status = %s", got.Status)
	}
	// Old cert stays checkable via the old issuer's OCSP.
	oldLeaf, _ := parsePEMCert(old.CertPEM)
	oldIssuerCert, _ := parsePEMCert(oldIssuer.CertPEM)
	reqDER, _ := ocsp.CreateRequest(oldLeaf, oldIssuerCert, nil)
	respDER, _ := svc.OCSPRespond(ctx, oldIssuer.ID, reqDER)
	if resp, err := ocsp.ParseResponseForCert(respDER, oldLeaf, oldIssuerCert); err != nil || resp.Status != ocsp.Good {
		t.Fatalf("old issuer OCSP: %v %+v", err, resp)
	}

	// Retire once its certificates expired.
	st.SetClock(func() time.Time { return time.Now().Add(400 * 24 * time.Hour) })
	if err := svc.RetireExpired(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetAuthority(ctx, oldIssuer.ID)
	if got.Status != store.StatusRetired {
		t.Fatalf("expected retired, got %s", got.Status)
	}
}

func verifyErr(svc *Service, rec *store.Certificate, name string) error {
	root, _ := svc.Root(context.Background())
	rootCert, _ := parsePEMCert(root.CertPEM)
	certs, _ := ParseCertificatesPEM([]byte(rec.ChainPEM))
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(rootCert)
	inter.AddCert(certs[1])
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name})
	return err
}

func TestRevokeIssuer(t *testing.T) {
	svc, st := newCA(t)
	ctx := context.Background()
	def, _ := svc.Issuer(ctx, "")
	if err := svc.RevokeIssuer(ctx, def.ID); !errors.Is(err, ErrCannotRevokeDef) {
		t.Fatalf("want ErrCannotRevokeDef, got %v", err)
	}
	iss, _ := svc.CreateIssuer(ctx, IssuerRequest{Slug: "devices"})
	rec, _ := svc.Issue(ctx, "devices", *leafKey(t))
	if err := svc.RevokeIssuer(ctx, iss.ID); err != nil {
		t.Fatal(err)
	}
	c, _ := st.GetCertificate(ctx, rec.ID)
	if c.Status != store.CertRevoked || c.RevocationReason != ReasonCACompromise {
		t.Fatalf("leaf should be revoked with cACompromise: %+v", c)
	}
	root, _ := svc.Root(ctx)
	der, err := svc.CRL(ctx, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	sn, _ := new(big.Int).SetString(iss.Serial, 16)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(sn) != 0 {
		t.Fatal("root CRL should list the revoked issuer")
	}
	if _, err := svc.Issue(ctx, "devices", *leafKey(t)); !errors.Is(err, ErrIssuerNotFound) {
		t.Fatalf("revoked slug must not issue, got %v", err)
	}
}

func TestSuccessorRootCrossSigned(t *testing.T) {
	svc, _ := newCA(t)
	ctx := context.Background()
	old, _ := svc.Root(ctx)
	nr, err := svc.SuccessorRoot(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := svc.Root(ctx)
	if cur.ID != nr.ID {
		t.Fatal("successor should become the active root (latest expiry)")
	}
	crossPEM, _ := svc.CrossCertificate(ctx, nr.ID)
	cross, err := parsePEMCert(crossPEM)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, _ := parsePEMCert(old.CertPEM)
	if err := cross.CheckSignatureFrom(oldCert); err != nil {
		t.Fatal(err)
	}
}

func TestImport(t *testing.T) {
	src, srcStore := newCA(t)
	ctx := context.Background()
	root, _ := src.Root(ctx)
	k, _ := srcStore.GetKey(ctx, root.KeyID)
	key, _ := src.keys.Load(k.Blob)
	der, _ := x509.MarshalPKCS8PrivateKey(key)

	st, _ := store.Open(":memory:")
	defer st.Close()
	dst := New(st, signer.NewSoftware(), "https://conrad.test", nil)
	_, iss, err := dst.Import(ctx, ImportRequest{Secret: pass, RootCertPEM: root.CertPEM, RootKeyPEM: EncodePEM("PRIVATE KEY", der)})
	if err != nil {
		t.Fatal(err)
	}
	if !iss.IsDefault {
		t.Fatal("imported hierarchy should get a default issuer")
	}
	rec, err := dst.Issue(ctx, "", *leafKey(t))
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, dst, rec)
}

func TestMobileConfig(t *testing.T) {
	b, err := MobileConfig("Conrad", []byte{1, 2, 3})
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
}
