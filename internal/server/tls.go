package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
)

// tlsManager serves Conrad's own certificate: self-signed until the CA is
// ready, then issued by the default issuer, persisted and renewed at 2/3 of its life.
type tlsManager struct {
	s    *Server
	dir  string
	mu   sync.Mutex
	cert atomic.Pointer[tls.Certificate]
}

func (m *tlsManager) config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.cert.Load(), nil
		},
	}
}

func (m *tlsManager) paths() (string, string) {
	return filepath.Join(m.dir, "cert.pem"), filepath.Join(m.dir, "key.pem")
}

// refresh makes sure a usable certificate is loaded. force re-issues from the CA.
func (m *tlsManager) refresh(ctx context.Context, force bool) error {
	if m.s.Cfg.TLSMode != "self" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ready := false
	if init, _ := m.s.CA.Initialized(ctx); init && !m.s.CA.Locked() {
		ready = true
	}
	if !force {
		if c := m.loadDisk(ctx); c != nil {
			m.cert.Store(c)
			return nil
		}
	}
	if ready {
		c, err := m.issue(ctx)
		if err == nil {
			m.cert.Store(c)
			m.s.Log.Info("installed TLS certificate from the default issuer", "hosts", m.s.serverHosts(), "not_after", c.Leaf.NotAfter)
			return nil
		}
		m.s.Log.Error("issuing server certificate failed; keeping the current one", "err", err)
	}
	if m.cert.Load() == nil {
		c, err := selfSigned(m.s.serverHosts())
		if err != nil {
			return err
		}
		m.cert.Store(c)
		m.s.Log.Warn("serving a temporary self-signed certificate until the CA is ready")
	}
	return nil
}

// loadDisk returns the persisted certificate if it is still fresh and chains to the default issuer.
func (m *tlsManager) loadDisk(ctx context.Context) *tls.Certificate {
	cp, kp := m.paths()
	c, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil || c.Leaf == nil {
		return nil
	}
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	if time.Now().After(c.Leaf.NotBefore.Add(life * 2 / 3)) {
		return nil
	}
	for _, h := range m.s.serverHosts() {
		if c.Leaf.VerifyHostname(h) != nil {
			return nil
		}
	}
	if iss, err := m.s.CA.Issuer(ctx, ""); err == nil {
		if ic, err := ca.ParseCertificatesPEM([]byte(iss.CertPEM)); err == nil && len(ic) > 0 {
			if !bytes.Equal(c.Leaf.AuthorityKeyId, ic[0].SubjectKeyId) {
				return nil
			}
		}
	}
	return &c
}

func (m *tlsManager) issue(ctx context.Context) (*tls.Certificate, error) {
	var req ca.IssueRequest
	for _, h := range m.s.serverHosts() {
		if ip := net.ParseIP(h); ip != nil {
			req.IPs = append(req.IPs, ip)
		} else {
			req.DNSNames = append(req.DNSNames, h)
		}
	}
	req.Source, req.Validity = "system", ca.DefaultLeafValidity
	rec, key, err := m.s.CA.IssueWithKey(ctx, "", signer.ECDSAP256, req)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	c, err := tls.X509KeyPair([]byte(rec.ChainPEM), keyPEM)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.dir, 0o700); err == nil {
		cp, kp := m.paths()
		_ = os.WriteFile(kp, keyPEM, 0o600)
		_ = os.WriteFile(cp, []byte(rec.ChainPEM), 0o600)
	}
	return &c, nil
}

func selfSigned(hosts []string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Conrad (temporary)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range append(slices.Clone(hosts), "localhost") {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
