package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// ValidSlug reports whether s is a valid issuer slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) && !strings.Contains(s, "--") }

// randomSerial returns a positive 128-bit serial number.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	if b[0] == 0 {
		b[0] = 0x01
	}
	return new(big.Int).SetBytes(b), nil
}

// SerialHex formats a serial as lowercase hex.
func SerialHex(n *big.Int) string { return strings.ToLower(n.Text(16)) }

// Fingerprint returns the SHA-256 fingerprint of DER bytes as hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// FingerprintColon formats a hex fingerprint as AA:BB:...
func FingerprintColon(hexFP string) string {
	up := strings.ToUpper(hexFP)
	var parts []string
	for i := 0; i+2 <= len(up); i += 2 {
		parts = append(parts, up[i:i+2])
	}
	return strings.Join(parts, ":")
}

// EncodePEM encodes DER as a PEM block.
func EncodePEM(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func parsePEMCert(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ParseCertificatesPEM parses every CERTIFICATE block in data.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	return out, nil
}

// ParsePrivateKeyPEM parses a PKCS#8, PKCS#1 or SEC1 private key.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("invalid private key PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key type %q", b.Type)
}

// publicKeysEqual compares public keys.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}
