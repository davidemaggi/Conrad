// Package signer abstracts where CA private keys live: an encrypted blob in
// the database (software) or a PKCS#11 token (HSM).
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// Algorithm identifies a key type.
type Algorithm string

const (
	ECDSAP256 Algorithm = "ecdsa-p256"
	ECDSAP384 Algorithm = "ecdsa-p384"
	RSA2048   Algorithm = "rsa-2048"
	RSA3072   Algorithm = "rsa-3072"
	RSA4096   Algorithm = "rsa-4096"
)

// ErrLocked is returned when keys are requested before the provider is unlocked.
var ErrLocked = errors.New("key provider is locked")

// Provider creates and loads CA keys. The blob it returns is opaque and is
// persisted by the caller; it is all the provider needs to load the key again.
type Provider interface {
	// Name is "software" or "pkcs11".
	Name() string
	Unlocked() bool
	Generate(alg Algorithm, label string) (blob []byte, s crypto.Signer, err error)
	Load(blob []byte) (crypto.Signer, error)
	// Import stores an existing private key (software only; HSMs return an error).
	Import(key crypto.Signer) ([]byte, error)
}

// GenerateKey creates a plain in-memory key (used for leaf keys and tests).
func GenerateKey(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// AlgorithmOf describes a public key with the Algorithm vocabulary (plus "ed25519").
func AlgorithmOf(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return string(ECDSAP256)
		case elliptic.P384():
			return string(ECDSAP384)
		case elliptic.P521():
			return "ecdsa-p521"
		}
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	case ed25519.PublicKey:
		return "ed25519"
	}
	return "unknown"
}

// SignatureAlgorithm picks the x509 signature algorithm for a CA key.
func SignatureAlgorithm(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P384() {
			return x509.ECDSAWithSHA384
		}
		return x509.ECDSAWithSHA256
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case ed25519.PublicKey:
		return x509.PureEd25519
	}
	return x509.UnknownSignatureAlgorithm
}
