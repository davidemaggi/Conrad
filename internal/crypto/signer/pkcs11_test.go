//go:build pkcs11

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"
)

// Run with a SoftHSM token, e.g.:
//
//	softhsm2-util --init-token --free --label conrad-test --pin 1234 --so-pin 1234
//	CONRAD_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so go test -tags pkcs11 ./internal/crypto/signer
func TestPKCS11(t *testing.T) {
	module := os.Getenv("CONRAD_TEST_PKCS11_MODULE")
	if module == "" {
		t.Skip("CONRAD_TEST_PKCS11_MODULE not set")
	}
	label := os.Getenv("CONRAD_TEST_PKCS11_TOKEN")
	if label == "" {
		label = "conrad-test"
	}
	pin := os.Getenv("CONRAD_TEST_PKCS11_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := NewPKCS11(module, label)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unlocked() {
		t.Fatal("new provider should be locked")
	}
	if _, _, err := p.Generate(ECDSAP256, "x"); err != ErrLocked {
		t.Fatalf("generate while locked: %v", err)
	}
	if err := p.Login("wrong"); err == nil {
		t.Fatal("wrong PIN accepted")
	}
	if err := p.Login(pin); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	digest := sha256.Sum256([]byte("approved"))
	for _, alg := range []Algorithm{ECDSAP256, ECDSAP384, RSA2048} {
		blob, s, err := p.Generate(alg, string(alg))
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if got := AlgorithmOf(s.Public()); got != string(alg) {
			t.Fatalf("algorithm %s, want %s", got, alg)
		}
		loaded, err := p.Load(blob)
		if err != nil {
			t.Fatalf("%s load: %v", alg, err)
		}
		sig, err := loaded.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		switch pub := s.Public().(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatalf("%s: bad signature", alg)
			}
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
		}
	}
	if _, err := p.Import(nil); err == nil {
		t.Fatal("import should fail")
	}
}
