package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestSoftwareRoundTrip(t *testing.T) {
	s := NewSoftware()
	params, err := s.Initialize("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	blob, k, err := s.Generate(ECDSAP256, "test")
	if err != nil {
		t.Fatal(err)
	}

	// A fresh provider must unlock with the same passphrase and load the key.
	s2 := NewSoftware()
	if _, err := s2.Load(blob); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := s2.Unlock("wrong passphrase!!", params); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
	if err := s2.Unlock("correct horse battery staple", params); err != nil {
		t.Fatal(err)
	}
	k2, err := s2.Load(blob)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := k2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyECDSA(k.Public(), digest[:], sig) {
		t.Fatal("signature from reloaded key does not verify with original public key")
	}
}

func TestShortPassphraseRejected(t *testing.T) {
	if _, err := NewSoftware().Initialize("short"); err == nil {
		t.Fatal("expected error")
	}
}
