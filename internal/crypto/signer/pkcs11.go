//go:build pkcs11

package signer

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/eclipse-keypont/crypto11"
)

// PKCS11 keeps CA keys on a PKCS#11 token (HSM, YubiHSM, SoftHSM...).
// The stored blob only references the key by its CKA_ID; key material never leaves the token.
type PKCS11 struct {
	module, tokenLabel string

	mu  sync.RWMutex
	ctx *crypto11.Context
}

type pkcs11Blob struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// NewPKCS11 returns a locked provider; call Login with the user PIN.
func NewPKCS11(module, tokenLabel string) (*PKCS11, error) {
	if module == "" || tokenLabel == "" {
		return nil, errors.New("pkcs11: module and token label are required")
	}
	return &PKCS11{module: module, tokenLabel: tokenLabel}, nil
}

func (p *PKCS11) Name() string { return "pkcs11" }

func (p *PKCS11) Unlocked() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ctx != nil
}

// Login opens the token with the user PIN.
func (p *PKCS11) Login(pin string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx != nil {
		return nil
	}
	ctx, err := crypto11.Configure(&crypto11.Config{Path: p.module, TokenLabel: p.tokenLabel, Pin: pin})
	if err != nil {
		return fmt.Errorf("pkcs11: %w", err)
	}
	p.ctx = ctx
	return nil
}

// Close logs out of the token.
func (p *PKCS11) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx == nil {
		return nil
	}
	err := p.ctx.Close()
	p.ctx = nil
	return err
}

func (p *PKCS11) context() (*crypto11.Context, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.ctx == nil {
		return nil, ErrLocked
	}
	return p.ctx, nil
}

func (p *PKCS11) Generate(alg Algorithm, label string) ([]byte, crypto.Signer, error) {
	ctx, err := p.context()
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, err
	}
	lbl := []byte("conrad-" + label)
	var s crypto.Signer
	switch alg {
	case ECDSAP256:
		s, err = ctx.GenerateECDSAKeyPairWithLabel(id, lbl, elliptic.P256())
	case ECDSAP384:
		s, err = ctx.GenerateECDSAKeyPairWithLabel(id, lbl, elliptic.P384())
	case RSA2048, RSA3072, RSA4096:
		bits := map[Algorithm]int{RSA2048: 2048, RSA3072: 3072, RSA4096: 4096}[alg]
		s, err = ctx.GenerateRSAKeyPairWithLabel(id, lbl, bits)
	default:
		return nil, nil, fmt.Errorf("pkcs11: unsupported algorithm %q", alg)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11: generate: %w", err)
	}
	blob, _ := json.Marshal(pkcs11Blob{ID: hex.EncodeToString(id), Label: string(lbl)})
	return blob, s, nil
}

func (p *PKCS11) Load(blob []byte) (crypto.Signer, error) {
	ctx, err := p.context()
	if err != nil {
		return nil, err
	}
	var b pkcs11Blob
	if err := json.Unmarshal(blob, &b); err != nil {
		return nil, fmt.Errorf("pkcs11: bad key reference: %w", err)
	}
	id, err := hex.DecodeString(b.ID)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: bad key id: %w", err)
	}
	s, err := ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find key: %w", err)
	}
	if s == nil {
		return nil, fmt.Errorf("pkcs11: key %s not found on token", b.ID)
	}
	return s, nil
}

func (p *PKCS11) Import(crypto.Signer) ([]byte, error) {
	return nil, errors.New("pkcs11: importing private keys is not supported; generate the CA on the token")
}
