package signer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/argon2"
)

// KDFParams are persisted (as JSON) so the passphrase can be re-derived.
type KDFParams struct {
	Salt    string `json:"salt"`    // base64
	Time    uint32 `json:"time"`    // iterations
	Memory  uint32 `json:"memory"`  // KiB
	Threads uint8  `json:"threads"` // parallelism
	Check   string `json:"check"`   // base64 AES-GCM(known plaintext) to verify the passphrase
}

var checkPlaintext = []byte("conrad-key-check-v1")

// ErrBadPassphrase is returned by Unlock when the passphrase is wrong.
var ErrBadPassphrase = errors.New("wrong passphrase")

// Software keeps CA keys as AES-256-GCM encrypted PKCS#8 blobs. The data key
// is derived from a passphrase with argon2id and only lives in memory.
type Software struct {
	mu  sync.RWMutex
	key []byte
}

func NewSoftware() *Software { return &Software{} }

func (s *Software) Name() string { return "software" }

func (s *Software) Unlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key != nil
}

// Initialize derives a fresh data key from passphrase, unlocks the provider
// and returns the parameters to persist.
func (s *Software) Initialize(passphrase string) (KDFParams, error) {
	if len(passphrase) < 12 {
		return KDFParams{}, errors.New("passphrase must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	p := KDFParams{Salt: base64.StdEncoding.EncodeToString(salt), Time: 3, Memory: 64 * 1024, Threads: 4}
	key := p.derive(passphrase)
	check, err := seal(key, checkPlaintext)
	if err != nil {
		return KDFParams{}, err
	}
	p.Check = base64.StdEncoding.EncodeToString(check)
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	return p, nil
}

// Unlock verifies passphrase against p and keeps the derived key in memory.
func (s *Software) Unlock(passphrase string, p KDFParams) error {
	key := p.derive(passphrase)
	check, err := base64.StdEncoding.DecodeString(p.Check)
	if err != nil {
		return fmt.Errorf("corrupt kdf params: %w", err)
	}
	pt, err := open(key, check)
	if err != nil || subtle.ConstantTimeCompare(pt, checkPlaintext) != 1 {
		return ErrBadPassphrase
	}
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	return nil
}

// Lock forgets the data key.
func (s *Software) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
}

func (s *Software) Generate(alg Algorithm, _ string) ([]byte, crypto.Signer, error) {
	k, err := GenerateKey(alg)
	if err != nil {
		return nil, nil, err
	}
	blob, err := s.Import(k)
	return blob, k, err
}

func (s *Software) Import(k crypto.Signer) ([]byte, error) {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if key == nil {
		return nil, ErrLocked
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return seal(key, der)
}

func (s *Software) Load(blob []byte) (crypto.Signer, error) {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if key == nil {
		return nil, ErrLocked
	}
	der, err := open(key, blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt key: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	sg, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return sg, nil
}

func (p KDFParams) derive(passphrase string) []byte {
	salt, _ := base64.StdEncoding.DecodeString(p.Salt)
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, 32)
}

// MarshalJSON helpers for persisting params as a setting.
func (p KDFParams) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

// ParseKDFParams parses the persisted JSON form.
func ParseKDFParams(s string) (KDFParams, error) {
	var p KDFParams
	err := json.Unmarshal([]byte(s), &p)
	return p, err
}

func seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
