//go:build pkcs11

package server

import (
	"github.com/davidemaggi/conrad/internal/config"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
)

func init() {
	NewPKCS11 = func(cfg *config.Config) (signer.Provider, error) {
		return signer.NewPKCS11(cfg.PKCS11.Module, cfg.PKCS11.TokenLabel)
	}
}
