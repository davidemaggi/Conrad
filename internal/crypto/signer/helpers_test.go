package signer

import (
	"crypto"
	"crypto/ecdsa"
)

func verifyECDSA(pub crypto.PublicKey, digest, sig []byte) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && ecdsa.VerifyASN1(k, digest, sig)
}
