package es256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jose/algorithms/common"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/jose/error"
)

type ES256 struct{}

func (signer *ES256) ValidateSignature(token, signature string, publicKeyJson string) (bool, error) {
	pk, err := common.NewPublicKeyFromJson(publicKeyJson, elliptic.P256())
	if err != nil {
		return false, err
	}

	bodyHash := sha256.Sum256([]byte(token))

	r, s, err := common.ExtractRSFromSignature(signature, 64)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, bodyHash[:], r, s), nil
}

func (signer *ES256) Sign(body map[string]interface{}, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error) {
	curve := elliptic.P256()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, &e.SigningError{Message: fmt.Sprintf("failed to generate key: %s", err.Error())}
	}

	token, err := common.GenerateToken("ES256", headerKeys, body)
	if err != nil {
		return nil, nil, nil, err
	}

	digest := sha256.Sum256([]byte(*token))

	signedToken, err := common.SignToken(*token, *pk, digest[:], 64)
	if err != nil {
		return nil, nil, nil, err
	}

	pubKey := common.GeneratePublicKey(*pk, "P-256", 64)

	return signedToken, pk, pubKey, nil
}
func (signer *ES256) SignWithKey(body map[string]interface{}, headerKeys map[string]string, privateKey string) (*string, error) {
	return nil, nil //todo
}
