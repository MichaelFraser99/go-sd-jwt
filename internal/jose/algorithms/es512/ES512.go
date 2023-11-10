package es512

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jose/algorithms/common"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/jose/error"
)

type ES512 struct{}

func (signer *ES512) ValidateSignature(token, signature string, publicKeyJson string) (bool, error) {
	pk, err := common.NewPublicKeyFromJson(publicKeyJson, elliptic.P521())
	if err != nil {
		return false, err
	}

	bodyHash := sha512.Sum512([]byte(token))

	r, s, err := common.ExtractRSFromSignature(signature, 132)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, bodyHash[:], r, s), nil
}

func (signer *ES512) Sign(body map[string]any, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error) {
	curve := elliptic.P521()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, &e.SigningError{Message: fmt.Sprintf("failed to generate key: %s", err.Error())}
	}

	token, err := common.GenerateToken("ES512", headerKeys, body)
	if err != nil {
		return nil, nil, nil, err
	}

	digest := sha512.Sum512([]byte(*token))

	signedToken, err := common.SignToken(*token, *pk, digest[:], 132)
	if err != nil {
		return nil, nil, nil, err
	}

	pubKey := common.GeneratePublicKey(*pk, "P-521", 132)

	return signedToken, pk, pubKey, nil
}
func (signer *ES512) SignWithKey(body map[string]any, headerKeys map[string]string, privateKey string) (*string, error) {
	return nil, nil //todo
}
