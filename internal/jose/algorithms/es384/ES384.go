package es384

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

type ES384 struct{}

func (signer *ES384) ValidateSignature(token, signature string, publicKeyJson string) (bool, error) {
	pk, err := common.NewPublicKeyFromJson(publicKeyJson, elliptic.P384())
	if err != nil {
		return false, err
	}

	bodyHash := sha512.Sum384([]byte(token))

	r, s, err := common.ExtractRSFromSignature(signature, 96)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, bodyHash[:], r, s), nil
}

func (signer *ES384) Sign(body map[string]interface{}, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error) {
	curve := elliptic.P384()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, &e.SigningError{Message: fmt.Sprintf("failed to generate key: %s", err.Error())}
	}

	token, err := common.GenerateToken("ES384", headerKeys, body)
	if err != nil {
		return nil, nil, nil, err
	}

	digest := sha512.Sum384([]byte(*token))

	signedToken, err := common.SignToken(*token, *pk, digest[:], 96)
	if err != nil {
		return nil, nil, nil, err
	}

	pubKey := common.GeneratePublicKey(*pk, "P-384", 96)

	return signedToken, pk, pubKey, nil
}
func (signer *ES384) SignWithKey(body map[string]interface{}, headerKeys map[string]string, privateKey string) (*string, error) {
	return nil, nil //todo
}
