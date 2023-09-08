package es512

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type PublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (pubKey *PublicKey) Equal(x PublicKey) bool {
	if pubKey.X == x.X && pubKey.Y == x.Y && pubKey.Kty == x.Kty && pubKey.Crv == x.Crv {
		return true
	}
	return false
}

type ES512 struct{}

func (signer *ES512) ValidateSignature(token, signature string, publicKeyJson string) (bool, error) {
	curve := elliptic.P521()

	var publicKey PublicKey
	err := json.Unmarshal([]byte(publicKeyJson), &publicKey)
	if err != nil {
		return false, errors.New("provided public key json isn't valid es512 public key")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return false, err
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return false, err
	}

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}

	bodyHash := sha512.Sum512([]byte(token))

	r, s, err := signer.extractRSFromSignature(signature)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, bodyHash[:], r, s), nil
}

func (signer *ES512) extractRSFromSignature(signature string) (*big.Int, *big.Int, error) {
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, err
	}

	if len(decodedSignature) < 130 || len(decodedSignature) > 132 {
		return nil, nil, errors.New("signature should be between 130 and 132 bytes for ES512")
	}
	rb := decodedSignature[:66]
	sb := decodedSignature[66:]

	r := big.NewInt(0).SetBytes(rb)
	s := big.NewInt(0).SetBytes(sb)

	return r, s, nil
}

func (signer *ES512) Sign(body map[string]interface{}, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error) {
	curve := elliptic.P521()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	header := headerKeys
	header["alg"] = "ES512"

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, nil, errors.New("failed to marshal header to bytes")
	}
	base64Header := base64.RawURLEncoding.EncodeToString(headerBytes)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, nil, nil, errors.New("failed to marshal body to bytes")
	}
	base64Body := base64.RawURLEncoding.EncodeToString(bodyBytes)

	token := fmt.Sprintf("%s.%s", base64Header, base64Body)

	digest := sha512.Sum512([]byte(token))

	r, s, err := ecdsa.Sign(rand.Reader, pk, digest[:])
	if err != nil {
		return nil, nil, nil, err
	}

	sigBytes := make([]byte, 132)

	r.FillBytes(sigBytes[0:66])
	s.FillBytes(sigBytes[66:])

	base64Sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	signedToken := fmt.Sprintf("%s.%s", token, base64Sig)

	cryptoPubKey := pk.PublicKey

	xb := make([]byte, 66)
	yb := make([]byte, 66)

	cryptoPubKey.X.FillBytes(xb)
	cryptoPubKey.Y.FillBytes(yb)

	x := base64.RawURLEncoding.EncodeToString(xb)
	y := base64.RawURLEncoding.EncodeToString(yb)

	pubKey := PublicKey{
		Kty: "EC",
		Crv: "P-521",
		X:   x,
		Y:   y,
	}

	return &signedToken, pk, pubKey, nil

}
func (signer *ES512) SignWithKey(body map[string]interface{}, headerKeys map[string]string, privateKey string) (*string, error) {
	return nil, nil //todo
}
