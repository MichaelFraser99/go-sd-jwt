package es384

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

type ES384 struct{}

func (signer *ES384) ValidateSignature(token, signature string, publicKeyJson string) (bool, error) {
	curve := elliptic.P384()

	var publicKey PublicKey
	err := json.Unmarshal([]byte(publicKeyJson), &publicKey)
	if err != nil {
		return false, errors.New("provided public key json isn't valid es384 public key")
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

	bodyHash := sha512.Sum384([]byte(token))

	r, s, err := signer.extractRSFromSignature(signature)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, bodyHash[:], r, s), nil
}

func (signer *ES384) extractRSFromSignature(signature string) (*big.Int, *big.Int, error) {
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, err
	}

	if len(decodedSignature) != 96 {
		return nil, nil, errors.New("signature should be 64 bytes for ES384")
	}
	rb := decodedSignature[:48]
	sb := decodedSignature[48:]

	r := big.NewInt(0).SetBytes(rb)
	s := big.NewInt(0).SetBytes(sb)

	return r, s, nil
}

func (signer *ES384) Sign(body map[string]interface{}, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error) {
	curve := elliptic.P384()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	header := headerKeys
	header["alg"] = "ES384"

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

	digest := sha512.Sum384([]byte(token))

	r, s, err := ecdsa.Sign(rand.Reader, pk, digest[:])
	if err != nil {
		return nil, nil, nil, err
	}

	rb := r.Bytes()
	sb := s.Bytes()

	sigBytes := append(rb, sb...)

	base64Sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	signedToken := fmt.Sprintf("%s.%s", token, base64Sig)

	cryptoPubKey := pk.PublicKey

	x := base64.RawURLEncoding.EncodeToString(cryptoPubKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(cryptoPubKey.Y.Bytes())

	pubKey := PublicKey{
		Kty: "EC",
		Crv: "P-384",
		X:   x,
		Y:   y,
	}

	return &signedToken, pk, pubKey, nil

}
func (signer *ES384) SignWithKey(body map[string]interface{}, headerKeys map[string]string, privateKey string) (*string, error) {
	return nil, nil //todo
}
