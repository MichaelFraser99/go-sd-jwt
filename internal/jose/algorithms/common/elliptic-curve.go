package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/jose/error"
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

func NewPublicKeyFromJson(publicKeyJson string, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	var publicKey PublicKey
	err := json.Unmarshal([]byte(publicKeyJson), &publicKey)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("provided public key json isn't valid es256 public key: %s", err.Error())}
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
	}

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}
	return pk, nil
}

func ExtractRSFromSignature(signature string, keySize int) (*big.Int, *big.Int, error) {
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, &e.InvalidSignature{Message: fmt.Sprintf("error decoding signature: %s", err.Error())}
	}

	if len(decodedSignature) != keySize {
		return nil, nil, &e.InvalidSignature{Message: fmt.Sprintf("signature should be %d bytes for given algorithm", keySize)}
	}
	rb := decodedSignature[:keySize/2]
	sb := decodedSignature[keySize/2:]

	r := big.NewInt(0).SetBytes(rb)
	s := big.NewInt(0).SetBytes(sb)

	return r, s, nil
}

func GenerateToken(alg string, header map[string]string, body map[string]any) (*string, error) {
	h := header
	h["alg"] = alg

	headerBytes, err := json.Marshal(h)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to marshal header to bytes: %s", err.Error())}
	}
	base64Header := base64.RawURLEncoding.EncodeToString(headerBytes)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to marshal body to bytes: %s", err.Error())}
	}
	base64Body := base64.RawURLEncoding.EncodeToString(bodyBytes)

	token := fmt.Sprintf("%s.%s", base64Header, base64Body)
	return &token, nil
}

func SignToken(token string, pk ecdsa.PrivateKey, digest []byte, keySize int) (*string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, &pk, digest)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to sign token: %s", err.Error())}
	}

	sigBytes := make([]byte, keySize)

	r.FillBytes(sigBytes[0 : keySize/2])
	s.FillBytes(sigBytes[keySize/2:])

	base64Sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	signedToken := fmt.Sprintf("%s.%s", token, base64Sig)
	return &signedToken, nil
}

func GeneratePublicKey(pk ecdsa.PrivateKey, curveName string, keySize int) PublicKey {
	cryptoPubKey := pk.PublicKey

	xb := make([]byte, keySize/2)
	yb := make([]byte, keySize/2)

	cryptoPubKey.X.FillBytes(xb)
	cryptoPubKey.Y.FillBytes(yb)

	x := base64.RawURLEncoding.EncodeToString(xb)
	y := base64.RawURLEncoding.EncodeToString(yb)

	return PublicKey{
		Kty: "EC",
		Crv: curveName,
		X:   x,
		Y:   y,
	}
}
