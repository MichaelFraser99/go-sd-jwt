package jose

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jose/algorithms/es256"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jose/algorithms/es384"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jose/algorithms/es512"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/jose/error"
)

type Signer interface {
	ValidateSignature(token, signature string, publicKey string) (bool, error)
	Sign(body map[string]any, headerKeys map[string]string) (*string, crypto.PrivateKey, crypto.PublicKey, error)
	SignWithKey(body map[string]any, headerKeys map[string]string, privateKey string) (*string, error)
}

func GetSigner(alg string) (Signer, error) {
	var s Signer
	switch alg {
	case "ES256":
		s = &es256.ES256{}
	case "ES384":
		s = &es384.ES384{}
	case "ES512":
		s = &es512.ES512{}

	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg)}
	}

	return s, nil
}
