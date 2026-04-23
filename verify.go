package go_sd_jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"

	e "github.com/MichaelFraser99/go-sd-jwt/internal/error"
)

// VerificationOptions configures what aspects of the SD-JWT are verified.
// All fields are optional — only checks with non-zero values are performed.
type VerificationOptions struct {
	IssuerKey            crypto.PublicKey
	ValidateExpiry       bool
	ValidateNotBefore    bool
	ExpectedAudience     *string
	ExpectedNonce        *string
	VerifyKBJwtSignature bool
}

// Verify performs cryptographic and semantic verification of the SD-JWT based on the provided options.
func (s *SdJwt) Verify(opts VerificationOptions) error {
	if opts.IssuerKey != nil {
		if err := s.verifyIssuerSignature(opts.IssuerKey); err != nil {
			return err
		}
	}

	if opts.ValidateExpiry {
		if err := s.validateExpiry(); err != nil {
			return err
		}
	}

	if opts.ValidateNotBefore {
		if err := s.validateNotBefore(); err != nil {
			return err
		}
	}

	if s.KbJwt != nil {
		if opts.ExpectedAudience != nil {
			if s.KbJwt.Aud == nil || *s.KbJwt.Aud != *opts.ExpectedAudience {
				return fmt.Errorf("%wkb-jwt audience mismatch: expected %s", e.ErrInvalidToken, *opts.ExpectedAudience)
			}
		}

		if opts.ExpectedNonce != nil {
			if s.KbJwt.Nonce == nil || *s.KbJwt.Nonce != *opts.ExpectedNonce {
				return fmt.Errorf("%wkb-jwt nonce mismatch: expected %s", e.ErrInvalidToken, *opts.ExpectedNonce)
			}
		}

		if opts.VerifyKBJwtSignature {
			if err := s.verifyKBJwtSignature(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *SdJwt) verifyIssuerSignature(issuerKey crypto.PublicKey) error {
	algStr, ok := s.Head["alg"].(string)
	if !ok {
		return fmt.Errorf("%wmissing or invalid 'alg' in header", e.ErrInvalidToken)
	}

	alg := josemodel.GetAlgorithm(algStr)
	if alg == nil {
		return fmt.Errorf("%wunsupported algorithm: %s", e.ErrInvalidToken, algStr)
	}

	validator, err := jws.GetValidator(*alg, issuerKey)
	if err != nil {
		return fmt.Errorf("%wfailed to create signature validator: %w", e.ErrInvalidToken, err)
	}

	headBytes, err := json.Marshal(s.Head)
	if err != nil {
		return fmt.Errorf("failed to marshal header for verification: %w", err)
	}
	bodyBytes, err := json.Marshal(s.Body)
	if err != nil {
		return fmt.Errorf("failed to marshal body for verification: %w", err)
	}

	signInput := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString(bodyBytes)

	sigBytes, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("%wfailed to decode signature: %w", e.ErrInvalidToken, err)
	}

	valid, err := validator.ValidateSignature([]byte(signInput), sigBytes)
	if err != nil {
		return fmt.Errorf("%wsignature verification error: %w", e.ErrInvalidToken, err)
	}
	if !valid {
		return fmt.Errorf("%wsignature verification failed", e.ErrInvalidToken)
	}

	return nil
}

func (s *SdJwt) validateExpiry() error {
	exp, ok := s.Body["exp"]
	if !ok {
		return nil
	}
	expFloat, ok := exp.(float64)
	if !ok {
		return fmt.Errorf("%w'exp' claim is not a valid number", e.ErrInvalidToken)
	}
	if time.Now().Unix() > int64(expFloat) {
		return fmt.Errorf("%wtoken has expired", e.ErrInvalidToken)
	}
	return nil
}

func (s *SdJwt) validateNotBefore() error {
	nbf, ok := s.Body["nbf"]
	if !ok {
		return nil
	}
	nbfFloat, ok := nbf.(float64)
	if !ok {
		return fmt.Errorf("%w'nbf' claim is not a valid number", e.ErrInvalidToken)
	}
	if time.Now().Unix() < int64(nbfFloat) {
		return fmt.Errorf("%wtoken is not yet valid", e.ErrInvalidToken)
	}
	return nil
}

func (s *SdJwt) verifyKBJwtSignature() error {
	cnf, ok := s.Body["cnf"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w'cnf' claim missing or invalid in issuer JWT", e.ErrInvalidToken)
	}

	jwkMap, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w'jwk' missing or invalid in 'cnf' claim", e.ErrInvalidToken)
	}

	holderKey, err := jwk.PublicFromJwk(jwkMap)
	if err != nil {
		return fmt.Errorf("%wfailed to parse holder public key from cnf.jwk: %w", e.ErrInvalidToken, err)
	}

	kbParts := strings.Split(s.KbJwt.Token, ".")
	if len(kbParts) != 3 {
		return fmt.Errorf("%wkb-jwt token is malformed", e.ErrInvalidToken)
	}

	kbHeadBytes, err := base64.RawURLEncoding.DecodeString(kbParts[0])
	if err != nil {
		return fmt.Errorf("%wfailed to decode kb-jwt header: %w", e.ErrInvalidToken, err)
	}

	var kbHead map[string]any
	if err := json.Unmarshal(kbHeadBytes, &kbHead); err != nil {
		return fmt.Errorf("%wfailed to parse kb-jwt header: %w", e.ErrInvalidToken, err)
	}

	kbAlgStr, ok := kbHead["alg"].(string)
	if !ok {
		return fmt.Errorf("%wmissing or invalid 'alg' in kb-jwt header", e.ErrInvalidToken)
	}

	kbAlg := josemodel.GetAlgorithm(kbAlgStr)
	if kbAlg == nil {
		return fmt.Errorf("%wunsupported kb-jwt algorithm: %s", e.ErrInvalidToken, kbAlgStr)
	}

	validator, err := jws.GetValidator(*kbAlg, holderKey)
	if err != nil {
		return fmt.Errorf("%wfailed to create kb-jwt signature validator: %w", e.ErrInvalidToken, err)
	}

	kbSignInput := kbParts[0] + "." + kbParts[1]

	kbSigBytes, err := base64.RawURLEncoding.DecodeString(kbParts[2])
	if err != nil {
		return fmt.Errorf("%wfailed to decode kb-jwt signature: %w", e.ErrInvalidToken, err)
	}

	valid, err := validator.ValidateSignature([]byte(kbSignInput), kbSigBytes)
	if err != nil {
		return fmt.Errorf("%wkb-jwt signature verification error: %w", e.ErrInvalidToken, err)
	}
	if !valid {
		return fmt.Errorf("%wkb-jwt signature verification failed", e.ErrInvalidToken)
	}

	return nil
}
