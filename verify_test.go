package go_sd_jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-sd-jwt/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildSignedSDJWT(t *testing.T, head, body map[string]any, signer model.Signer) string {
	headBytes, err := json.Marshal(head)
	require.NoError(t, err)
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	b64Head := base64.RawURLEncoding.EncodeToString(headBytes)
	b64Body := base64.RawURLEncoding.EncodeToString(bodyBytes)
	signInput := b64Head + "." + b64Body

	sig, err := signer.Sign(rand.Reader, []byte(signInput), nil)
	require.NoError(t, err)

	b64Sig := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("%s.%s.%s~", b64Head, b64Body, b64Sig)
}

func TestVerify_IssuerSignature(t *testing.T) {
	signer, err := jws.GetSigner(model.ES256, nil)
	require.NoError(t, err)

	head := map[string]any{"alg": "ES256"}
	body := map[string]any{"sub": "user_42", "iss": "https://example.com", "_sd_alg": "sha-256"}

	token := buildSignedSDJWT(t, head, body, signer)

	sdJwt, err := New(token)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		err := sdJwt.Verify(VerificationOptions{IssuerKey: signer.Public()})
		assert.NoError(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		otherSigner, err := jws.GetSigner(model.ES256, nil)
		require.NoError(t, err)
		err = sdJwt.Verify(VerificationOptions{IssuerKey: otherSigner.Public()})
		require.Error(t, err)
		assert.Equal(t, "invalid token: signature verification failed", err.Error())
	})

	t.Run("no key skips verification", func(t *testing.T) {
		err := sdJwt.Verify(VerificationOptions{})
		assert.NoError(t, err)
	})
}

func TestVerify_Expiry(t *testing.T) {
	signer, err := jws.GetSigner(model.ES256, nil)
	require.NoError(t, err)

	head := map[string]any{"alg": "ES256"}

	t.Run("expired token", func(t *testing.T) {
		body := map[string]any{"exp": float64(time.Now().Unix() - 3600), "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{ValidateExpiry: true})
		require.Error(t, err)
		assert.Equal(t, "invalid token: token has expired", err.Error())
	})

	t.Run("valid expiry", func(t *testing.T) {
		body := map[string]any{"exp": float64(time.Now().Unix() + 3600), "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{ValidateExpiry: true})
		assert.NoError(t, err)
	})

	t.Run("no exp claim is fine", func(t *testing.T) {
		body := map[string]any{"sub": "test", "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{ValidateExpiry: true})
		assert.NoError(t, err)
	})

	t.Run("disabled by default", func(t *testing.T) {
		body := map[string]any{"exp": float64(time.Now().Unix() - 3600), "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{})
		assert.NoError(t, err)
	})
}

func TestVerify_NotBefore(t *testing.T) {
	signer, err := jws.GetSigner(model.ES256, nil)
	require.NoError(t, err)

	head := map[string]any{"alg": "ES256"}

	t.Run("not yet valid", func(t *testing.T) {
		body := map[string]any{"nbf": float64(time.Now().Unix() + 3600), "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{ValidateNotBefore: true})
		require.Error(t, err)
		assert.Equal(t, "invalid token: token is not yet valid", err.Error())
	})

	t.Run("already valid", func(t *testing.T) {
		body := map[string]any{"nbf": float64(time.Now().Unix() - 3600), "_sd_alg": "sha-256"}
		token := buildSignedSDJWT(t, head, body, signer)
		sdJwt, err := New(token)
		require.NoError(t, err)

		err = sdJwt.Verify(VerificationOptions{ValidateNotBefore: true})
		assert.NoError(t, err)
	})
}

func TestVerify_KBJwtAudienceAndNonce(t *testing.T) {
	issuerSigner, err := jws.GetSigner(model.ES256, nil)
	require.NoError(t, err)
	holderSigner, err := jws.GetSigner(model.ES256, nil)
	require.NoError(t, err)

	holderJwk, err := jwk.PublicJwk(holderSigner.Public())
	require.NoError(t, err)

	head := map[string]any{"alg": "ES256"}
	body := map[string]any{
		"sub":     "user_42",
		"_sd_alg": "sha-256",
		"cnf":    map[string]any{"jwk": *holderJwk},
	}

	token := buildSignedSDJWT(t, head, body, issuerSigner)
	sdJwt, err := New(token)
	require.NoError(t, err)

	sdToken, err := sdJwt.Token()
	require.NoError(t, err)

	h := sha256.New()
	h.Write([]byte(*sdToken))
	sdHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	kbHead := map[string]string{"typ": "kb+jwt", "alg": "ES256"}
	kbBody := map[string]any{
		"iat":     time.Now().Unix(),
		"aud":     "https://verifier.example.com",
		"nonce":   "abc123",
		"sd_hash": sdHash,
	}

	kbHeadBytes, _ := json.Marshal(kbHead)
	kbBodyBytes, _ := json.Marshal(kbBody)
	kbB64Head := base64.RawURLEncoding.EncodeToString(kbHeadBytes)
	kbB64Body := base64.RawURLEncoding.EncodeToString(kbBodyBytes)
	kbSignInput := kbB64Head + "." + kbB64Body

	kbSig, err := holderSigner.Sign(rand.Reader, []byte(kbSignInput), nil)
	require.NoError(t, err)
	kbB64Sig := base64.RawURLEncoding.EncodeToString(kbSig)

	fullToken := *sdToken + kbB64Head + "." + kbB64Body + "." + kbB64Sig
	sdJwtWithKb, err := New(fullToken)
	require.NoError(t, err)

	t.Run("matching audience", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			ExpectedAudience: utils.Pointer("https://verifier.example.com"),
		})
		assert.NoError(t, err)
	})

	t.Run("wrong audience", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			ExpectedAudience: utils.Pointer("https://wrong.example.com"),
		})
		require.Error(t, err)
		assert.Equal(t, "invalid token: kb-jwt audience mismatch: expected https://wrong.example.com", err.Error())
	})

	t.Run("matching nonce", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			ExpectedNonce: utils.Pointer("abc123"),
		})
		assert.NoError(t, err)
	})

	t.Run("wrong nonce", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			ExpectedNonce: utils.Pointer("wrong"),
		})
		require.Error(t, err)
		assert.Equal(t, "invalid token: kb-jwt nonce mismatch: expected wrong", err.Error())
	})

	t.Run("kb-jwt signature verification", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			VerifyKBJwtSignature: true,
		})
		assert.NoError(t, err)
	})

	t.Run("full verification", func(t *testing.T) {
		err := sdJwtWithKb.Verify(VerificationOptions{
			IssuerKey:            issuerSigner.Public(),
			VerifyKBJwtSignature: true,
			ExpectedAudience:     utils.Pointer("https://verifier.example.com"),
			ExpectedNonce:        utils.Pointer("abc123"),
		})
		assert.NoError(t, err)
	})
}
