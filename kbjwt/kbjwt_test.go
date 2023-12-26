package kbjwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/error"
	"testing"
)

func TestNewFromToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		validate func(jwt *KbJwt, err error)
	}{
		{
			name:  "valid KB jwt",
			token: "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJfajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM45J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g",
			validate: func(jwt *KbJwt, err error) {
				if err != nil {
					t.Errorf("No error should have been thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("No kb jwt returned")
				} else {
					if jwt.Token != "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJfajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM45J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g" {
						t.Error("Incorrect token value returned")
					}
					if jwt.Nonce == nil {
						t.Error("Nonce value not returned")
					}
					if jwt.Iat == nil {
						t.Error("Iat value not returned")
					}
					if jwt.Aud == nil {
						t.Error("Aud value not returned")
					}
					if jwt.SdHash == nil {
						t.Error("SdHash value not returned")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(NewFromToken(tt.token))
		})
	}
}

func FuzzNewFromToken(f *testing.F) {
	// Adding some valid JWTs
	f.Add(int64(1702316015), "kb+jwt", "https://verifier.example.org", "1234567890", "nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo")
	f.Add(int64(1702316015), "bad-type", "https://verifier.example.org", "1234567890", "nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo")
	f.Add(int64(1702316015), "kb+jwt", "", "1234567890", "nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo")
	f.Add(int64(1702316015), "kb+jwt", "https://verifier.example.org", "", "nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo")
	f.Add(int64(1702316015), "kb+jwt", "https://verifier.example.org", "1234567890", "")

	f.Fuzz(func(t *testing.T, iat int64, typ, aud, nonce, sdhash string) {
		token := NewJwt(t, iat, typ, aud, nonce, sdhash)
		kbjwt, err := NewFromToken(token)

		if kbjwt != nil {
			if err != nil {
				t.Errorf("No error should have been returned: %s", err.Error())
			}
			if kbjwt.Nonce == nil {
				t.Error("Nonce value not returned")
			} else {
				if *kbjwt.Nonce != string([]rune(nonce)) {
					t.Errorf("Incorrect nonce value returned: %s", *kbjwt.Nonce)
				}
			}
			if kbjwt.Iat == nil {
				t.Error("Iat value not returned")
			} else {
				if *kbjwt.Iat != iat {
					t.Errorf("Incorrect iat value returned: %d", *kbjwt.Iat)
				}
			}
			if kbjwt.Aud == nil {
				t.Error("Aud value not returned")
			} else {
				if *kbjwt.Aud != string([]rune(aud)) {
					t.Errorf("Incorrect aud value returned: %s", *kbjwt.Aud)
				}
			}
			if kbjwt.SdHash == nil {
				t.Error("SdHash value not returned")
			} else {
				if *kbjwt.SdHash != string([]rune(sdhash)) {
					t.Errorf("Incorrect sd_hash value returned: %s", *kbjwt.SdHash)
				}
			}
			if kbjwt.Token != token {
				t.Error("Incorrect token value included on return")
			}
		} else {
			if !errors.Is(err, e.InvalidToken) {
				t.Errorf("Unexpected error type returned: %s", err.Error())
			}
		}
	})
}

func NewJwt(t *testing.T, iat int64, typ, aud, nonce, sdhash string) string {
	signer, err := jws.GetSigner(model.RS256, nil)
	if err != nil {
		t.Fatalf("Error creating signer: %s", err.Error())
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": typ,
	}
	kbjwt := KbJwt{
		Iat:    &iat,
		Aud:    &aud,
		Nonce:  &nonce,
		SdHash: &sdhash,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("error marshalling header as json: %s", err.Error())
	}
	bb, err := json.Marshal(kbjwt)
	if err != nil {
		t.Fatalf("error marshalling body as json: %s", err.Error())
	}
	b64H := make([]byte, base64.RawURLEncoding.EncodedLen(len(hb)))
	b64B := make([]byte, base64.RawURLEncoding.EncodedLen(len(bb)))
	base64.RawURLEncoding.Encode(b64H, hb)
	base64.RawURLEncoding.Encode(b64B, bb)

	sig, err := signer.Sign(rand.Reader, []byte(fmt.Sprintf("%s.%s", string(hb), string(bb))), nil)
	if err != nil {
		t.Fatalf("error signing digest: %s", err.Error())
	}
	b64S := make([]byte, base64.RawURLEncoding.EncodedLen(len(sig)))
	base64.RawURLEncoding.Encode(b64S, sig)
	return fmt.Sprintf("%s.%s.%s", string(b64H), string(b64B), string(b64S))
}
