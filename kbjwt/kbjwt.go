package kbjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/error"
	"strings"
)

type KbJwt struct {
	Iat    *int64  `json:"iat"`
	Aud    *string `json:"aud"`
	Nonce  *string `json:"nonce"`
	SdHash *string `json:"sd_hash"`
	Token  string  `json:"-"`
}

func NewFromToken(token string) (*KbJwt, error) {
	kbjc := strings.Split(token, ".")

	if len(kbjc) != 3 {
		return nil, fmt.Errorf("%wkb jwt is in an invalid format", e.ErrInvalidToken)
	}

	//head
	kbhb, err := base64.RawURLEncoding.DecodeString(kbjc[0])
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.ErrInvalidToken, err)
	}
	var kbh map[string]any
	err = json.Unmarshal(kbhb, &kbh)
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.ErrInvalidToken, err)
	}

	if kbh["typ"] != "kb+jwt" {
		return nil, fmt.Errorf("%wkb jwt is not of type kb+jwt", e.ErrInvalidToken)
	}

	//body
	kbbb, err := base64.RawURLEncoding.DecodeString(kbjc[1])
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.ErrInvalidToken, err)
	}
	var kbJwt KbJwt
	err = json.Unmarshal(kbbb, &kbJwt)
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.ErrInvalidToken, err)
	}

	//validation
	if kbJwt.Iat == nil {
		return nil, fmt.Errorf("%w%s", e.ErrInvalidToken, "iat field is missing")
	}
	if kbJwt.Aud == nil {
		return nil, fmt.Errorf("%w%s", e.ErrInvalidToken, "aud field is missing")
	}
	if kbJwt.Nonce == nil {
		return nil, fmt.Errorf("%w%s", e.ErrInvalidToken, "nonce field is missing")
	}
	if kbJwt.SdHash == nil {
		return nil, fmt.Errorf("%w%s", e.ErrInvalidToken, "sd_hash field is missing")
	}

	kbJwt.Token = token

	return &kbJwt, nil
}
