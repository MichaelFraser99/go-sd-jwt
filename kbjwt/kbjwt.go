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
	Token  string
}

func NewFromToken(token string) (*KbJwt, error) {
	kbjc := strings.Split(token, ".")

	if len(kbjc) != 3 {
		return nil, fmt.Errorf("%wkb jwt is in an invalid format", e.InvalidToken)
	}

	//head
	kbhb, err := base64.RawURLEncoding.DecodeString(kbjc[0])
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.InvalidToken, err)
	}
	var kbh map[string]any
	err = json.Unmarshal(kbhb, &kbh)
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.InvalidToken, err)
	}

	if kbh["typ"] != "kb+jwt" {
		return nil, fmt.Errorf("%wkb jwt is not of type kb+jwt", e.InvalidToken)
	}

	//body
	kbbb, err := base64.RawURLEncoding.DecodeString(kbjc[1])
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.InvalidToken, err)
	}
	var kbJwt KbJwt
	err = json.Unmarshal(kbbb, &kbJwt)
	if err != nil {
		return nil, fmt.Errorf("%w%w", e.InvalidToken, err)
	}

	//validation
	if kbJwt.Iat == nil {
		return nil, fmt.Errorf("%w%s", e.InvalidToken, "iat field is missing")
	}
	if kbJwt.Aud == nil {
		return nil, fmt.Errorf("%w%s", e.InvalidToken, "aud field is missing")
	}
	if kbJwt.Nonce == nil {
		return nil, fmt.Errorf("%w%s", e.InvalidToken, "nonce field is missing")
	}
	if kbJwt.SdHash == nil {
		return nil, fmt.Errorf("%w%s", e.InvalidToken, "sd_hash field is missing")
	}

	kbJwt.Token = token

	return &kbJwt, nil
}
