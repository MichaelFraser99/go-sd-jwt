package salt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func NewSalt() (*string, error) {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("error generating salt value: %w", err)
	}
	saltValue := base64.RawURLEncoding.EncodeToString(randomBytes)
	return &saltValue, nil
}
