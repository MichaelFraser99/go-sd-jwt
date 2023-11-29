package disclosure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/error"
	s "github.com/MichaelFraser99/go-sd-jwt/internal/salt"
	"hash"
)

// Disclosure this object represents a single disclosure in a SD-JWT.
// Salt the base64url encoded cryptographically secure string used during generation
// Key the key of the disclosed value. Only present for disclosed object values and not set when for an array element
// Value the value being disclosed
// EncodedValue the resulting base64url encoded disclosure array
type Disclosure struct {
	Salt         string
	Key          *string
	Value        any
	EncodedValue string
}

func (d *Disclosure) Hash(hash hash.Hash) []byte {
	hash.Write([]byte(d.EncodedValue))
	hashedBytes := hash.Sum(nil)

	b64Hash := make([]byte, base64.RawURLEncoding.EncodedLen(len(hashedBytes)))
	base64.RawURLEncoding.Encode(b64Hash, hashedBytes)
	return b64Hash
}

func NewFromObject(key string, value any, salt *string) (*Disclosure, error) {
	if key == "" || key == "_sd" || key == "..." {
		return nil, fmt.Errorf("%winvalid key value provided, must not be empty, '_sd', or '...'", e.InvalidDisclosure)
	}

	var saltValue string
	if salt == nil {
		newSalt, err := s.NewSalt()
		if err != nil {
			return nil, err
		}
		saltValue = *newSalt
	} else {
		saltValue = *salt
	}

	disclosureArray := []any{saltValue, key, value}
	dBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return nil, fmt.Errorf("error encoding disclosure array as bytes: %w", err)
	}

	encodedDisclosureArray := make([]byte, base64.RawURLEncoding.EncodedLen(len(dBytes)))
	base64.RawURLEncoding.Encode(encodedDisclosureArray, dBytes)

	disclosure := &Disclosure{
		Salt:         saltValue,
		Key:          &key,
		Value:        value,
		EncodedValue: string(encodedDisclosureArray),
	}

	return disclosure, nil
}

func NewFromArrayElement(element any, salt *string) (*Disclosure, error) {
	var saltValue string
	if salt == nil {
		newSalt, err := s.NewSalt()
		if err != nil {
			return nil, err
		}
		saltValue = *newSalt
	} else {
		saltValue = *salt
	}

	disclosureArray := []any{saltValue, element}
	dBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return nil, fmt.Errorf("error encoding disclosure array as bytes: %w", err)
	}

	encodedDisclosureArray := make([]byte, base64.RawURLEncoding.EncodedLen(len(dBytes)))
	base64.RawURLEncoding.Encode(encodedDisclosureArray, dBytes)

	disclosure := &Disclosure{
		Salt:         saltValue,
		Value:        element,
		EncodedValue: string(encodedDisclosureArray),
	}

	return disclosure, nil
}

func NewFromDisclosure(disclosure string) (*Disclosure, error) {
	d := &Disclosure{
		EncodedValue: disclosure,
	}

	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		return nil, fmt.Errorf("%werror base64url decoding provided disclosure: %s", e.InvalidDisclosure, err.Error())
	}

	var dArray []any
	err = json.Unmarshal(decoded, &dArray)
	if err != nil {
		return nil, fmt.Errorf("%werror parsing decoded disclosure as array: %s", e.InvalidDisclosure, err.Error())
	}

	if len(dArray) == 2 {
		d.Salt = dArray[0].(string)
		d.Value = dArray[1]
	} else if len(dArray) == 3 {
		d.Salt = dArray[0].(string)
		d.Key = String(dArray[1].(string))
		d.Value = dArray[2]
	} else {
		return nil, fmt.Errorf("%winvalid disclosure contents: %s", e.InvalidDisclosure, string(decoded))
	}

	return d, nil
}

func String(s string) *string {
	return &s
}
