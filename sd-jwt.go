// Package go_sd_jwt provides a library for creating and validating SD-JWTs.
// The resulting SdJwt object exposes methods for retrieving the claims and
// disclosures as well as retrieving all disclosed claims in line with the specification.
package go_sd_jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	e "github.com/MichaelFraser99/go-sd-jwt/internal/error"
	"github.com/MichaelFraser99/go-sd-jwt/internal/model"
	"github.com/MichaelFraser99/go-sd-jwt/internal/utils"
	"hash"
	"slices"
	"strings"
	"time"
)

// SdJwt this object represents a valid SD-JWT. Created using the FromToken function which performs the required validation.
// Helper methods are provided for retrieving the contents
type SdJwt struct {
	head        map[string]any
	body        map[string]any
	signature   string
	kbJwt       *string
	disclosures []disclosure.Disclosure
}

// New
// Creates a new SD-JWT from a JWT format token.
// The token is validated inline with the SD-JWT specification.
// If the token is valid, a new SdJwt object is returned.
// If a kb-jwt is included, the contents of this too will be validated.
func New(token string) (*SdJwt, error) {
	return validateJwt(token)
}

// NewFromJws
// Creates a new SD-JWT from a JWS format token.
// The token is validated inline with the SD-JWT specification.
// If the token is valid, a new SdJwt object is returned.
// If a kb-jwt is included, the contents of this too will be validated.
func NewFromJws(token string) (*SdJwt, error) {
	jwsSdjwt := model.JwsSdJwt{}
	err := json.Unmarshal([]byte(token), &jwsSdjwt)
	if err != nil {
		return nil, fmt.Errorf("%winvalid JSON provided", e.InvalidToken)
	}

	if jwsSdjwt.Payload != nil && jwsSdjwt.Protected != nil && jwsSdjwt.Signature != nil {
		return validateJws(jwsSdjwt)
	} else {
		return nil, fmt.Errorf("%winvalid JWS format SD-JWT provided", e.InvalidToken)
	}
}

// todo: refactor this - its not overly flexible
func (s *SdJwt) AddKeyBindingJwt(signer crypto.Signer, hash crypto.Hash, alg, aud, nonce string) error {
	if s.kbJwt != nil {
		return errors.New("key binding jwt already exists")
	}

	sdAlg, ok := s.body["_sd_alg"].(string)
	if (ok && strings.ToLower(sdAlg) != strings.ToLower(hash.String())) || strings.ToLower(hash.String()) != "sha-256" {
		return errors.New("key binding jwt hashing algorithm does not match the hashing algorithm specified in the sd-jwt - if sd-jwt does not specify a hashing algorithm, sha-256 is selected by default")
	}

	kbHead := map[string]string{
		"typ": "kb+jwt",
		"alg": strings.ToUpper(alg),
	}

	kbBody := map[string]any{
		"iat":      time.Now().Unix(),
		"aud":      aud,
		"nonce":    nonce,
		"_sd_hash": "", //todo: calculate hash of sd-jwt
	}

	bKbHead, err := json.Marshal(kbHead)
	if err != nil {
		return fmt.Errorf("error marshalling kb-jwt header: %w", err)
	}

	b64KbHead := make([]byte, base64.RawURLEncoding.EncodedLen(len(bKbHead)))
	base64.RawURLEncoding.Encode(b64KbHead, bKbHead)

	bKbBody, err := json.Marshal(kbBody)
	if err != nil {
		return fmt.Errorf("error marshalling kb-jwt body: %w", err)
	}

	b64KbBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(bKbBody)))
	base64.RawURLEncoding.Encode(b64KbBody, bKbBody)

	signInput := string(b64KbHead) + "." + string(b64KbBody)

	sig, err := signer.Sign(rand.Reader, []byte(signInput), nil)
	if err != nil {
		return fmt.Errorf("error signing kb-jwt: %w", err)
	}

	b64Sig := make([]byte, base64.RawURLEncoding.EncodedLen(len(sig)))
	base64.RawURLEncoding.Encode(b64Sig, sig)

	kbJwt := signInput + "." + string(b64Sig)

	s.kbJwt = &kbJwt
	return nil
}

// GetDisclosedClaims returns the claims that were disclosed in the token or included as plaintext values.
// This function will error one of the following scenarios is encountered:
// 1. The SD-JWT contains a disclosure that does not match an included digest
// 2. The SD-JWT contains a malformed _sd claim
// 3. The SD-JWT contains an unsupported value for the _sd_alg claim
// 4. The SD-JWT has a disclosure that is malformed for the use (e.g. doesn't contain a claim name for a non-array digest)
func (s *SdJwt) GetDisclosedClaims() (map[string]any, error) {

	disclosuresToCheck := make([]disclosure.Disclosure, len(s.disclosures))
	copy(disclosuresToCheck, s.disclosures)

	var h hash.Hash

	strAlg, ok := s.body["_sd_alg"].(string)
	if ok {
		switch strings.ToLower(strAlg) {
		case "sha-256", "":
			// default to sha-256
			h = sha256.New()
		case "sha-224":
			h = sha256.New224()
		case "sha-512":
			h = sha512.New()
		case "sha-384":
			h = sha512.New384()
		case "sha-512/224":
			h = sha512.New512_224()
		case "sha-512/256":
			h = sha512.New512_256()
		case "sha3-224":
			h = crypto.SHA3_224.New()
		case "sha3-256":
			h = crypto.SHA3_256.New()
		case "sha3-384":
			h = crypto.SHA3_384.New()
		case "sha3-512":
			h = crypto.SHA3_512.New()
		default:
			return nil, errors.New("unsupported _sd_alg: " + s.body["_sd_alg"].(string))
		}
	} else {
		h = sha256.New()
	}

	bodyMap := utils.CopyMap(*s.Body())

	for {
		var indexesFound []int
		for i := 0; i < len(disclosuresToCheck); i++ {
			d := disclosuresToCheck[i]

			h.Write([]byte(d.EncodedValue))
			hashedDisclosures := h.Sum(nil)
			base64HashedDisclosureBytes := make([]byte, base64.RawURLEncoding.EncodedLen(len(hashedDisclosures)))
			base64.RawURLEncoding.Encode(base64HashedDisclosureBytes, hashedDisclosures)

			found, err := utils.ValidateSDClaims(utils.PointerMap(bodyMap), &d, string(base64HashedDisclosureBytes))
			if err != nil {
				return nil, err
			}

			if found {
				indexesFound = append(indexesFound, i)
			}
			h.Reset()
		}

		if len(indexesFound) == 0 {
			return nil, fmt.Errorf("no matching digest found for: %v", utils.StringifyDisclosures(disclosuresToCheck))
		}
		slices.Sort(indexesFound)
		slices.Reverse(indexesFound)
		for _, i := range indexesFound {
			disclosuresToCheck = append(disclosuresToCheck[:i], disclosuresToCheck[i+1:]...)
		}
		if len(disclosuresToCheck) == 0 {
			break
		}
	}

	bodyMap = utils.StripSDClaims(bodyMap)

	return bodyMap, nil
}

func validateJwt(token string) (*SdJwt, error) {
	sdJwt := &SdJwt{}

	sections := strings.Split(token, "~")
	if len(sections) < 2 {
		return nil, fmt.Errorf("%wtoken has no specified disclosures", e.InvalidToken)
	}

	tokenSections := strings.Split(sections[0], ".")

	if len(tokenSections) != 3 {
		return nil, fmt.Errorf("%wtoken is not a valid JWT", e.InvalidToken)
	}

	jwtHead := map[string]any{}
	hb, err := base64.RawURLEncoding.DecodeString(tokenSections[0])
	if err != nil {
		return nil, fmt.Errorf("%wfailed to decode header: %s", e.InvalidToken, err.Error())
	}

	err = json.Unmarshal(hb, &jwtHead)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to json parse decoded header: %s", e.InvalidToken, err.Error())
	}

	sdJwt.head = jwtHead

	sdJwt.signature = tokenSections[2]

	if sections[len(sections)-1] != "" && sections[len(sections)-1][len(sections[len(sections)-1])-1:] != "~" {
		kbJwt := utils.CheckForKbJwt(sections[len(sections)-1])

		if kbJwt == nil {
			return nil, fmt.Errorf("%wif no kb-jwt is provided, the last disclosure must be followed by a ~", e.InvalidToken)
		}
		sdJwt.kbJwt = kbJwt
		sections = sections[:len(sections)-1]
	}

	disclosures, err := utils.ValidateDisclosures(sections[1:])
	if err != nil {
		return nil, fmt.Errorf("%wfailed to validate disclosures: %s", e.InvalidToken, err.Error())
	}
	sdJwt.disclosures = disclosures

	b, err := base64.RawURLEncoding.DecodeString(tokenSections[1])
	if err != nil {
		return nil, fmt.Errorf("%wfailed to decode payload: %s", e.InvalidToken, err.Error())
	}

	var m map[string]any
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to json parse decoded payload: %s", e.InvalidToken, err.Error())
	}

	err = utils.ValidateDigests(m)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to validate digests: %s", e.InvalidToken, err.Error())
	}

	sdJwt.body = m

	if sdJwt.kbJwt != nil {
		err = utils.ValidateKbJwt(*sdJwt.kbJwt, sdJwt.body)

		if err != nil {
			return nil, fmt.Errorf("%wfailed to validate kb-jwt: %s", e.InvalidToken, err.Error())
		}
	}

	return sdJwt, nil
}

func validateJws(token model.JwsSdJwt) (*SdJwt, error) {
	sdJwt := &SdJwt{}

	sdJwt.kbJwt = token.KbJwt

	b, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to json parse provided jws token: %s", e.InvalidToken, err.Error())
	}

	hb, err := base64.RawURLEncoding.DecodeString(*token.Protected)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to decode protected header: %s", e.InvalidToken, err.Error())
	}
	var head map[string]any
	err = json.Unmarshal(hb, &head)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to json parse decoded protected header: %s", e.InvalidToken, err.Error())
	}
	sdJwt.head = head

	sdJwt.signature = *token.Signature

	disclosures, err := utils.ValidateDisclosures(token.Disclosures)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to validate disclosures: %s", e.InvalidToken, err.Error())
	}

	sdJwt.disclosures = disclosures

	b, err = base64.RawURLEncoding.DecodeString(*token.Payload)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to decode payload: %s", e.InvalidToken, err.Error())
	}

	var m map[string]any
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to json parse decoded payload: %s", e.InvalidToken, err.Error())
	}

	err = utils.ValidateDigests(m)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to validate digests: %s", e.InvalidToken, err.Error())
	}

	sdJwt.body = m

	if sdJwt.kbJwt != nil {
		err = utils.ValidateKbJwt(*sdJwt.kbJwt, sdJwt.body)

		if err != nil {
			return nil, fmt.Errorf("%wfailed to validate kb-jwt: %s", e.InvalidToken, err.Error())
		}
	}

	return sdJwt, nil
}

// Body returns the body of the JWT
func (s *SdJwt) Body() *map[string]any {
	return &s.body
}

// Signature returns the signature of the provided token used to verify it
func (s *SdJwt) Signature() string {
	return s.signature
}

// Head returns the head of the JWT
func (s *SdJwt) Head() map[string]any {
	return s.head
}

// Disclosures returns the disclosures of the SD-JWT
func (s *SdJwt) Disclosures() []disclosure.Disclosure {
	return s.disclosures
}

// KbJwt returns the signed kb-jwt (if provided)
func (s *SdJwt) KbJwt() *string {
	return s.kbJwt
}
