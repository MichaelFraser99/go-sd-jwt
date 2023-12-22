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
	"github.com/MichaelFraser99/go-sd-jwt/internal/utils"
	"github.com/MichaelFraser99/go-sd-jwt/kbjwt"
	"hash"
	"slices"
	"strings"
	"time"
)

// SdJwt this object represents a valid SD-JWT. Created using the FromToken function which performs the required validation.
// Helper methods are provided for retrieving the contents
type SdJwt struct {
	Head        map[string]any
	Body        map[string]any
	Signature   string
	KbJwt       *kbjwt.KbJwt
	Disclosures []disclosure.Disclosure
}

// New
// Creates a new SD-JWT from a JWT format token.
// The token is validated inline with the SD-JWT specification.
// If the token is valid, a new SdJwt object is returned.
// If a kb-jwt is included, the contents of this too will be validated.
func New(token string) (*SdJwt, error) {
	return validateJwt(token)
}

// NewFromComponents
// Creates a new SD-JWT from the individual components optionally taking in a kbJwt.
// The token is validated inline with the SD-JWT specification.
// If the token is valid, a new SdJwt object is returned.
// If a kb-jwt is included, the contents of this too will be validated.
// This function is designed to cater for the much more free-form JSON serialization options on offer
func NewFromComponents(protected, payload, signature string, disclosures []string, kbJwt *string) (*SdJwt, error) {
	token := fmt.Sprintf("%s.%s.%s", protected, payload, signature)
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosures, "~"))
	}
	if kbJwt != nil {
		token = fmt.Sprintf("%s%s", token, *kbJwt)
	}

	return validateJwt(token)
}

// AddKeyBindingJwt This method adds a keybinding jwt signed with the provided signer interface and hash
// If the provided hash does not match the hash algorithm specified in the SD Jwt (or isn't sha256 if no _sd_alg claim present), an error will be thrown
// The sd_hash value will be set based off of all disclosures present in the current sd jwt object
func (s *SdJwt) AddKeyBindingJwt(signer crypto.Signer, h crypto.Hash, alg, aud, nonce string) error {
	if s.KbJwt != nil {
		return errors.New("key binding jwt already exists")
	}

	sdAlg, ok := s.Body["_sd_alg"].(string)
	if (ok && !strings.EqualFold(sdAlg, h.String())) || (!ok && strings.ToLower(h.String()) != "sha-256") {
		return errors.New("key binding jwt hashing algorithm does not match the hashing algorithm specified in the sd-jwt - if sd-jwt does not specify a hashing algorithm, sha-256 is selected by default")
	}

	kbHead := map[string]string{
		"typ": "kb+jwt",
		"alg": strings.ToUpper(alg),
	}

	// calculate sd hash
	bSdHead, err := json.Marshal(s.Head)
	if err != nil {
		return fmt.Errorf("error marshalling sd-jwt header: %w", err)
	}
	b64SdHead := make([]byte, base64.RawURLEncoding.EncodedLen(len(bSdHead)))
	base64.RawURLEncoding.Encode(b64SdHead, bSdHead)

	bSdBody, err := json.Marshal(s.Body)
	if err != nil {
		return fmt.Errorf("error marshalling sd-jwt body: %w", err)
	}
	b64SdBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(bSdBody)))
	base64.RawURLEncoding.Encode(b64SdBody, bSdBody)

	disclosureString := ""
	for _, d := range s.Disclosures {
		disclosureString += d.EncodedValue + "~"
	}

	fullToken := fmt.Sprintf("%s.%s.%s~%s", string(b64SdHead), string(b64SdBody), s.Signature, disclosureString)
	hasher := h.New()
	hasher.Write([]byte(fullToken))
	hashedToken := hasher.Sum(nil)

	b64SdHash := make([]byte, base64.RawURLEncoding.EncodedLen(len(hashedToken)))
	base64.RawURLEncoding.Encode(b64SdHash, hashedToken)

	kbJwt := kbjwt.KbJwt{
		Iat:    utils.Pointer(time.Now().Unix()),
		Aud:    utils.Pointer(aud),
		Nonce:  utils.Pointer(nonce),
		SdHash: utils.Pointer(string(b64SdHash)),
	}

	bKbHead, err := json.Marshal(kbHead)
	if err != nil {
		return fmt.Errorf("error marshalling kb-jwt header: %w", err)
	}

	b64KbHead := make([]byte, base64.RawURLEncoding.EncodedLen(len(bKbHead)))
	base64.RawURLEncoding.Encode(b64KbHead, bKbHead)

	bKbBody, err := json.Marshal(kbJwt)
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

	kbJwt.Token = signInput + "." + string(b64Sig)

	s.KbJwt = &kbJwt
	return nil
}

func GetHash(hashString string) (hash.Hash, error) {
	var h hash.Hash
	switch strings.ToLower(hashString) {
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
		return nil, errors.New("unsupported _sd_alg: " + hashString)
	}
	return h, nil
}

// GetDisclosedClaims returns the claims that were disclosed in the token or included as plaintext values.
// This function will error one of the following scenarios is encountered:
// 1. The SD-JWT contains a disclosure that does not match an included digest
// 2. The SD-JWT contains a malformed _sd claim
// 3. The SD-JWT contains an unsupported value for the _sd_alg claim
// 4. The SD-JWT has a disclosure that is malformed for the use (e.g. doesn't contain a claim name for a non-array digest)
func (s *SdJwt) GetDisclosedClaims() (map[string]any, error) {

	disclosuresToCheck := make([]disclosure.Disclosure, len(s.Disclosures))
	copy(disclosuresToCheck, s.Disclosures)

	var h hash.Hash
	var err error
	strAlg, ok := s.Body["_sd_alg"].(string)
	if ok {
		h, err = GetHash(strAlg)
		if err != nil {
			return nil, err
		}
	} else {
		h = sha256.New()
	}

	bodyMap := utils.CopyMap(s.Body)

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

	sdJwt.Head = jwtHead

	sdJwt.Signature = tokenSections[2]

	if sections[len(sections)-1] != "" && sections[len(sections)-1][len(sections[len(sections)-1])-1:] != "~" {
		kbJwt := utils.CheckForKbJwt(sections[len(sections)-1])

		if kbJwt == nil {
			return nil, fmt.Errorf("%wif no kb-jwt is provided, the last disclosure must be followed by a ~", e.InvalidToken)
		}

		sections = sections[:len(sections)-1]

		if kbJwt != nil {
			sdJwt.KbJwt, err = kbjwt.NewFromToken(*kbJwt)
			if err != nil {
				return nil, fmt.Errorf("failed to extract kb-jwt: %w", err)
			}
		}
	}

	disclosures, err := utils.ValidateDisclosures(sections[1:])
	if err != nil {
		return nil, fmt.Errorf("%wfailed to validate disclosures: %s", e.InvalidToken, err.Error())
	}
	sdJwt.Disclosures = disclosures

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

	sdJwt.Body = m

	if sdJwt.KbJwt != nil {
		tokenBytes := []byte(fmt.Sprintf("%s~", strings.Join(sections, "~")))

		var h hash.Hash
		strAlg, ok := sdJwt.Body["_sd_alg"].(string)
		if ok {
			h, err = GetHash(strAlg)
			if err != nil {
				return nil, err
			}
		} else {
			h = sha256.New()
		}

		_, err = h.Write(tokenBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to hash provided token for kbjwt validation: %s", err.Error())
		}

		hashedToken := h.Sum(nil)
		b64Ht := make([]byte, base64.RawURLEncoding.EncodedLen(len(hashedToken)))
		base64.RawURLEncoding.Encode(b64Ht, hashedToken)

		if string(b64Ht) != *sdJwt.KbJwt.SdHash {
			return nil, fmt.Errorf("%wsd hash validation failed: calculated hash %s does not equal provided hash %s", e.InvalidToken, string(b64Ht), *sdJwt.KbJwt.SdHash)
		}
	}

	return sdJwt, nil
}
