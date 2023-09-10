// Package go_sd_jwt provides a library for creating and validating SD-JWTs.
// The resulting SdJwt object exposes methods for retrieving the claims and
// disclosures as well as retrieving all disclosed claims in line with the specification.
package go_sd_jwt

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-sd-jwt/internal/jwt"
	"hash"
	"reflect"
	"strings"
)

// SdJwt this object represents a valid SD-JWT. Created using the FromToken function which performs the required validation.
// Helper methods are provided for retrieving the contents
type SdJwt struct {
	token       string
	head        map[string]any
	body        map[string]any
	signature   string
	publicKey   string
	kbJwt       *string
	disclosures []Disclosure
}

// Disclosure this object represents a single disclosure in a SD-JWT.
// Helper methods are provided for retrieving the contents
type Disclosure struct {
	salt         string
	claimName    *string
	claimValue   string
	rawValue     string
	encodedValue string
}

type jwsSdJwt struct {
	Payload     *string  `json:"payload"`
	Protected   *string  `json:"protected"`
	Signature   *string  `json:"signature"`
	Disclosures []string `json:"disclosures"`
	KbJwt       *string  `json:"kb_jwt"`
}

type arrayDisclosure struct {
	Digest *string `json:"..."`
}

// FromToken
// Creates a new SD-JWT from a JWS or JWT format token.
// The token is validated inline with the SD-JWT specification.
// If the token is valid, a new SdJwt object is returned.
// The signature will be validated using the provided public key.
// The public key must be provided in JSON jwk format.
// If a cnf claim is present in the token AND the sd-jwt was sent with a kb-jwt, the kb-jwt will be validated.
func FromToken(token string, publicKey string) (*SdJwt, error) {
	jwsSdjwt := jwsSdJwt{}
	err := json.Unmarshal([]byte(token), &jwsSdjwt)
	if err == nil {
		if jwsSdjwt.Payload != nil && jwsSdjwt.Protected != nil && jwsSdjwt.Signature != nil {
			return validateJws(jwsSdjwt, publicKey)
		} else {
			return nil, errors.New("invalid JWS format SD-JWT provided")
		}
	} else {
		return validateJwt(token, publicKey)
	}
	//todo: check iat if present (have tolerance for clock skew, user defines how long jwt is valid for) - not sure if this is needed, might delegate to consumer
	//todo: check exp if present (have tolerance for clock skew) - not sure if this is needed, might delegate to consumer
	//todo: add toggle for key binding jwt validation
	//todo: allow consumer to pass a kb public key as cnf alternative
}

func validateJws(token jwsSdJwt, publicKey string) (*SdJwt, error) {
	sdJwt := &SdJwt{}

	sdJwt.publicKey = publicKey
	sdJwt.kbJwt = token.KbJwt

	b, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	sdJwt.token = string(b)

	hb, err := base64.RawURLEncoding.DecodeString(*token.Protected)
	if err != nil {
		return nil, err
	}
	var head map[string]any
	err = json.Unmarshal(hb, &head)
	if err != nil {
		return nil, err
	}
	sdJwt.head = head

	sdJwt.signature = *token.Signature

	disclosures, err := validateDisclosures(token.Disclosures)
	if err != nil {
		return nil, err
	}

	sdJwt.disclosures = disclosures

	b, err = base64.RawURLEncoding.DecodeString(*token.Payload)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	err = validateDigests(m)
	if err != nil {
		return nil, err
	}

	sdJwt.body = m

	valid, err := validateSignature(sdJwt.head, fmt.Sprintf("%s.%s", *token.Protected, *token.Payload), sdJwt.signature, publicKey)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid signature")
	}

	if sdJwt.kbJwt != nil {
		valid, err = validateKbJwt(*sdJwt.kbJwt, sdJwt.body)

		if err != nil {
			return nil, err
		}

		if !valid {
			return nil, errors.New("key-bound jwt has invalid signature")
		}
	}

	return sdJwt, nil
}

func validateJwt(token string, publicKey string) (*SdJwt, error) {
	sdJwt := &SdJwt{}

	sdJwt.publicKey = publicKey

	sections := strings.Split(token, "~")
	if len(sections) < 2 {
		return nil, errors.New("token has no specified disclosures")
	}

	sdJwt.token = sections[0]

	tokenSections := strings.Split(sections[0], ".")

	if len(tokenSections) != 3 {
		return nil, errors.New("token is not a valid JWT")
	}

	jwtHead := map[string]any{}
	hb, err := base64.RawURLEncoding.DecodeString(tokenSections[0])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(hb, &jwtHead)
	if err != nil {
		return nil, err
	}

	sdJwt.head = jwtHead

	sdJwt.signature = tokenSections[2]

	if sections[len(sections)-1] != "" && sections[len(sections)-1][len(sections[len(sections)-1])-1:] != "~" {
		kbJwt := checkForKbJwt(sections[len(sections)-1])

		if kbJwt == nil {
			return nil, errors.New("if no kb-jwt is provided, the last disclosure must be followed by a ~")
		}
		sdJwt.kbJwt = kbJwt
		sections = sections[:len(sections)-1]
	}

	disclosures, err := validateDisclosures(sections[1:])
	if err != nil {
		return nil, err
	}
	sdJwt.disclosures = disclosures

	b, err := base64.RawURLEncoding.DecodeString(tokenSections[1])
	if err != nil {
		return nil, err
	}

	var m map[string]any
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	err = validateDigests(m)
	if err != nil {
		return nil, err
	}

	sdJwt.body = m

	valid, err := validateSignature(sdJwt.head, strings.Join(tokenSections[0:2], "."), sdJwt.signature, publicKey)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid signature")
	}

	if sdJwt.kbJwt != nil {
		valid, err = validateKbJwt(*sdJwt.kbJwt, sdJwt.body)

		if err != nil {
			return nil, err
		}

		if !valid {
			return nil, errors.New("key-bound jwt has invalid signature")
		}
	}

	return sdJwt, nil
}

func validateKbJwt(kbJwt string, sdJwtBody map[string]any) (bool, error) {
	kbjc := strings.Split(kbJwt, ".")

	if len(kbjc) != 3 {
		return false, errors.New("kb jwt is in an invalid format")
	}

	//head
	kbhb, err := base64.RawURLEncoding.DecodeString(kbjc[0])
	if err != nil {
		return false, err
	}
	var kbh map[string]any
	err = json.Unmarshal(kbhb, &kbh)
	if err != nil {
		return false, err
	}

	//body
	kbbb, err := base64.RawURLEncoding.DecodeString(kbjc[1])
	if err != nil {
		return false, err
	}
	var kbb map[string]any
	err = json.Unmarshal(kbbb, &kbb)
	if err != nil {
		return false, err
	}

	//validate kb jwt contents
	if kbh["typ"] != "kb+jwt" {
		return false, errors.New("kb jwt is not of type kb+jwt")
	}

	//todo: if no other public key retrieval methods are specified, fall back to cnf
	pkm := sdJwtBody["cnf"].(map[string]any)["jwk"].(map[string]any)
	pkb, err := json.Marshal(pkm)
	if err != nil {
		return false, err
	}

	return validateSignature(kbh, strings.Join(kbjc[0:2], "."), kbjc[2], string(pkb))
}

func checkForKbJwt(candidate string) *string {
	if !strings.Contains(candidate, ".") {
		return nil
	}

	sections := strings.Split(candidate, ".")
	if len(sections) != 3 {
		return nil
	}

	return &candidate
}

func newDisclosure(d []byte) (*Disclosure, error) {
	decodedDisclosure, err := base64.RawURLEncoding.DecodeString(string(d))
	if err != nil {
		return nil, err
	}
	if decodedDisclosure[0] != '[' || decodedDisclosure[len(decodedDisclosure)-1] != ']' {
		return nil, errors.New("provided decoded disclosure is not a valid array")
	}

	disclosure := &Disclosure{}

	parts := strings.Split(string(decodedDisclosure[1:len(decodedDisclosure)-1]), ",")

	disclosure.setRawValue(string(decodedDisclosure))
	disclosure.setEncodedValue(string(d))
	if len(parts) == 2 {
		disclosure.setSalt(*cleanStr(parts[0]))
		disclosure.setClaimValue(*cleanStr(parts[1]))
	} else {
		parts[2] = strings.Join(parts[2:], ",")
		parts = parts[:3]

		if len(parts) != 3 {
			return nil, errors.New("provided decoded disclosure does not have all required parts")
		}

		disclosure.setSalt(*cleanStr(parts[0]))
		disclosure.setClaimName(cleanStr(parts[1]))
		disclosure.setClaimValue(*cleanStr(parts[2]))
	}
	return disclosure, nil
}

func cleanStr(s string) *string {
	return Pointer(strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "\"")))
}

func validateDisclosures(disclosures []string) ([]Disclosure, error) {
	var disclosureArray []Disclosure

	if len(disclosures) == 0 {
		return nil, errors.New("token has no specified disclosures")
	}

	for _, d := range disclosures {
		count := 0
		if d != "" {
			for _, d2 := range disclosures {
				if d == d2 {
					count++
				}
			}
			if count > 1 {
				return nil, errors.New("duplicate disclosure found")
			}
			dis, err := newDisclosure([]byte(d))
			if err != nil {
				return nil, err
			}
			disclosureArray = append(disclosureArray, *dis)
		}
	}
	return disclosureArray, nil
}

func validateDigests(body map[string]interface{}) error {
	digests := getDigests(body)

	for _, d := range digests {
		count := 0
		for _, d2 := range digests {
			if d == d2 {
				count++
			}
		}
		if count > 1 {
			return errors.New("duplicate digest found")
		}
	}
	return nil
}

// GetDisclosedClaims returns the claims that were disclosed in the token or included as plaintext values.
// This function will error one of the following scenarios is encountered:
// 1. The SD-JWT contains a disclosure that does not match an included digest
// 2. The SD-JWT contains a malformed _sd claim
// 3. The SD-JWT contains an unsupported value for the _sd_alg claim
// 4. The SD-JWT has a disclosure that is malformed for the use (e.g. doesn't contain a claim name for a non-array digest)
func (s *SdJwt) GetDisclosedClaims() (map[string]any, error) {
	bodyMap := make(map[string]any)

	disclosuresToCheck := make([]Disclosure, len(s.disclosures))
	copy(disclosuresToCheck, s.disclosures)
	for len(disclosuresToCheck) > 0 {
		d := disclosuresToCheck[0]

		var h hash.Hash

		switch strings.ToLower(s.body["_sd_alg"].(string)) {
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

		h.Write([]byte(d.EncodedValue()))
		hashedDisclosures := h.Sum(nil)
		base64HashedDisclosureBytes := make([]byte, base64.RawURLEncoding.EncodedLen(len(hashedDisclosures)))
		base64.RawURLEncoding.Encode(base64HashedDisclosureBytes, hashedDisclosures)

		found, err := validateSDClaims(s.Body(), &d, string(base64HashedDisclosureBytes))
		if err != nil {
			return nil, err
		}

		if !found {
			return nil, errors.New("no matching digest found: " + d.RawValue() + " encoded: " + string(base64HashedDisclosureBytes))
		}

		if len(disclosuresToCheck) > 1 {
			disclosuresToCheck = disclosuresToCheck[1:]
		} else {
			disclosuresToCheck = []Disclosure{} //empty to-check array
		}

	}

	for k, v := range s.body {
		if k != "_sd" && k != "_sd_alg" {
			bodyMap[k] = v
		}
	}

	return bodyMap, nil
}

func validateSignature(head map[string]any, signedBody, signature string, publicKey string) (bool, error) {
	alg := head["alg"].(string)

	signer, err := jwt.GetSigner(strings.ToUpper(alg))
	if err != nil {
		return false, err
	}

	return signer.ValidateSignature(signedBody, signature, publicKey)
}

func getDigests(m map[string]any) []any {
	var digests []any
	for k, v := range m {
		if reflect.TypeOf(v).Kind() == reflect.Map {
			digests = append(digests, getDigests(v.(map[string]any))...)
		} else if k == "_sd" {
			digests = append(digests, v.([]any)...)
		} else if reflect.TypeOf(v).Kind() == reflect.Slice {
			for _, v2 := range v.([]any) {
				b, err := json.Marshal(v2)
				if err == nil {
					var arrayDisclosure arrayDisclosure
					err = json.Unmarshal(b, &arrayDisclosure)
					if err == nil {
						digests = append(digests, *arrayDisclosure.Digest)
					}
				}
			}
		}
	}
	return digests
}

func parseClaimValue(cv string) (any, error) {
	var m map[string]any
	var s []any
	var b bool
	var i int

	err := json.Unmarshal([]byte(cv), &m)
	if err == nil {
		return m, nil
	}

	err = json.Unmarshal([]byte(cv), &s)
	if err == nil {
		return s, nil
	}

	err = json.Unmarshal([]byte(cv), &b)
	if err == nil {
		return b, nil
	}

	err = json.Unmarshal([]byte(cv), &i)
	if err == nil {
		return i, nil
	}

	//Return string as a fallback
	return cv, nil
}

func validateSDClaims(values *map[string]any, currentDisclosure *Disclosure, base64HashedDisclosure string) (found bool, err error) {
	if _, ok := (*values)["_sd"]; ok {
		for _, digest := range (*values)["_sd"].([]any) {
			if digest == base64HashedDisclosure {
				if currentDisclosure.ClaimName() != nil {
					val, err := parseClaimValue(currentDisclosure.ClaimValue())
					if err != nil {
						return false, err
					}
					(*values)[*currentDisclosure.ClaimName()] = val
					return true, nil
				} else {
					return false, errors.New("invalid disclosure format for _sd claim")
				}
			}
		}
	}

	for k, v := range *values {
		if k != "_sd" && k != "_sd_alg" {
			if reflect.TypeOf(v).Kind() == reflect.Slice {
				found, err = validateArrayClaims(PointerSlice(v.([]any)), currentDisclosure, base64HashedDisclosure)
				if err != nil {
					return false, err
				}
			} else if reflect.TypeOf(v).Kind() == reflect.Map {
				found, err = validateSDClaims(PointerMap(v.(map[string]any)), currentDisclosure, base64HashedDisclosure)
				if err != nil {
					return found, err
				}
			}
			if found {
				return true, nil
			}
		}
	}
	return false, nil
}

func validateArrayClaims(s *[]any, currentDisclosure *Disclosure, base64HashedDisclosure string) (found bool, err error) {

	for i, v := range *s {
		ad := &arrayDisclosure{}
		vb, err := json.Marshal(v)
		if err != nil {
			return false, err
		}

		_ = json.Unmarshal(vb, ad)

		if ad.Digest != nil {
			if *ad.Digest == base64HashedDisclosure {
				(*s)[i] = currentDisclosure.ClaimValue()
				return true, nil
			}
		}

		if reflect.TypeOf(v).Kind() == reflect.Slice {
			found, err = validateArrayClaims(PointerSlice(v.([]any)), currentDisclosure, base64HashedDisclosure)
			if err != nil {
				return found, err
			}
		}

		if reflect.TypeOf(v).Kind() == reflect.Map {
			found, err = validateSDClaims(PointerMap(v.(map[string]any)), currentDisclosure, base64HashedDisclosure)
			if err != nil {
				return found, err
			}
		}
	}

	return false, nil
}

// Body returns the body of the JWT
func (s *SdJwt) Body() *map[string]any {
	return &s.body
}

// Token returns the JWT token as it was received
func (s *SdJwt) Token() string {
	return s.token
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
func (s *SdJwt) Disclosures() []Disclosure {
	return s.disclosures
}

// PublicKey returns the public key json (if provided)
func (s *SdJwt) PublicKey() string {
	return s.publicKey
}

// KbJwt returns the signed kb-jwt (if provided)
func (s *SdJwt) KbJwt() *string {
	return s.kbJwt
}

// ClaimName returns the claim name of the disclosure
func (d *Disclosure) ClaimName() *string {
	return d.claimName
}

// ClaimValue returns the claim value of the disclosure
func (d *Disclosure) ClaimValue() string {
	return d.claimValue
}

// Salt returns the salt of the disclosure
func (d *Disclosure) Salt() string {
	return d.salt
}

// RawValue returns the decoded contents of the disclosure
func (d *Disclosure) RawValue() string {
	return d.rawValue
}

// EncodedValue returns the disclosure as it was listed in the original SD-JWT
func (d *Disclosure) EncodedValue() string {
	return d.encodedValue
}

func (d *Disclosure) setClaimName(claimName *string) {
	d.claimName = claimName
}

func (d *Disclosure) setClaimValue(claimValue string) {
	d.claimValue = claimValue
}

func (d *Disclosure) setSalt(salt string) {
	d.salt = salt
}

func (d *Disclosure) setRawValue(rawValue string) {
	d.rawValue = rawValue
}

func (d *Disclosure) setEncodedValue(encodedValue string) {
	d.encodedValue = encodedValue
}

// Pointer is a helper method that returns a pointer to the given value.
func Pointer[T comparable](t T) *T {
	return &t
}

// PointerMap is a helper method that returns a pointer to the given map.
func PointerMap(m map[string]any) *map[string]any {
	return &m
}

// PointerSlice is a helper method that returns a pointer to the given slice.
func PointerSlice(s []any) *[]any {
	return &s
}
