package e2e_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"runtime"
	"testing"
)

func TestE2E(t *testing.T) {
	issuerSigner, err := jws.GetSigner(model.RS256, &model.Opts{BitSize: 4096})
	if err != nil {
		t.Fatalf("error creating issuer signer: %s", err.Error())
	}
	issuerValidator, err := jws.GetValidator(issuerSigner.Alg(), issuerSigner.Public())
	if err != nil {
		t.Fatalf("error creating issuer validator: %s", err.Error())
	}

	holderSigner, err := jws.GetSigner(model.RS256, &model.Opts{BitSize: 4096})
	if err != nil {
		t.Fatalf("error creating holder signer: %s", err.Error())
	}
	holderValidator, err := jws.GetValidator(holderSigner.Alg(), holderSigner.Public())
	if err != nil {
		t.Fatalf("error creating holder validator: %s", err.Error())
	}

	inputData := map[string]any{
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework":      "de_aml",
				"time":                 "2012-04-23T18:25Z",
				"verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
				"evidence": []map[string]any{
					{
						"type":   "document",
						"method": "pipp",
						"time":   "2012-04-22T11:30Z",
						"document": map[string]any{
							"type": "idcard",
							"issuer": map[string]any{
								"name":    "Stadt Augsburg",
								"country": "DE",
							},
							"number":           "53554554",
							"date_of_issuance": "2010-03-23",
							"date_of_expiry":   "2020-03-22",
						},
					},
				},
			},
			"claims": map[string]any{
				"given_name":    "Max",
				"family_name":   "Müller",
				"nationalities": []any{"DE"},
				"birthdate":     "1956-01-28",
				"place_of_birth": map[string]any{
					"country":  "IS",
					"locality": "Þykkvabæjarklaustur",
				},
				"address": map[string]any{
					"locality":       "Maxstadt",
					"postal_code":    "12344",
					"country":        "DE",
					"street_address": "Weidenstraße 22",
				},
			},
		},
		"birth_middle_name": "Timotheus",
		"salutation":        "Dr.",
		"msisdn":            "49123456789",
	}
	var sdJwtString string

	t.Run("we can create an SD Jwt as an issuer", func(t *testing.T) {
		inputData["cnf"], err = jwk.PublicJwk(holderValidator.Public())
		if err != nil {
			t.Fatalf("error creating jwk: %s", err.Error())
		}

		header := map[string]string{
			"typ": "application/json+sd-jwt",
			"alg": issuerSigner.Alg().String(),
		}

		// Create issuer disclosure
		issuerDisclosure, err := disclosure.NewFromObject("issuer", inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any)["issuer"], nil)
		if err != nil {
			t.Fatalf("error creating disclosure from object: %s", err.Error())
		}
		delete(inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any), "issuer")

		// Create date of issuance disclosure
		dateOfIssuanceDisclosure, err := disclosure.NewFromObject("date_of_issuance", inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any)["date_of_issuance"], nil)
		if err != nil {
			t.Fatalf("error creating disclosure from object: %s", err.Error())
		}
		delete(inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any), "date_of_issuance")

		// Create number disclosure
		numberDisclosure, err := disclosure.NewFromObject("number", inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any)["number"], nil)
		if err != nil {
			t.Fatalf("error creating disclosure from object: %s", err.Error())
		}
		delete(inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any), "number")

		// Create nationalities disclosure
		nationalitiesDEDisclosure, err := disclosure.NewFromArrayElement(inputData["verified_claims"].(map[string]any)["claims"].(map[string]any)["nationalities"].([]any)[0], nil)
		if err != nil {
			t.Fatalf("error creating disclosure from array element: %s", err.Error())
		}
		inputData["verified_claims"].(map[string]any)["claims"].(map[string]any)["nationalities"].([]any)[0] = map[string]any{"...": string(nationalitiesDEDisclosure.Hash(sha256.New()))}

		// Add disclosures to array
		inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]map[string]any)[0]["document"].(map[string]any)["_sd"] = []string{
			string(issuerDisclosure.Hash(sha256.New())),
			string(dateOfIssuanceDisclosure.Hash(sha256.New())),
			string(numberDisclosure.Hash(sha256.New())),
		}

		// Create evidence disclosure
		evidenceDisclosure, err := disclosure.NewFromObject("evidence", inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"], nil)
		if err != nil {
			t.Fatalf("error creating disclosure from object: %s", err.Error())
		}
		delete(inputData["verified_claims"].(map[string]any)["verification"].(map[string]any), "evidence")

		// Add disclosures to array
		inputData["verified_claims"].(map[string]any)["verification"].(map[string]any)["_sd"] = []string{
			string(evidenceDisclosure.Hash(sha256.New())),
		}

		headerBytes, err := json.Marshal(header)
		if err != nil {
			t.Fatalf("error marshalling header as bytes: %s", err.Error())
		}
		bodyBytes, err := json.Marshal(inputData)
		if err != nil {
			t.Fatalf("error marshalling body as bytes: %s", err.Error())
		}

		b64Header := make([]byte, base64.RawURLEncoding.EncodedLen(len(headerBytes)))
		base64.RawURLEncoding.Encode(b64Header, headerBytes)
		b64Body := make([]byte, base64.RawURLEncoding.EncodedLen(len(bodyBytes)))
		base64.RawURLEncoding.Encode(b64Body, bodyBytes)

		jwt := fmt.Sprintf("%s.%s", string(b64Header), string(b64Body))

		signature, err := issuerSigner.Sign(rand.Reader, []byte(jwt), nil)
		if err != nil {
			t.Fatalf("error when signing provided jwt: %s", err.Error())
		}
		b64Signature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
		base64.RawURLEncoding.Encode(b64Signature, signature)

		jwt = fmt.Sprintf("%s.%s", jwt, string(b64Signature))
		sdJwtString = fmt.Sprintf("%s~%s~%s~%s~%s~%s~", jwt,
			issuerDisclosure.EncodedValue,
			dateOfIssuanceDisclosure.EncodedValue,
			numberDisclosure.EncodedValue,
			evidenceDisclosure.EncodedValue,
			nationalitiesDEDisclosure.EncodedValue,
		)
	})
	issuerJwk, err := jwk.PublicJwk(issuerValidator.Public())
	if err != nil {
		t.Fatalf("error creating jwk from issuer validatior: %s", err.Error())
	}

	jwkBytes, err := json.Marshal(*issuerJwk)
	if err != nil {
		t.Fatalf("error creating jwk from validator")
	}

	t.Log(sdJwtString)
	t.Log(string(jwkBytes))

	var sdJwt *go_sd_jwt.SdJwt
	var disclosedClaims map[string]any
	t.Run("we can create an sd jwt object from the newly created sd jwt string", func(t *testing.T) {
		sdJwt, err = go_sd_jwt.New(sdJwtString)
		if err != nil {
			t.Fatalf("error creating sd jwt object from created sd jwt string: %s", err.Error())
		}
		disclosedClaims, err = sdJwt.GetDisclosedClaims()
		if err != nil {
			t.Fatalf("error disclosing claims: %s", err.Error())
		}

		body := sdJwt.Body

		t.Run("validate body", func(t *testing.T) {
			keyPresent(t, body, "birth_middle_name")
			keyPresent(t, body, "msisdn")
			keyPresent(t, body, "salutation")
			keyPresent(t, body, "cnf")
			keyPresent(t, body, "verified_claims")
		})

		cnf := keyPresent(t, body, "cnf").(map[string]any)
		t.Run("validate cnf", func(t *testing.T) {
			keyPresent(t, cnf, "e")
			keyPresent(t, cnf, "kty")
			keyPresent(t, cnf, "n")
		})

		verifiedClaims := keyPresent(t, body, "verified_claims").(map[string]any)
		t.Run("validate verified_claims", func(t *testing.T) {
			keyPresent(t, verifiedClaims, "claims")
			keyPresent(t, verifiedClaims, "verification")
		})

		claims := keyPresent(t, verifiedClaims, "claims").(map[string]any)
		t.Run("validate claims", func(t *testing.T) {
			keyPresent(t, claims, "address")
			keyPresent(t, claims, "birthdate")
			keyPresent(t, claims, "family_name")
			keyPresent(t, claims, "given_name")
			keyPresent(t, claims, "nationalities")
			keyPresent(t, claims, "place_of_birth")
		})

		address := keyPresent(t, claims, "address").(map[string]any)
		t.Run("validate address", func(t *testing.T) {
			keyPresent(t, address, "country")
			keyPresent(t, address, "locality")
			keyPresent(t, address, "postal_code")
			keyPresent(t, address, "street_address")
		})

		nationalities := keyPresent(t, claims, "nationalities").([]any)
		t.Run("validate nationalities", func(t *testing.T) {
			if len(nationalities) != 1 {
				t.Errorf("nationalities has wrong length: %d", len(nationalities))
			}
			deMap, ok := nationalities[0].(map[string]any)
			if !ok {
				t.Error("nationalities should have a single map element")
			}
			if len(deMap) != 1 {
				t.Error("the map should have a single key")
			}
			_, ok = deMap["..."]
			if !ok {
				t.Error("the map should have a single value of '...'")
			}
		})

		placeOfBirth := keyPresent(t, claims, "place_of_birth").(map[string]any)
		t.Run("validate place_of_birth", func(t *testing.T) {
			keyPresent(t, placeOfBirth, "country")
			keyPresent(t, placeOfBirth, "locality")
		})

		verification := keyPresent(t, verifiedClaims, "verification").(map[string]any)
		t.Run("validate verification", func(t *testing.T) {
			keyNotPresent(t, verification, "evidence")
			keyPresent(t, verification, "time")
			keyPresent(t, verification, "trust_framework")
			keyPresent(t, verification, "verification_process")
		})
	})

	t.Run("we can validate the disclosed claims from our SdJwt", func(t *testing.T) {
		t.Run("validate disclosed claims", func(t *testing.T) {
			keyPresent(t, disclosedClaims, "birth_middle_name")
			keyPresent(t, disclosedClaims, "msisdn")
			keyPresent(t, disclosedClaims, "salutation")
			keyPresent(t, disclosedClaims, "cnf")
			keyPresent(t, disclosedClaims, "verified_claims")
		})

		cnf := keyPresent(t, disclosedClaims, "cnf").(map[string]any)
		t.Run("validate cnf", func(t *testing.T) {
			keyPresent(t, cnf, "e")
			keyPresent(t, cnf, "kty")
			keyPresent(t, cnf, "n")
		})

		verifiedClaims := keyPresent(t, disclosedClaims, "verified_claims").(map[string]any)
		t.Run("validate verified_claims", func(t *testing.T) {
			keyPresent(t, verifiedClaims, "claims")
			keyPresent(t, verifiedClaims, "verification")
		})

		claims := keyPresent(t, verifiedClaims, "claims").(map[string]any)
		t.Run("validate claims", func(t *testing.T) {
			keyPresent(t, claims, "address")
			keyPresent(t, claims, "birthdate")
			keyPresent(t, claims, "family_name")
			keyPresent(t, claims, "given_name")
			keyPresent(t, claims, "nationalities")
			keyPresent(t, claims, "place_of_birth")
		})

		address := keyPresent(t, claims, "address").(map[string]any)
		t.Run("validate address", func(t *testing.T) {
			keyPresent(t, address, "country")
			keyPresent(t, address, "locality")
			keyPresent(t, address, "postal_code")
			keyPresent(t, address, "street_address")
		})

		nationalities := keyPresent(t, claims, "nationalities").([]any)
		t.Run("validate nationalities", func(t *testing.T) {
			if len(nationalities) != 1 {
				t.Errorf("nationalities has wrong length: %d", len(nationalities))
			}
			de, ok := nationalities[0].(string)
			if !ok {
				t.Error("nationalities should have a single string")
			}
			if de != "DE" {
				t.Errorf("incorrect nationalities value storred: %s", de)
			}
		})

		placeOfBirth := keyPresent(t, claims, "place_of_birth").(map[string]any)
		t.Run("validate place_of_birth", func(t *testing.T) {
			keyPresent(t, placeOfBirth, "country")
			keyPresent(t, placeOfBirth, "locality")
		})

		verification := keyPresent(t, verifiedClaims, "verification").(map[string]any)
		t.Run("validate verification", func(t *testing.T) {
			keyPresent(t, verification, "evidence")
			keyPresent(t, verification, "time")
			keyPresent(t, verification, "trust_framework")
			keyPresent(t, verification, "verification_process")
		})

		evidence := keyPresent(t, verification, "evidence").([]any)
		t.Run("validate evidence", func(t *testing.T) {
			if len(evidence) != 1 {
				t.Errorf("evidence has wrong length: %d", len(evidence))
			}
			_, ok := evidence[0].(map[string]any)
			if !ok {
				t.Error("evidence should have a single map")
			}
		})

		evidenceContents := keyPresent(t, verification, "evidence").([]any)[0].(map[string]any)
		t.Run("validate evidence contents", func(t *testing.T) {
			keyPresent(t, evidenceContents, "document")
			keyPresent(t, evidenceContents, "method")
			keyPresent(t, evidenceContents, "time")
			keyPresent(t, evidenceContents, "type")
		})

		document := keyPresent(t, evidenceContents, "document").(map[string]any)
		t.Run("validate document", func(t *testing.T) {
			keyNotPresent(t, document, "_sd")
			keyPresent(t, document, "date_of_expiry")
			keyPresent(t, document, "type")
			issuer := keyPresent(t, document, "issuer")
			dateOfIssuance := keyPresent(t, document, "date_of_issuance")
			number := keyPresent(t, document, "number")

			//Validate issuer
			issuerMap, ok := issuer.(map[string]any)
			if !ok {
				t.Error("disclosed issuer value should be a map")
			}
			if len(issuerMap) != 2 {
				t.Errorf("issuer key is incorrect length: %d", len(issuerMap))
			}
			if issuerMap["name"] != "Stadt Augsburg" {
				t.Errorf("incorrect name value returned: %s", issuerMap["name"])
			}
			if issuerMap["country"] != "DE" {
				t.Errorf("incorrect country value returned: %s", issuerMap["country"])
			}

			//Validate date of issuance
			dateOfIssuanceString, ok := dateOfIssuance.(string)
			if !ok {
				t.Error("disclosed date of issuance value should be a string")
			}
			if dateOfIssuanceString != "2010-03-23" {
				t.Errorf("incorrect date of issuance value returned: %s", dateOfIssuanceString)
			}

			//Validate number
			numberString, ok := number.(string)
			if !ok {
				t.Error("disclosed number value should be a string")
			}
			if numberString != "53554554" {
				t.Errorf("incorrect number value returned: %s", numberString)
			}
		})
	})

	t.Run("we can receive the sd-jwt as a holder and reissue with a subset of disclosures and with key binding", func(t *testing.T) {
		providedSdJwt, err := go_sd_jwt.New(sdJwtString)
		if err != nil {
			t.Fatalf("No error expected: %s", err.Error())
		}

		allDisclosures := providedSdJwt.Disclosures

		subsetDisclosures := []disclosure.Disclosure{}

		for _, d := range allDisclosures {
			if d.Key != nil && (*d.Key == "issuer" || *d.Key == "date_of_issuance" || *d.Key == "evidence") {
				subsetDisclosures = append(subsetDisclosures, d)
			}
		}

		providedSdJwt.Disclosures = subsetDisclosures

		nonce := make([]byte, 32)
		_, err = rand.Read(nonce)
		if err != nil {
			t.Fatalf("error generating nonce value: %s", err.Error())
		}

		err = providedSdJwt.AddKeyBindingJwt(holderSigner, crypto.SHA256, holderSigner.Alg().String(), "https://audience.com", string(nonce))
		if err != nil {
			t.Fatalf("error adding kb jwt: %s", err.Error())
		}

		// a receiver would be able to validate
		bHead, err := json.Marshal(providedSdJwt.Head)
		if err != nil {
			t.Fatalf("error marshalling head as json: %s", err.Error())
		}
		b64Head := make([]byte, base64.RawURLEncoding.EncodedLen(len(bHead)))
		base64.RawURLEncoding.Encode(b64Head, bHead)

		bBody, err := json.Marshal(providedSdJwt.Body)
		if err != nil {
			t.Fatalf("error marshalling body as json: %s", err.Error())
		}
		b64Body := make([]byte, base64.RawURLEncoding.EncodedLen(len(bBody)))
		base64.RawURLEncoding.Encode(b64Body, bBody)

		disclosures := make([]string, len(providedSdJwt.Disclosures))
		for i, d := range providedSdJwt.Disclosures {
			disclosures[i] = d.EncodedValue
		}

		finalToken, err := go_sd_jwt.NewFromComponents(string(b64Head), string(b64Body), providedSdJwt.Signature, disclosures, &providedSdJwt.KbJwt.Token)
		if err != nil {
			t.Fatalf("error parsing final token: %s", err.Error())
		}
		finalDisclosedClaims, err := finalToken.GetDisclosedClaims()
		if err != nil {
			t.Fatalf("error extracting disclosed claims from final token: %s", err.Error())
		}

		t.Run("validate disclosed claims", func(t *testing.T) {
			keyPresent(t, finalDisclosedClaims, "birth_middle_name")
			keyPresent(t, finalDisclosedClaims, "msisdn")
			keyPresent(t, finalDisclosedClaims, "salutation")
			keyPresent(t, finalDisclosedClaims, "cnf")
			keyPresent(t, finalDisclosedClaims, "verified_claims")
		})

		cnf := keyPresent(t, finalDisclosedClaims, "cnf").(map[string]any)
		t.Run("validate cnf", func(t *testing.T) {
			keyPresent(t, cnf, "e")
			keyPresent(t, cnf, "kty")
			keyPresent(t, cnf, "n")
		})

		verifiedClaims := keyPresent(t, finalDisclosedClaims, "verified_claims").(map[string]any)
		t.Run("validate verified_claims", func(t *testing.T) {
			keyPresent(t, verifiedClaims, "claims")
			keyPresent(t, verifiedClaims, "verification")
		})

		claims := keyPresent(t, verifiedClaims, "claims").(map[string]any)
		t.Run("validate claims", func(t *testing.T) {
			keyPresent(t, claims, "address")
			keyPresent(t, claims, "birthdate")
			keyPresent(t, claims, "family_name")
			keyPresent(t, claims, "given_name")
			keyPresent(t, claims, "place_of_birth")
		})

		address := keyPresent(t, claims, "address").(map[string]any)
		t.Run("validate address", func(t *testing.T) {
			keyPresent(t, address, "country")
			keyPresent(t, address, "locality")
			keyPresent(t, address, "postal_code")
			keyPresent(t, address, "street_address")
		})

		placeOfBirth := keyPresent(t, claims, "place_of_birth").(map[string]any)
		t.Run("validate place_of_birth", func(t *testing.T) {
			keyPresent(t, placeOfBirth, "country")
			keyPresent(t, placeOfBirth, "locality")
		})

		verification := keyPresent(t, verifiedClaims, "verification").(map[string]any)
		t.Run("validate verification", func(t *testing.T) {
			keyPresent(t, verification, "evidence")
			keyPresent(t, verification, "time")
			keyPresent(t, verification, "trust_framework")
			keyPresent(t, verification, "verification_process")
		})

		evidence := keyPresent(t, verification, "evidence").([]any)
		t.Run("validate evidence", func(t *testing.T) {
			if len(evidence) != 1 {
				t.Errorf("evidence has wrong length: %d", len(evidence))
			}
			_, ok := evidence[0].(map[string]any)
			if !ok {
				t.Error("evidence should have a single map")
			}
		})

		evidenceContents := keyPresent(t, verification, "evidence").([]any)[0].(map[string]any)
		t.Run("validate evidence contents", func(t *testing.T) {
			keyPresent(t, evidenceContents, "document")
			keyPresent(t, evidenceContents, "method")
			keyPresent(t, evidenceContents, "time")
			keyPresent(t, evidenceContents, "type")
		})

		document := keyPresent(t, evidenceContents, "document").(map[string]any)
		t.Run("validate document", func(t *testing.T) {
			keyNotPresent(t, document, "_sd")
			keyPresent(t, document, "date_of_expiry")
			keyPresent(t, document, "type")
			issuer := keyPresent(t, document, "issuer")
			dateOfIssuance := keyPresent(t, document, "date_of_issuance")
			keyNotPresent(t, document, "number")

			//Validate issuer
			issuerMap, ok := issuer.(map[string]any)
			if !ok {
				t.Error("disclosed issuer value should be a map")
			}
			if len(issuerMap) != 2 {
				t.Errorf("issuer key is incorrect length: %d", len(issuerMap))
			}
			if issuerMap["name"] != "Stadt Augsburg" {
				t.Errorf("incorrect name value returned: %s", issuerMap["name"])
			}
			if issuerMap["country"] != "DE" {
				t.Errorf("incorrect country value returned: %s", issuerMap["country"])
			}

			//Validate date of issuance
			dateOfIssuanceString, ok := dateOfIssuance.(string)
			if !ok {
				t.Error("disclosed date of issuance value should be a string")
			}
			if dateOfIssuanceString != "2010-03-23" {
				t.Errorf("incorrect date of issuance value returned: %s", dateOfIssuanceString)
			}
		})
	})
}

func keyPresent(t *testing.T, data map[string]any, key string) any {
	val, ok := data[key]
	if !ok {
		_, file, line, _ := runtime.Caller(1)
		t.Errorf("%s should exist\n\t%s:%v", key, file, line)
	}
	return val
}

func keyNotPresent(t *testing.T, data map[string]any, key string) {
	_, ok := data[key]
	if ok {
		_, file, line, _ := runtime.Caller(1)
		t.Errorf("%s should not exist\n\t%s:%v", key, file, line)
	}
}
