package es384

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateSignatureES384(t *testing.T) {
	publicKey := "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"AgQPgcqypazyTOW8CsQOhnN2jXSLrUha6YrkXAZES6sOWT44t_OSx68kEg-UQ1lo\",\"y\":\"uRYLEPxefzGME223BsBLDyhDJ7KZApkKdmXbvaZorFQol8beG6zfve3Z16Jq1Xrj\"}"

	token := "eyJhbGciOiJFUzM4NCIsInR5cCI6Imp3dCJ9.eyJhZGRyZXNzIjp7ImNpdHkiOiJFZGluYnVyZ2giLCJudW1iZXIiOiIxNSIsInN0cmVldCI6IkxvbmcgTGFuZSJ9LCJmaXJzdG5hbWUiOiJqb2huIiwic3VybmFtZSI6InNtaXRoIn0"

	signature := "T1wWViEJKvYoOIYTD3WtK69cJMJTAmaAXni54AcWBLmOmiYQCIigzynawj5Fe1L4MRqmiCHdRF7F3Uz_ab_QvDhQw925k7rHWTwL2eSmK8TRRIS598MEM0VbcBL7AAbN"

	es384 := &ES384{}

	valid, err := es384.ValidateSignature(token, signature, publicKey)
	if err != nil {
		t.Error("no error should be thrown", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}

func TestES384_Sign(t *testing.T) {
	body := map[string]any{
		"firstname": "john",
		"surname":   "smith",
		"address": map[string]string{
			"street": "Long Lane",
			"number": "15",
			"city":   "Edinburgh",
		},
	}

	headerKeys := map[string]string{
		"typ": "jwt",
	}

	es384 := &ES384{}

	token, privateKey, publicKey, err := es384.Sign(body, headerKeys)
	if err != nil {
		t.Error("no error should be thrown", err)
		t.FailNow()
	}
	if token == nil {
		t.Error("token should not be nil")
		t.FailNow()
	}
	if privateKey == nil {
		t.Error("private key should not be nil")
		t.FailNow()
	}
	if publicKey == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}
	jsonPk, err := json.Marshal(publicKey)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	t.Log(*token)
	t.Log(string(jsonPk))

	components := strings.Split(*token, ".")
	valid, err := es384.ValidateSignature(strings.Join(components[0:2], "."), components[2], string(jsonPk))
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}
