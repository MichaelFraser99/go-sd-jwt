package es512

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateSignatureES512(t *testing.T) {
	publicKey := "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"Ae9hYaIls2sRK8n1XddHMjeS592yBIanCf8skWNbPPgez00w1m_xVt9BANFrQnZQgzoE0kBhOSVidRazi1QcY-3k\",\"y\":\"AX7Q--gyprCTZUDDPv48nNLtlbhCvC1aXxtc4pYpLFQbBIkeDXz0aMbBTyqs6sJZU0tDjeKohDTjwg3-3dbZLCm4\"}"

	token := "eyJhbGciOiJFUzUxMiIsInR5cCI6Imp3dCJ9.eyJhZGRyZXNzIjp7ImNpdHkiOiJFZGluYnVyZ2giLCJudW1iZXIiOiIxNSIsInN0cmVldCI6IkxvbmcgTGFuZSJ9LCJmaXJzdG5hbWUiOiJqb2huIiwic3VybmFtZSI6InNtaXRoIn0"

	signature := "ADT4CJwauvGdsZ1739n9iT0_HYq0om0h-UirM5CZQEwAmfj6cGgHR-M2cDZCq5dDXvKISY5ZqBrOLk_uNeQv0ZzNAJ_6Jmz_Sa3sClp-uHLAGAiKOYx7l_aFSN4_rxq2vQFXbfsclREdQTv_8W-u5ax8SWLyNHxaNn7nYKpssmGaokTs"

	es512 := &ES512{}

	valid, err := es512.ValidateSignature(token, signature, publicKey)
	if err != nil {
		t.Error("no error should be thrown", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}

func TestES512_Sign(t *testing.T) {
	body := map[string]interface{}{
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

	es512 := &ES512{}

	token, privateKey, publicKey, err := es512.Sign(body, headerKeys)
	if err != nil {
		t.Error("no error should be thrown", err)
	}
	if token == nil {
		t.Error("token should not be nil")
	}
	if privateKey == nil {
		t.Error("private key should not be nil")
	}
	if publicKey == nil {
		t.Error("public key should not be nil")
	}
	jsonPk, err := json.Marshal(publicKey)
	if err != nil {
		t.Error("no error should be thrown", err)
	}
	t.Log(*token)
	t.Log(string(jsonPk))

	components := strings.Split(*token, ".")
	valid, err := es512.ValidateSignature(strings.Join(components[0:2], "."), components[2], string(jsonPk))
	if err != nil {
		t.Error("no error should be thrown", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}
