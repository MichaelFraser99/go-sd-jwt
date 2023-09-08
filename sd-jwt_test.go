package go_sd_jwt_test

import (
	"encoding/json"
	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

var examplePublicKey = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ\",\"y\":\"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8\"}"

func TestFromToken(t *testing.T) {
	exampleJwt := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"

	sdJwt, err := go_sd_jwt.FromToken(exampleJwt, examplePublicKey)
	if err != nil {
		t.Error("error should be nilL", err)
	}
	if sdJwt == nil {
		t.Error("sdJwt should not be nil")
	}
	if sdJwt.Token() == "" {
		t.Error("token should not be empty")
	}
	if sdJwt.Head() == nil || len(sdJwt.Head()) == 0 {
		t.Error("head should not be empty")
	}
	if sdJwt.Body() == nil {
		t.Error("body should not be empty")
	}
	if sdJwt.Signature() == "" {
		t.Error("signature should not be empty")
	}
	if sdJwt.Disclosures() == nil || len(sdJwt.Disclosures()) == 0 {
		t.Error("disclosures should not be empty")
	}
	if len(sdJwt.Disclosures()) != 10 {
		t.Error("disclosures should have 10 elements")
	}
	if sdJwt.KbJwt() != nil {
		t.Error("kbJwt should be nil:", *sdJwt.KbJwt())
	}

	claims, err := sdJwt.GetDisclosedClaims()
	require.NoError(t, err)

	b, _ := json.Marshal(claims)
	t.Log(string(b))

	assert.Nil(t, claims["_sd"])
	assert.Nil(t, claims["_sd_alg"])
	assert.Equal(t, 1570000000, claims["updated_at"])
	assert.Len(t, claims["nationalities"], 2)
	assert.Contains(t, claims["nationalities"], "DE")
	assert.Contains(t, claims["nationalities"], "US")
	assert.Equal(t, "1940-01-01", claims["birthdate"])
	assert.NotNil(t, claims["address"])
	assert.Equal(t, "123 Main St", claims["address"].(map[string]interface{})["street_address"])
	assert.Equal(t, "Anytown", claims["address"].(map[string]interface{})["locality"])
	assert.Equal(t, "Anystate", claims["address"].(map[string]interface{})["region"])
	assert.Equal(t, "US", claims["address"].(map[string]interface{})["country"])
	assert.True(t, claims["phone_number_verified"].(bool))
	assert.Equal(t, "+1-202-555-0101", claims["phone_number"])
	assert.Equal(t, "johndoe@example.com", claims["email"])
	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, "user_42", claims["sub"])
}

func TestFromToken_KBJwt(t *testing.T) {
	exampleJwt := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIjA5VGJTdW8xMmkyQ3FaYmczMUFGZ2JHeV9Vbk1JWElIb01qc0VMcHVrcWciLCAiMG45eXpGU1d2S19CVUhpYU1obTEyZ2hyQ3RWYWhyR0o2Xy1rWlAteVNxNCIsICI0Vm9BM2ExVm1QeG1kQzhXSW4zcE9xUWYzZ2ZPVk92RFlzTjVFNVI1S2QwIiwgIjVBODhBbWF1QWFvLVFBTmFvOTVDWVVrVVBOVGlkX2dBSzhhWXRaOVJad2MiLCAiOTEwYnlyM1VWUnFSelFvUHpCc2MyMG0tZU1ncFpBaExONno4Tm9HRjVtYyIsICJDaC1EQmNMM2tiNFZiSEl3dGtublpkTlVIdGhFcTlNWmpvRmRnNmlkaWhvIiwgIkkwMGZjRlVvRFhDdWNwNXl5MnVqcVBzc0RWR2FXTmlVbGlOel9hd0QwZ2MiLCAiWDlNYVBhRldtUVlwZkhFZHl0UmRhY2xuWW9FcnU4RXp0QkVVUXVXT2U0NCIsICJZMXVyV0pWXy1IQkduU2Y5dEZPd3ZINGNJQ1JCQ2lLd0VIZmtYRlNmanBvIiwgInJOaEtvcmFhcS0teDdCV1dJVmhiR1h1MVhYWExNOGl2WlhEM20yRlpNZ3MiLCAieHBzcTZjeFFIRHNPblpXaHJxQmNrVGtPTV9lZkVsVW5ERlhPRm1vd0xTRSIsICJ6VTQ1MmxrR2JFS2g4WnVIXzhLeDNDVXZuMUY0eTFnWkxxbERUZ1hfOFBrIl0sICJpc3MiOiAiaHR0cHM6Ly9waWQtcHJvdmlkZXIubWVtYmVyc3RhdGUuZXhhbXBsZS5ldSIsICJpYXQiOiAxNTQxNDkzNzI0LCAiZXhwIjogMTg4MzAwMDAwMCwgInR5cGUiOiAiUGVyc29uSWRlbnRpZmljYXRpb25EYXRhIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.K5Ol1OgKQtP3FGBoJ8pmPdraIsSeOHxOAE-64L3Bc3q_aq2ANQSRNh4hqPYjuK4CnqyCK1reyHLO2iiMDwleOw~WyJzLXpVaXE1azFyU0dSb1hQUE5rMzVRIiwgImlzX292ZXJfMTgiLCB0cnVlXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm5hdGlvbmFsaXRpZXMiLCBbeyIuLi4iOiAiSnVMMzJRWER6aXpsLUw2Q0xyZnhmanBac1gzTzZ2c2ZwQ1ZkMWprd0pZZyJ9XV0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgIkRFIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2ODgxNjA0ODN9.duRIKesDpGY-5GkRcr98uhud64PfmPhL0qMcXFeBL5x2IGbAc_buglOrpd0LZA_cgCGXDx4zQoMou2kKrl-WCA"

	sdJwt, err := go_sd_jwt.FromToken(exampleJwt, examplePublicKey)
	if err != nil {
		t.Error("error should be nil:", err)
	}
	if sdJwt == nil {
		t.Error("sdJwt should not be nil")
	}
	if sdJwt.Token() == "" {
		t.Error("token should not be empty")
	}
	if sdJwt.Head() == nil || len(sdJwt.Head()) == 0 {
		t.Error("head should not be empty")
	}
	if sdJwt.Body() == nil {
		t.Error("body should not be empty")
	}
	if sdJwt.Signature() == "" {
		t.Error("signature should not be empty")
	}
	if sdJwt.Disclosures() == nil || len(sdJwt.Disclosures()) == 0 {
		t.Error("disclosures should not be empty")
	}
	if len(sdJwt.Disclosures()) != 3 {
		t.Error("disclosures should have 10 elements:", len(sdJwt.Disclosures()))
	}
	if sdJwt.KbJwt() == nil {
		t.Error("kbJwt should not be nil")
	}

	claims, err := sdJwt.GetDisclosedClaims()
	require.NoError(t, err)

	b, _ := json.Marshal(claims)
	t.Log(string(b))

	assert.Nil(t, claims["_sd"])
	assert.Nil(t, claims["_sd_alg"])
	assert.NotNil(t, claims["cnf"])
	assert.NotNil(t, claims["cnf"].(map[string]interface{})["jwk"])
	assert.Len(t, claims["nationalities"], 1)
	assert.Contains(t, claims["nationalities"], "DE")
	assert.True(t, claims["is_over_18"].(bool))
	assert.Equal(t, "https://pid-provider.memberstate.example.eu", claims["iss"])
	assert.Equal(t, "PersonIdentificationData", claims["type"])
}

func TestFromToken_Jws(t *testing.T) {
	exampleJwt := "{\"payload\": \"eyJfc2QiOiBbIjRIQm42YUlZM1d0dUdHV1R4LXFVajZjZGs2V0JwWnlnbHRkRmF2UGE3TFkiLCAiOHNtMVFDZjAyMXBObkhBQ0k1c1A0bTRLWmd5Tk9PQVljVGo5SE5hQzF3WSIsICJTRE43OU5McEFuSFBta3JkZVlkRWE4OVhaZHNrME04REtZU1FPVTJaeFFjIiwgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLCAiZ2JPc0k0RWRxMngyS3ctdzV3UEV6YWtvYjloVjFjUkQwQVROM29RTDlKTSIsICJqTUNYVnotLTliOHgzN1ljb0RmWFFpbnp3MXdaY2NjZkZSQkNGR3FkRzJvIiwgIm9LSTFHZDJmd041V3d2amxGa29oaWRHdmltLTMxT3VsUjNxMGhyRE8wNzgiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ\",\"protected\": \"eyJhbGciOiAiRVMyNTYifQ\",\"signature\": \"qNNvkravlssjHS8TSnj5lAFc5on6MjG0peMt8Zjh1Yefxn0DxkcVOU9r7t1VNehJISOFL7NuJ5V27DVbNJBLoA\",\"disclosures\": [\"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICJqb2huX2RvZV80MiJd\",\"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiSm9obiJd\",\"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd\",\"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ\",\"WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ\",\"WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0\",\"WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0\"]}"

	sdJwt, err := go_sd_jwt.FromToken(exampleJwt, examplePublicKey)
	require.NoError(t, err)
	require.NotNil(t, sdJwt)
	assert.NotEmpty(t, sdJwt.Token())
	assert.NotEmpty(t, sdJwt.Head())
	assert.NotEmpty(t, sdJwt.Body())
	assert.NotEmpty(t, sdJwt.Signature())
	assert.NotEmpty(t, sdJwt.Disclosures())
	assert.Len(t, sdJwt.Disclosures(), 7)
	assert.Nil(t, sdJwt.KbJwt())

	claims, err := sdJwt.GetDisclosedClaims()
	require.NoError(t, err)

	b, _ := json.Marshal(claims)
	t.Log(string(b))

	assert.Nil(t, claims["_sd"])
	assert.Nil(t, claims["_sd_alg"])
	assert.Equal(t, "1940-01-01", claims["birthdate"])
	assert.NotNil(t, claims["address"])
	assert.Equal(t, "123 Main St", claims["address"].(map[string]interface{})["street_address"])
	assert.Equal(t, "Anytown", claims["address"].(map[string]interface{})["locality"])
	assert.Equal(t, "Anystate", claims["address"].(map[string]interface{})["region"])
	assert.Equal(t, "US", claims["address"].(map[string]interface{})["country"])
	assert.Equal(t, "+1-202-555-0101", claims["phone_number"])
	assert.Equal(t, "johndoe@example.com", claims["email"])
	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, "john_doe_42", claims["sub"])
}

func TestFromToken_DuplicateDisclosure(t *testing.T) {
	exampleJwt := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~"

	sdJwt, err := go_sd_jwt.FromToken(exampleJwt, examplePublicKey)
	assert.Error(t, err)
	assert.Nil(t, sdJwt)
}
