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

func TestNew(t *testing.T) {
	exampleJwt := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"

	sdJwt, err := go_sd_jwt.New(exampleJwt)
	require.NoError(t, err)
	require.NotNil(t, sdJwt)
	assert.NotEmpty(t, sdJwt.Token())
	assert.NotEmpty(t, sdJwt.Head())
	assert.NotEmpty(t, sdJwt.Body())
	assert.NotEmpty(t, sdJwt.Signature())
	assert.NotEmpty(t, sdJwt.Disclosures())
	assert.Len(t, sdJwt.Disclosures(), 10)

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

func TestNew_Jws(t *testing.T) {
	exampleJwt := "{\"payload\": \"eyJfc2QiOiBbIjRIQm42YUlZM1d0dUdHV1R4LXFVajZjZGs2V0JwWnlnbHRkRmF2UGE3TFkiLCAiOHNtMVFDZjAyMXBObkhBQ0k1c1A0bTRLWmd5Tk9PQVljVGo5SE5hQzF3WSIsICJTRE43OU5McEFuSFBta3JkZVlkRWE4OVhaZHNrME04REtZU1FPVTJaeFFjIiwgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLCAiZ2JPc0k0RWRxMngyS3ctdzV3UEV6YWtvYjloVjFjUkQwQVROM29RTDlKTSIsICJqTUNYVnotLTliOHgzN1ljb0RmWFFpbnp3MXdaY2NjZkZSQkNGR3FkRzJvIiwgIm9LSTFHZDJmd041V3d2amxGa29oaWRHdmltLTMxT3VsUjNxMGhyRE8wNzgiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ\",\"protected\": \"eyJhbGciOiAiRVMyNTYifQ\",\"signature\": \"qNNvkravlssjHS8TSnj5lAFc5on6MjG0peMt8Zjh1Yefxn0DxkcVOU9r7t1VNehJISOFL7NuJ5V27DVbNJBLoA\",\"disclosures\": [\"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICJqb2huX2RvZV80MiJd\",\"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiSm9obiJd\",\"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd\",\"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ\",\"WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ\",\"WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0\",\"WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0\"]}"

	sdJwt, err := go_sd_jwt.New(exampleJwt)
	require.NoError(t, err)
	require.NotNil(t, sdJwt)
	assert.NotEmpty(t, sdJwt.Token())
	assert.NotEmpty(t, sdJwt.Head())
	assert.NotEmpty(t, sdJwt.Body())
	assert.NotEmpty(t, sdJwt.Signature())
	assert.NotEmpty(t, sdJwt.Disclosures())
	assert.Len(t, sdJwt.Disclosures(), 7)

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

func TestNew_DuplicateDisclosure(t *testing.T) {
	exampleJwt := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~"

	sdJwt, err := go_sd_jwt.New(exampleJwt)
	assert.Error(t, err)
	assert.Nil(t, sdJwt)
}
