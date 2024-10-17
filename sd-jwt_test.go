package go_sd_jwt_test

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		validate func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error)
	}{
		{
			name:  "valid token",
			token: "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Errorf("error should be nil: %s", err.Error())
				}
				if sdJwt == nil {
					t.Fatal("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 10 {
						t.Error("disclosures should have 10 elements")
					}
					if sdJwt.KbJwt != nil {
						t.Error("kbJwt should be nil:", *sdJwt.KbJwt)
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.Equal(t, float64(1570000000), claims["updated_at"])
					assert.Len(t, claims["nationalities"], 2)
					assert.Contains(t, claims["nationalities"], "DE")
					assert.Contains(t, claims["nationalities"], "US")
					assert.Equal(t, "1940-01-01", claims["birthdate"])
					assert.NotNil(t, claims["address"])
					assert.Equal(t, "123 Main St", claims["address"].(map[string]any)["street_address"])
					assert.Equal(t, "Anytown", claims["address"].(map[string]any)["locality"])
					assert.Equal(t, "Anystate", claims["address"].(map[string]any)["region"])
					assert.Equal(t, "US", claims["address"].(map[string]any)["country"])
					assert.True(t, claims["phone_number_verified"].(bool))
					assert.Equal(t, "+1-202-555-0101", claims["phone_number"])
					assert.Equal(t, "johndoe@example.com", claims["email"])
					assert.Equal(t, "John", claims["given_name"])
					assert.Equal(t, "Doe", claims["family_name"])
					assert.Equal(t, "user_42", claims["sub"])
				}
			},
		},
		{
			name:  "valid token more complex structure",
			token: "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.IjE4EfnYu1RZ1uz6yqtFh5Lppq36VC4VeSr-hLDFpZ9zqBNmMrT5JHLLXTuMJqKQp3NIzDsLaft4GK5bYyfqhg~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Error("error should be nil", err)
				}
				if sdJwt == nil {
					t.Fatal("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("Head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 2 {
						t.Error("disclosures should have 2 elements")
					}
					if sdJwt.KbJwt != nil {
						t.Error("kbJwt should be nil:", *sdJwt.KbJwt)
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.Equal(t, float64(1883000000), claims["exp"])
					assert.Equal(t, float64(1683000000), claims["iat"])
					assert.Equal(t, "https://issuer.example.com", claims["iss"])
					assert.NotNil(t, claims["address"])
					assert.Nil(t, claims["address"].(map[string]any)["_sd"])
					assert.Equal(t, "JP", claims["address"].(map[string]any)["country"])
					assert.Equal(t, "港区", claims["address"].(map[string]any)["region"])
				}
			},
		},
		{
			name:  "valid token with a very complex structure",
			token: "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIi1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.kbfpTas9_-dLMgyeUxIXuBGLtCZUO2bG9JA7v73ebzpX1LA5MBtQsyZZut-Bm3_TW8sTqLCDPUN4ZC5pKCyQig~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Error("error should be nil", err)
				}
				if sdJwt == nil {
					t.Error("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 6 {
						t.Error("disclosures should have 6 elements, has", len(sdJwt.Disclosures))
					}
					if sdJwt.KbJwt != nil {
						t.Error("kbJwt should be nil:", *sdJwt.KbJwt)
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Equal(t, 4, len(claims))
					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.Equal(t, float64(1883000000), claims["exp"])
					assert.Equal(t, float64(1683000000), claims["iat"])
					assert.Equal(t, "https://issuer.example.com", claims["iss"])
					assert.NotNil(t, claims["verified_claims"])
					assert.Equal(t, 2, len(claims["verified_claims"].(map[string]any)))
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["verification"])
					assert.Equal(t, 3, len(claims["verified_claims"].(map[string]any)["verification"].(map[string]any)))
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["trust_framework"])
					assert.Equal(t, "de_aml", claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["trust_framework"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"])
					assert.Equal(t, 1, len(claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]any)))
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["method"])
					assert.Equal(t, 1, len(claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]any)[0].(map[string]any)))
					assert.Equal(t, "pipp", claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["method"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["time"])
					assert.Equal(t, "2012-04-23T18:25Z", claims["verified_claims"].(map[string]any)["verification"].(map[string]any)["time"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"])
					assert.Equal(t, 3, len(claims["verified_claims"].(map[string]any)["claims"].(map[string]any)))
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["given_name"])
					assert.Equal(t, "Max", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["given_name"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["family_name"])
					assert.Equal(t, "Müller", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["family_name"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"])
					assert.Equal(t, 4, len(claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)))
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["locality"])
					assert.Equal(t, "Maxstadt", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["locality"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["postal_code"])
					assert.Equal(t, "12344", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["postal_code"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["country"])
					assert.Equal(t, "DE", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["country"])
					assert.NotNil(t, claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["street_address"])
					assert.Equal(t, "Weidenstraße 22", claims["verified_claims"].(map[string]any)["claims"].(map[string]any)["address"].(map[string]any)["street_address"])
				}
			},
		},
		{
			name:  "valid token with valid key-bound jwt",
			token: "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.7oEYwv1H4rBa54xAhDH19DEIy-RRSTdwyJvhbjOKVFyQeM0-gcgpwCq-yFCbWj9THEjD9M4yYkAeaWXfuvBS-Q~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJfajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM45J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Fatalf("error should be nil: %s", err.Error())
				}
				if sdJwt == nil {
					t.Fatal("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 4 {
						t.Error("disclosures should have 4 elements:", len(sdJwt.Disclosures))
					}
					if sdJwt.KbJwt == nil {
						t.Error("kbJwt should not be nil")
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.NotNil(t, claims["cnf"])
					assert.NotNil(t, claims["cnf"].(map[string]any)["jwk"])
					assert.Equal(t, "P-256", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["crv"])
					assert.Equal(t, "EC", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["kty"])
					assert.Equal(t, "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
					assert.Equal(t, "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["y"])
					assert.Len(t, claims["nationalities"], 1)
					assert.Contains(t, claims["nationalities"], "US")
					assert.Equal(t, float64(1683000000), claims["iat"])
					assert.Equal(t, "https://issuer.example.com", claims["iss"])
					assert.Equal(t, "user_42", claims["sub"])
					assert.Equal(t, "John", claims["given_name"])
					assert.Equal(t, "Doe", claims["family_name"])
					assert.NotNil(t, claims["address"])
					assert.NotNil(t, claims["address"].(map[string]any)["country"])
					assert.Equal(t, "US", claims["address"].(map[string]any)["country"])
					assert.NotNil(t, claims["address"].(map[string]any)["locality"])
					assert.Equal(t, "Anytown", claims["address"].(map[string]any)["locality"])
					assert.NotNil(t, claims["address"].(map[string]any)["region"])
					assert.Equal(t, "Anystate", claims["address"].(map[string]any)["region"])
					assert.NotNil(t, claims["address"].(map[string]any)["street_address"])
					assert.Equal(t, "123 Main St", claims["address"].(map[string]any)["street_address"])
				}
			},
		},
		{
			name:  "valid token with disclosed address with no properties",
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6ImFwcGxpY2F0aW9uL2pzb24rc2Qtand0In0.eyJfc2QiOlsienctOU1SQXdtcUJXeTFUOEVua0JvZ2lyVEpfU2NTbnZfSGlCenhOWXFUNCJdLCJjbmYiOnsiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoidlpEc29UMW5HVjR4X1gzck9HTGUzOF8tQmpibVUtUWxlSjRIZU1Fbl9GRUZLaEhTc1ZIR1dsR28xZ2pBckR5a2d5d0VTQVg0dEhqdURMUFZiODlkNzQ2eVJIRVF3aXRIbU5sTE40c1NGQUd1MWNJSU1iUDNuM3RrSWtYQlh5U25pMXNCanV4b3lnMFU1UmJQd1lMN2J0NklqWS04OWljd2ZjTVV1N2p3aV80dFk2SUUyQXpTbm9sQi1RN21tS2o1ZXNWeEJ3RTIzTkdlamp2NmNvLWNtTFVZMEhuZFE2QXo1RldKbjlGRTA3RlFOeHQwVXNLaGZDTi05eGVnVXR1c1lDX3IyZlg2SnRsYy1UYWlwQWV5WEZ2RFVIVHVUSEdWSHNseGN5NFhPVS15WnE2OFhGaHJUQnZRTVNKV1dxRDR0MjYyXzlIR2k2QlEzVmlpbE51ZDd3In0sImZhbWlseV9uYW1lIjoiTcO8bGxlciIsImdpdmVuX25hbWUiOiJNYXgifQ.xj0X10080FANgzrdpfWrbF0DO0Y3KwiJzoO8-C-pj_DU6xjrG9kX9Nbh6rFhD1iuX_aGL-tXQwXaiGrgWLC72ws_mleRkQ6cvibl-ej9mr45iqZ2vd9rQavBh_q5v9AoKI3vu763ZEp49b_Z02acOWbIK9LlmSf3_hivHvV8mV5tpUCaSxD8JQ8tWbD5q5WhPofeAprm0_ygj4JmF0EuC_ARPmAZEK8of9kIKTgRKsLQuAPreQId8Sg7tTZaSLL4D47DZlWY0ioO2wn6QyYXIbHFnx01EKbsk_I3F0ha4P0h0UPif3KcIRh_tGkrjazejAv7mXd0jJLjF9CEGJzNYw~WyI1eWZHRjVxZnhKN2ViOXN0anBIR3dRIiwiYWRkcmVzcyIseyJfc2QiOlsiaFRiS1NZdVBaaW5qMVBja1N1Z0pfdnRhc3dFVEYxR0xPSVRpRnM1Wnl1dyIsIk0xU3FsVWNyZ1Ewc1FuRE1Vek5nVVFXVXBWM19XWEN0YzN3QWNNMUx4Y2siLCJ1OTdHb1cwRnZiVkl3dElBdWJGZEFIbTVjaG5wc0VFVm1jTzVGNUJxeG5JIl19XQ~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Fatalf("error should be nil: %s", err.Error())
				}
				if sdJwt == nil {
					t.Fatal("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 1 {
						t.Error("disclosures should have 1 element:", len(sdJwt.Disclosures))
					}
					if sdJwt.KbJwt != nil {
						t.Error("kbJwt should be nil")
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.Equal(t, "Max", claims["given_name"])
					assert.Equal(t, "Müller", claims["family_name"])
					assert.NotNil(t, claims["address"])
					assert.Len(t, claims["address"], 0)
				}
			},
		},
		{
			name:  "another valid token with valid key-bound jwt",
			token: "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIzLTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDExOjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhiWlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVllZy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3laUmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVOdzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRCeTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1XZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxkTURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0MtX29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJfc2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEiLCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQbjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAiVmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.LvxBnGlzhbpnrIq-isT5riLqQ8yCqQv2TGJ51lnwxuScAGT_6pX1-D8WitwKUWFqhqYfz1qTS6nLpdbS5Ji3EA~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjIwMjEtMDYtMjNUMTM6NDA6MTJaIl0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiwgIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogImltREJmRW9QUWRrdWNBUDdTR0FHQWJaQ1lzYjVVM2w5VkZERVRUSjllUVEifQ.CREhV5QqVLe6B1AEgLKFJ2xiTvuINxNlNjYR1hZEZDS0Ixm1gxKHHVRtxrOcuHxv9kO9QRxV4ZQtThjnYavUgg",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err != nil {
					t.Fatalf("error should be nil: %s", err.Error())
				}
				if sdJwt == nil {
					t.Fatal("sdJwt should not be nil")
				} else {
					if len(sdJwt.Head) == 0 {
						t.Error("head should not be empty")
					}
					if sdJwt.Body == nil {
						t.Error("body should not be empty")
					}
					if sdJwt.Signature == "" {
						t.Error("signature should not be empty")
					}
					if len(sdJwt.Disclosures) == 0 {
						t.Error("disclosures should not be empty")
					}
					if len(sdJwt.Disclosures) != 4 {
						t.Error("disclosures should have 4 elements:", len(sdJwt.Disclosures))
					}
					if sdJwt.KbJwt == nil {
						t.Error("kbJwt should not be nil")
					}

					claims, err := sdJwt.GetDisclosedClaims()
					require.NoError(t, err)

					b, _ := json.Marshal(claims)
					t.Log(string(b))

					assert.Nil(t, claims["_sd"])
					assert.Nil(t, claims["_sd_alg"])
					assert.NotNil(t, claims["cnf"])
					assert.NotNil(t, claims["cnf"].(map[string]any)["jwk"])
					assert.Equal(t, "P-256", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["crv"])
					assert.Equal(t, "EC", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["kty"])
					assert.Equal(t, "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
					assert.Equal(t, "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["y"])
					assert.Len(t, claims["@context"], 2)
					assert.Contains(t, claims["@context"], "https://www.w3.org/2018/credentials/v1")
					assert.Contains(t, claims["@context"], "https://w3id.org/vaccination/v1")
					assert.Len(t, claims["type"], 2)
					assert.Contains(t, claims["type"], "VerifiableCredential")
					assert.Contains(t, claims["type"], "VaccinationCertificate")
					assert.Equal(t, "https://example.com/issuer", claims["issuer"])
					assert.Equal(t, "2023-02-09T11:01:59Z", claims["issuanceDate"])
					assert.Equal(t, "2028-02-08T11:01:59Z", claims["expirationDate"])
					assert.Equal(t, "COVID-19 Vaccination Certificate", claims["name"])
					assert.Equal(t, "COVID-19 Vaccination Certificate", claims["description"])
					assert.NotNil(t, claims["credentialSubject"])
					assert.NotNil(t, claims["credentialSubject"].(map[string]any)["vaccine"])
					assert.Equal(t, "Vaccine", claims["credentialSubject"].(map[string]any)["vaccine"].(map[string]any)["type"])
					assert.Equal(t, "J07BX03", claims["credentialSubject"].(map[string]any)["vaccine"].(map[string]any)["atcCode"])
					assert.Equal(t, "COVID-19 Vaccine Moderna", claims["credentialSubject"].(map[string]any)["vaccine"].(map[string]any)["medicinalProductName"])
					assert.Equal(t, "VaccinationEvent", claims["credentialSubject"].(map[string]any)["type"])
					assert.Equal(t, "3/3", claims["credentialSubject"].(map[string]any)["order"])
					assert.Equal(t, "2021-06-23T13:40:12Z", claims["credentialSubject"].(map[string]any)["dateOfVaccination"])
					assert.NotNil(t, claims["credentialSubject"].(map[string]any)["recipient"])
					assert.Equal(t, "VaccineRecipient", claims["credentialSubject"].(map[string]any)["recipient"].(map[string]any)["type"])
				}
			},
		},
		{
			name:  "another valid token with invalid key-bound jwt",
			token: "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIzLTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDExOjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhiWlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVllZy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3laUmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVOdzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRCeTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1XZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxkTURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0MtX29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJfc2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEiLCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQbjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAiVmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.LvxBnGlzhbpnrIq-isT5riLqQ8yCqQv2TGJ51lnwxuScAGT_6pX1-D8WitwKUWFqhqYfz1qTS6nLpdbS5Ji3EA~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjIwMjEtMDYtMjNUMTM6NDA6MTJaIl0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiwgIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJfajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM45J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err == nil {
					t.Fatalf("error should not be nil: %s", err.Error())
				}
				if sdJwt != nil {
					t.Error("sdJwt should be nil")
				}
				assert.Equal(t, "sd hash validation failed: calculated hash imDBfEoPQdkucAP7SGAGAbZCYsb5U3l9VFDETTJ9eQQ does not equal provided hash nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo", err.Error())
			},
		},
		{
			name:  "valid token but duplicate disclosure",
			token: "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				if err == nil {
					t.Error("error should be thrown")
					t.FailNow()
				}
				if sdJwt != nil {
					t.Error("sdJwt should be nil: ", sdJwt)
				}
				if err.Error() != "failed to validate disclosures: duplicate disclosure found" {
					t.Error("error message is not correct: ", err.Error())
				}
			},
		},
		{
			name:  "valid token but xxx",
			token: "eyJhbGciOiAiRVMyNTYifQ.eyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIzLTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDExOjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhiWlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVllZy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3laUmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVOdzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRCeTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1XZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxkTURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0MtX29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJfc2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEiLCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQbjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAiVmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.l7byWDsTtDOjFbWS4lko-3mkeeZwzUYw6ZicrJurES_gzs6EK_svPiVwj5g6evb_nmLWpK2_cXQ_J0cjH0XnGw~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiwgIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgIm1hcmtldGluZ0F1dGhvcml6YXRpb25Ib2xkZXIiLCAiTW9kZXJuYSBCaW90ZWNoIl0~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm5leHRWYWNjaW5hdGlvbkRhdGUiLCAiMjAyMS0wOC0xNlQxMzo0MDoxMloiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImNvdW50cnlPZlZhY2NpbmF0aW9uIiwgIkdFIl0~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjIwMjEtMDYtMjNUMTM6NDA6MTJaIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdlbmRlciIsICJGZW1hbGUiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImJpcnRoRGF0ZSIsICIxOTYxLTA4LTE3Il0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgImdpdmVuTmFtZSIsICJNYXJpb24iXQ~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImZhbWlseU5hbWUiLCAiTXVzdGVybWFubiJd~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImFkbWluaXN0ZXJpbmdDZW50cmUiLCAiUHJheGlzIFNvbW1lcmdhcnRlbiJd~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImJhdGNoTnVtYmVyIiwgIjE2MjYzODI3MzYiXQ~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImhlYWx0aFByb2Zlc3Npb25hbCIsICI4ODMxMTAwMDAwMTUzNzYiXQ~",
			validate: func(t *testing.T, sdJwt *go_sd_jwt.SdJwt, err error) {
				require.Nil(t, err, "must not error")
				var disclosedClaims map[string]any
				disclosedClaims, err = sdJwt.GetDisclosedClaims()
				require.Nil(t, err, "must not error")
				b, err := json.Marshal(disclosedClaims)
				require.Nil(t, err, "must not error")
				fmt.Println(string(b))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdJwt, err := go_sd_jwt.New(tt.token)
			tt.validate(t, sdJwt, err)
		})
	}
}

func TestNewFromComponents(t *testing.T) {
	token := map[string]any{
		"payload":   "eyJfc2QiOiBbIjRIQm42YUlZM1d0dUdHV1R4LXFVajZjZGs2V0JwWnlnbHRkRmF2UGE3TFkiLCAiOHNtMVFDZjAyMXBObkhBQ0k1c1A0bTRLWmd5Tk9PQVljVGo5SE5hQzF3WSIsICJTRE43OU5McEFuSFBta3JkZVlkRWE4OVhaZHNrME04REtZU1FPVTJaeFFjIiwgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLCAiZ2JPc0k0RWRxMngyS3ctdzV3UEV6YWtvYjloVjFjUkQwQVROM29RTDlKTSIsICJqTUNYVnotLTliOHgzN1ljb0RmWFFpbnp3MXdaY2NjZkZSQkNGR3FkRzJvIiwgIm9LSTFHZDJmd041V3d2amxGa29oaWRHdmltLTMxT3VsUjNxMGhyRE8wNzgiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ",
		"protected": "eyJhbGciOiAiRVMyNTYifQ",
		"signature": "qNNvkravlssjHS8TSnj5lAFc5on6MjG0peMt8Zjh1Yefxn0DxkcVOU9r7t1VNehJISOFL7NuJ5V27DVbNJBLoA",
		"disclosures": []string{
			"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICJqb2huX2RvZV80MiJd",
			"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
			"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
			"WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ",
			"WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
			"WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0",
		},
	}

	sdJwt, err := go_sd_jwt.NewFromComponents(token["protected"].(string), token["payload"].(string), token["signature"].(string), token["disclosures"].([]string), nil)

	require.NoError(t, err)
	require.NotNil(t, sdJwt)
	assert.NotEmpty(t, sdJwt.Head)
	assert.NotEmpty(t, sdJwt.Body)
	assert.NotEmpty(t, sdJwt.Signature)
	assert.NotEmpty(t, sdJwt.Disclosures)
	assert.Len(t, sdJwt.Disclosures, 7)
	assert.Nil(t, sdJwt.KbJwt)

	claims, err := sdJwt.GetDisclosedClaims()
	require.NoError(t, err)

	b, _ := json.Marshal(claims)
	t.Log(string(b))

	assert.Nil(t, claims["_sd"])
	assert.Nil(t, claims["_sd_alg"])
	assert.Equal(t, "1940-01-01", claims["birthdate"])
	assert.NotNil(t, claims["address"])
	assert.Equal(t, "123 Main St", claims["address"].(map[string]any)["street_address"])
	assert.Equal(t, "Anytown", claims["address"].(map[string]any)["locality"])
	assert.Equal(t, "Anystate", claims["address"].(map[string]any)["region"])
	assert.Equal(t, "US", claims["address"].(map[string]any)["country"])
	assert.Equal(t, "+1-202-555-0101", claims["phone_number"])
	assert.Equal(t, "johndoe@example.com", claims["email"])
	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, "john_doe_42", claims["sub"])
}

func TestNewFromComponentsKbJwt(t *testing.T) {
	token := map[string]any{
		"payload":   "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0",
		"protected": "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0",
		"signature": "7oEYwv1H4rBa54xAhDH19DEIy-RRSTdwyJvhbjOKVFyQeM0-gcgpwCq-yFCbWj9THEjD9M4yYkAeaWXfuvBS-Q",
		"disclosures": []string{
			"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
			"WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
			"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			"WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
		},
		"kb-jwt": "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJfajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM45J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g",
	}

	sdJwt, err := go_sd_jwt.NewFromComponents(token["protected"].(string), token["payload"].(string), token["signature"].(string), token["disclosures"].([]string), disclosure.String(token["kb-jwt"].(string)))

	if err != nil {
		t.Fatalf("error should be nil: %s", err.Error())
	}
	if sdJwt == nil {
		t.Fatal("sdJwt should not be nil")
	} else {
		if len(sdJwt.Head) == 0 {
			t.Error("head should not be empty")
		}
		if sdJwt.Body == nil {
			t.Error("body should not be empty")
		}
		if sdJwt.Signature == "" {
			t.Error("signature should not be empty")
		}
		if len(sdJwt.Disclosures) == 0 {
			t.Error("disclosures should not be empty")
		}
		if len(sdJwt.Disclosures) != 4 {
			t.Error("disclosures should have 4 elements:", len(sdJwt.Disclosures))
		}
		if sdJwt.KbJwt == nil {
			t.Error("kbJwt should not be nil")
		}

		claims, err := sdJwt.GetDisclosedClaims()
		require.NoError(t, err)

		b, _ := json.Marshal(claims)
		t.Log(string(b))

		assert.Nil(t, claims["_sd"])
		assert.Nil(t, claims["_sd_alg"])
		assert.NotNil(t, claims["cnf"])
		assert.NotNil(t, claims["cnf"].(map[string]any)["jwk"])
		assert.Equal(t, "P-256", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["crv"])
		assert.Equal(t, "EC", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["kty"])
		assert.Equal(t, "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
		assert.Equal(t, "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ", claims["cnf"].(map[string]any)["jwk"].(map[string]any)["y"])
		assert.Len(t, claims["nationalities"], 1)
		assert.Contains(t, claims["nationalities"], "US")
		assert.Equal(t, float64(1683000000), claims["iat"])
		assert.Equal(t, "https://issuer.example.com", claims["iss"])
		assert.Equal(t, "user_42", claims["sub"])
		assert.Equal(t, "John", claims["given_name"])
		assert.Equal(t, "Doe", claims["family_name"])
		assert.NotNil(t, claims["address"])
		assert.NotNil(t, claims["address"].(map[string]any)["country"])
		assert.Equal(t, "US", claims["address"].(map[string]any)["country"])
		assert.NotNil(t, claims["address"].(map[string]any)["locality"])
		assert.Equal(t, "Anytown", claims["address"].(map[string]any)["locality"])
		assert.NotNil(t, claims["address"].(map[string]any)["region"])
		assert.Equal(t, "Anystate", claims["address"].(map[string]any)["region"])
		assert.NotNil(t, claims["address"].(map[string]any)["street_address"])
		assert.Equal(t, "123 Main St", claims["address"].(map[string]any)["street_address"])
	}
}

func TestNewFromComponentsWrongKbJwt(t *testing.T) {
	token := map[string]any{
		"payload":   "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0",
		"protected": "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0",
		"signature": "7oEYwv1H4rBa54xAhDH19DEIy-RRSTdwyJvhbjOKVFyQeM0-gcgpwCq-yFCbWj9THEjD9M4yYkAeaWXfuvBS-Q",
		"disclosures": []string{
			"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
			"WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
			"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			"WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
		},
		"kb-jwt": "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogImltREJmRW9QUWRrdWNBUDdTR0FHQWJaQ1lzYjVVM2w5VkZERVRUSjllUVEifQ.CREhV5QqVLe6B1AEgLKFJ2xiTvuINxNlNjYR1hZEZDS0Ixm1gxKHHVRtxrOcuHxv9kO9QRxV4ZQtThjnYavUgg",
	}

	sdJwt, err := go_sd_jwt.NewFromComponents(token["protected"].(string), token["payload"].(string), token["signature"].(string), token["disclosures"].([]string), disclosure.String(token["kb-jwt"].(string)))

	if err == nil {
		t.Fatalf("error should be not nil")
	}
	if sdJwt != nil {
		t.Error("sdJwt should be nil")
	}
	assert.Equal(t, "sd hash validation failed: calculated hash nYcOXyP43v9szKryn_k_4GkRr_j3STHhNSS-i1Duauo does not equal provided hash imDBfEoPQdkucAP7SGAGAbZCYsb5U3l9VFDETTJ9eQQ", err.Error())
}

func TestSdJwt_AddKeyBindingJwt(t *testing.T) {
	token := "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIi1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.kbfpTas9_-dLMgyeUxIXuBGLtCZUO2bG9JA7v73ebzpX1LA5MBtQsyZZut-Bm3_TW8sTqLCDPUN4ZC5pKCyQig~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~"
	sdJwt, err := go_sd_jwt.New(token)
	if err != nil {
		t.Fatalf("no error should be thrown: %s", err.Error())
	}

	if sdJwt.KbJwt != nil {
		t.Fatalf("no kb jwt should yet exist")
	}

	signer, err := jws.GetSigner(model.RS256, &model.Opts{BitSize: 2048})
	if err != nil {
		t.Fatalf("failed to get signer %s", err.Error())
	}
	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		t.Errorf("error generating nonce value: %s", err.Error())
	}

	err = sdJwt.AddKeyBindingJwt(signer, crypto.SHA256, signer.Alg().String(), "https://unused.com", string(nonce))
	if err != nil {
		t.Errorf("no error should be thrown: %s", err.Error())
	}

	if sdJwt.KbJwt == nil {
		t.Error("KB Jwt should now exist")
	}

	//We can validate the key bound jwt
	head, err := json.Marshal(sdJwt.Head)
	if err != nil {
		t.Fatalf("no error should be thrown: %s", err.Error())
	}
	b64Head := make([]byte, base64.RawURLEncoding.EncodedLen(len(head)))
	base64.RawURLEncoding.Encode(b64Head, head)

	body, err := json.Marshal(sdJwt.Body)
	if err != nil {
		t.Fatalf("no error should be thrown: %s", err.Error())
	}
	b64Body := make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
	base64.RawURLEncoding.Encode(b64Body, body)

	var disclosures []string
	for _, d := range sdJwt.Disclosures {
		disclosures = append(disclosures, d.EncodedValue)
	}

	_, err = go_sd_jwt.NewFromComponents(string(b64Head), string(b64Body), sdJwt.Signature, disclosures, &sdJwt.KbJwt.Token)
	if err != nil {
		t.Errorf("error validating sdjwt components: %s", err.Error())
	}
}

func TestNew_AllDuplicateDigestScenarios(t *testing.T) {
	duplicateDigestSdClaimJwt := "eyJhbGciOiAiRVMyNTYifQ.ew0KICAiX3NkIjogWw0KICAgICJDclFlN1M1a3FCQUh0LW5NWVhnYzZiZHQyU0g1YVRZMXNVX00tUGdralBJIiwNCiAgICAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsDQogICAgIlBvckZicEt1VnU2eHltSmFndmtGc0ZYQWJSb2MySkdsQVVBMkJBNG83Y0kiLA0KICAgICJUR2Y0b0xiZ3dkNUpRYUh5S1ZRWlU5VWRHRTB3NXJ0RHNyWnpmVWFvbUxvIiwNCiAgICAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsDQogICAgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLA0KICAgICJnYk9zSTRFZHEyeDJLdy13NXdQRXpha29iOWhWMWNSRDBBVE4zb1FMOUpNIiwNCiAgICAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCIsDQogICAgImpzdTl5VnVsd1FRbGhGbE1fM0psek1hU0Z6Z2xoUUcwRHBmYXlRd0xVSzQiDQogIF0sDQogICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLA0KICAiaWF0IjogMTY4MzAwMDAwMCwNCiAgImV4cCI6IDE4ODMwMDAwMDAsDQogICJzdWIiOiAidXNlcl80MiIsDQogICJuYXRpb25hbGl0aWVzIjogWw0KICAgIHsNCiAgICAgICIuLi4iOiAicEZuZGprWl9WQ3pteVRhNlVqbFpvM2RoLWtvOGFJS1FjOURsR3poYVZZbyINCiAgICB9LA0KICAgIHsNCiAgICAgICIuLi4iOiAiN0NmNkprUHVkcnkzbGNid0hnZVo4a2hBdjFVMU9TbGVyUDBWa0JKcldaMCINCiAgICB9DQogIF0sDQogICJfc2RfYWxnIjogInNoYS0yNTYiLA0KICAiY25mIjogew0KICAgICJqd2siOiB7DQogICAgICAia3R5IjogIkVDIiwNCiAgICAgICJjcnYiOiAiUC0yNTYiLA0KICAgICAgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsDQogICAgICAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIg0KICAgIH0NCiAgfQ0KfQ.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
	duplicateDigestArrayClaimJwt := "eyJhbGciOiAiRVMyNTYifQ.ew0KICAiX3NkIjogWw0KICAgICJDclFlN1M1a3FCQUh0LW5NWVhnYzZiZHQyU0g1YVRZMXNVX00tUGdralBJIiwNCiAgICAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsDQogICAgIlBvckZicEt1VnU2eHltSmFndmtGc0ZYQWJSb2MySkdsQVVBMkJBNG83Y0kiLA0KICAgICJUR2Y0b0xiZ3dkNUpRYUh5S1ZRWlU5VWRHRTB3NXJ0RHNyWnpmVWFvbUxvIiwNCiAgICAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsDQogICAgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLA0KICAgICJnYk9zSTRFZHEyeDJLdy13NXdQRXpha29iOWhWMWNSRDBBVE4zb1FMOUpNIiwNCiAgICAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCINCiAgXSwNCiAgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsDQogICJpYXQiOiAxNjgzMDAwMDAwLA0KICAiZXhwIjogMTg4MzAwMDAwMCwNCiAgInN1YiI6ICJ1c2VyXzQyIiwNCiAgIm5hdGlvbmFsaXRpZXMiOiBbDQogICAgew0KICAgICAgIi4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIg0KICAgIH0sDQogICAgew0KICAgICAgIi4uLiI6ICI3Q2Y2SmtQdWRyeTNsY2J3SGdlWjhraEF2MVUxT1NsZXJQMFZrQkpyV1owIg0KICAgIH0sDQogICAgew0KICAgICAgIi4uLiI6ICI3Q2Y2SmtQdWRyeTNsY2J3SGdlWjhraEF2MVUxT1NsZXJQMFZrQkpyV1owIg0KICAgIH0NCiAgXSwNCiAgIl9zZF9hbGciOiAic2hhLTI1NiIsDQogICJjbmYiOiB7DQogICAgImp3ayI6IHsNCiAgICAgICJrdHkiOiAiRUMiLA0KICAgICAgImNydiI6ICJQLTI1NiIsDQogICAgICAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwNCiAgICAgICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEiDQogICAgfQ0KICB9DQp9.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
	duplicateDigestSdArrayClaimJwt := "eyJhbGciOiAiRVMyNTYifQ.ew0KICAiX3NkIjogWw0KICAgICJDclFlN1M1a3FCQUh0LW5NWVhnYzZiZHQyU0g1YVRZMXNVX00tUGdralBJIiwNCiAgICAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsDQogICAgIlBvckZicEt1VnU2eHltSmFndmtGc0ZYQWJSb2MySkdsQVVBMkJBNG83Y0kiLA0KICAgICJUR2Y0b0xiZ3dkNUpRYUh5S1ZRWlU5VWRHRTB3NXJ0RHNyWnpmVWFvbUxvIiwNCiAgICAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsDQogICAgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLA0KICAgICJnYk9zSTRFZHEyeDJLdy13NXdQRXpha29iOWhWMWNSRDBBVE4zb1FMOUpNIiwNCiAgICAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCINCiAgXSwNCiAgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsDQogICJpYXQiOiAxNjgzMDAwMDAwLA0KICAiZXhwIjogMTg4MzAwMDAwMCwNCiAgInN1YiI6ICJ1c2VyXzQyIiwNCiAgIm5hdGlvbmFsaXRpZXMiOiBbDQogICAgew0KICAgICAgIi4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIg0KICAgIH0sDQogICAgew0KICAgICAgIi4uLiI6ICI3Q2Y2SmtQdWRyeTNsY2J3SGdlWjhraEF2MVUxT1NsZXJQMFZrQkpyV1owIg0KICAgIH0sDQogICAgew0KICAgICAgIi4uLiI6ICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Ig0KICAgIH0NCiAgXSwNCiAgIl9zZF9hbGciOiAic2hhLTI1NiIsDQogICJjbmYiOiB7DQogICAgImp3ayI6IHsNCiAgICAgICJrdHkiOiAiRUMiLA0KICAgICAgImNydiI6ICJQLTI1NiIsDQogICAgICAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwNCiAgICAgICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEiDQogICAgfQ0KICB9DQp9.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
	duplicateDigestNestedSdClaimJwt := "eyJhbGciOiAiRVMyNTYifQ.ew0KICAiX3NkIjogWw0KICAgICJDclFlN1M1a3FCQUh0LW5NWVhnYzZiZHQyU0g1YVRZMXNVX00tUGdralBJIiwNCiAgICAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsDQogICAgIlBvckZicEt1VnU2eHltSmFndmtGc0ZYQWJSb2MySkdsQVVBMkJBNG83Y0kiLA0KICAgICJUR2Y0b0xiZ3dkNUpRYUh5S1ZRWlU5VWRHRTB3NXJ0RHNyWnpmVWFvbUxvIiwNCiAgICAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsDQogICAgIlh6RnJ6d3NjTTZHbjZDSkRjNnZWSzhCa01uZkc4dk9TS2ZwUElaZEFmZEUiLA0KICAgICJnYk9zSTRFZHEyeDJLdy13NXdQRXpha29iOWhWMWNSRDBBVE4zb1FMOUpNIiwNCiAgICAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCINCiAgXSwNCiAgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsDQogICJpYXQiOiAxNjgzMDAwMDAwLA0KICAiZXhwIjogMTg4MzAwMDAwMCwNCiAgInN1YiI6ICJ1c2VyXzQyIiwNCiAgImtleSI6IHsNCiAgICAiX3NkIjogWw0KICAgICAgImpzdTl5VnVsd1FRbGhGbE1fM0psek1hU0Z6Z2xoUUcwRHBmYXlRd0xVSzQiDQogICAgXQ0KICB9LA0KICAibmF0aW9uYWxpdGllcyI6IFsNCiAgICB7DQogICAgICAiLi4uIjogInBGbmRqa1pfVkN6bXlUYTZVamxabzNkaC1rbzhhSUtRYzlEbEd6aGFWWW8iDQogICAgfSwNCiAgICB7DQogICAgICAiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAiDQogICAgfQ0KICBdLA0KICAiX3NkX2FsZyI6ICJzaGEtMjU2IiwNCiAgImNuZiI6IHsNCiAgICAiandrIjogew0KICAgICAgImt0eSI6ICJFQyIsDQogICAgICAiY3J2IjogIlAtMjU2IiwNCiAgICAgICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLA0KICAgICAgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSINCiAgICB9DQogIH0NCn0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"

	for i, testJwt := range []string{duplicateDigestSdClaimJwt, duplicateDigestArrayClaimJwt, duplicateDigestSdArrayClaimJwt, duplicateDigestNestedSdClaimJwt} {
		sdJwt, err := go_sd_jwt.New(testJwt)
		if err == nil {
			t.Log("iteration: ", i)
			t.Error("error should be thrown")
			t.FailNow()
		}
		if sdJwt != nil {
			t.Log("iteration: ", i)
			t.Error("sdJwt should be nil: ", sdJwt)
		}
		if err.Error() != "failed to validate digests: duplicate digest found" {
			t.Log("iteration: ", i)
			t.Error("error message is not correct: ", err.Error())
		}
	}
}

func TestSDJwtWithoutSD(t *testing.T) {
	testJwt := "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJmaXJzdG5hbWUiOiJKb2huIiwibGFzdG5hbWUiOiJEb2UiLCJzc24iOiIxMjMtNDUtNjc4OSIsImlkIjoiMTIzNCIsIl9zZF9hbGciOiJTSEEtMjU2In0.sUA_aYeA4YNQ1Paxna30VLAce1KdxvYMPEIduCwSD6X_Z56ZrBY5fbUBM5JVQ3vceS86CCghr8wkemdhQYRdfA~"
	sdJwt, err := go_sd_jwt.New(testJwt)

	if err != nil {
		t.Fatalf("Token not parseable: %s", err.Error())
	}

	_, err = sdJwt.GetDisclosedClaims()

	if err != nil {
		t.Log("Token cant survive without Selective Disclosures")
		t.Fatalf("The token has empty selective disclosure but fails in parsing: %s", err.Error())
	}
}
