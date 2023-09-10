# Go SD-JWT
Package go_sd_jwt provides a library for creating and validating SD-JWTs. The
resulting SdJwt object exposes methods for retrieving the claims and disclosures
as well as retrieving all disclosed claims in line with the specification.

For more information on SD-JWTs, see the [Selective Disclosure JWTs RFC](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html)

## Requirements
- Go 1.21 or higher

## Installation
```bash
go get github.com/MichaelFraser99/go-sd-jwt
```

## Algorithms Supported
Currently, the module will support the following jwt signing algorithms:
- ES256
- ES384
- ES512

## Functions
### Pointer
```go
func Pointer[T comparable](t T) *T
```
Pointer is a helper method that returns a pointer to the given value.


### PointerMap
```go
func PointerMap(m map[string]any) *map[string]any
```
PointerMap is a helper method that returns a pointer to the given map.

### PointerSlice
```go
func PointerSlice(s []any) *[]any
```
PointerSlice is a helper method that returns a pointer to the given slice.


## Types
### Disclosure
```go
type Disclosure struct {
// Has unexported fields.
}
```
This object represents a single disclosure in a SD-JWT. Helper
methods are provided for retrieving the contents

```go
func (d *Disclosure) ClaimName() *string
```
ClaimName returns the claim name of the disclosure

```go
func (d *Disclosure) ClaimValue() string
```
ClaimValue returns the claim value of the disclosure

```go
func (d *Disclosure) EncodedValue() string
```
EncodedValue returns the disclosure as it was listed in the original SD-JWT

```go
func (d *Disclosure) RawValue() string
```
RawValue returns the decoded contents of the disclosure

```go
func (d *Disclosure) Salt() string
```
Salt returns the salt of the disclosure

### SdJwt
```go
type SdJwt struct {
// Has unexported fields.
}
```
SdJwt this object represents a valid SD-JWT. Created using the FromToken function
which performs the required validation. Helper methods are provided for
retrieving the contents

```go
func FromToken(token string) (*SdJwt, error)
```
FromToken Creates a new SD-JWT from a JWS or JWT format token. The token is
validated inline with the SD-JWT specification. If the token is valid,
a new SdJwt object is returned.

```go
func (s *SdJwt) Body() *map[string]any
```
Body returns the body of the JWT

```go
func (s *SdJwt) Disclosures() []Disclosure
```
Disclosures returns the disclosures of the SD-JWT

```go
func (s *SdJwt) GetDisclosedClaims() (map[string]any, error)
```
GetDisclosedClaims returns the claims that were disclosed in the token or
included as plaintext values. This function will error one of the following
scenarios is encountered:
1. The SD-JWT contains a disclosure that does not
match an included digest
2. The SD-JWT contains a malformed _sd claim
3. The SD-JWT contains an unsupported value for the _sd_alg claim
4. The SD-JWT has a disclosure that is malformed for the use (e.g. doesn't contain a claim
name for a non-array digest)

```go
func (s *SdJwt) Head() map[string]any
```
Head returns the head of the JWT

```go
func (s *SdJwt) Signature() string
```
Signature returns the signature of the provided token used to verify it

```go
func (s *SdJwt) Token() string
```
Token returns the JWT token as it was received
