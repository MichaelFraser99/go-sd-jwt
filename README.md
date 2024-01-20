# Go SD-JWT
Package go_sd_jwt provides a library for creating and validating SD-JWTs. The
resulting SdJwt object exposes methods for retrieving the claims and disclosures
as well as retrieving all disclosed claims in line with the specification.

For more information on SD-JWTs, see the [Selective Disclosure JWTs RFC](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html)

Also see: [sdjwt.org](https://sdjwt.org/) for a playground powered by this module

## Requirements
- Go 1.21 or higher

## Installation
```bash
go get github.com/MichaelFraser99/go-sd-jwt
```

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
    Salt         string
    Key          *string
    Value        any
    EncodedValue string
}
```
This object represents a single disclosure in a SD-JWT. The EncodedValue property returns the disclosure string as provided in the original sd jwt

```go
func NewFromObject(key string, value any, salt *string) (*Disclosure, error)
```
NewFromObject creates a Disclosure object for the provided key/value pair and optional salt. If no salt provided, a new salt value of 128 bits is generated

```go
func NewFromArrayElement(element any, salt *string) (*Disclosure, error)
```
NewFromArrayElement creates a Disclosure object for the provided array element and optional salt. If no salt provided, a new salt value of 128 bits is generated

```go
func NewFromDisclosure(disclosure string) (*Disclosure, error)
```
NewFromDisclosure creates a Disclosure object from the provided encoded disclosure string

```go
func (d *Disclosure) Hash(hash hash.Hash)
```
Hash returns the digest bytes of the current disclosure using the provided hash

### SdJwt
```go
type SdJwt struct {
    Head        map[string]any
    Body        map[string]any
    Signature   string
    KbJwt       *kbjwt.KbJwt
    Disclosures []disclosure.Disclosure
}
```
SdJwt this object represents a valid SD-JWT. Created using the New or NewFromComponents functions
which performs the required validation.

```go
func New(token string) (*SdJwt, error)
```
New Creates a new SD-JWT from a JWT format token. The token is
validated inline with the SD-JWT specification. If the token is valid,
a new SdJwt object is returned.

```go
func NewFromComponents(protected, payload, signature string, disclosures []string, kbJwt *string) (*SdJwt, error)
```
NewFromComponents Creates a new SD-JWT from the individual components. This function
is designed to cater for the many different permutations of JSON format token.
If the token is valid, a new SdJwt object is returned.

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

### Usage
For an example e2e flow of an SD Jwt see the e2e_test
Contains examples of:
- creating an SD Jwt as an issuer
- receiving the SD Jwt as a holder
- re-issuing the SD Jwt as a holder with a subset of disclosures
- receiving the SD Jwt as a consumer

### Errors
This package defines the following errors:
- InvalidToken - The provided token is malformed in some way
- InvalidDisclosure - The provided disclosure is malformed or invalid in some way
