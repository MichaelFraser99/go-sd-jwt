package go_sd_jwt

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
