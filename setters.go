package go_sd_jwt

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
