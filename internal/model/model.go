package model

type JwsSdJwt struct {
	Payload     *string  `json:"payload"`
	Protected   *string  `json:"protected"`
	Signature   *string  `json:"signature"`
	Disclosures []string `json:"disclosures"`
	KbJwt       *string  `json:"kb_jwt"`
}

type ArrayDisclosure struct {
	Digest *string `json:"..."`
}
