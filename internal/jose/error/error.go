package error

type InvalidSignature struct {
	Message string
}

func (e *InvalidSignature) Error() string {
	return e.Message
}

type UnsupportedAlgorithm struct {
	Message string
}

func (e *UnsupportedAlgorithm) Error() string {
	return e.Message
}

type InvalidPublicKey struct {
	Message string
}

func (e *InvalidPublicKey) Error() string {
	return e.Message
}

type SigningError struct {
	Message string
}

func (e *SigningError) Error() string {
	return e.Message
}
