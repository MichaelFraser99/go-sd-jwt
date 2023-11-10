package error

import "errors"

type InvalidToken struct {
	Message string
}

func (e *InvalidToken) Error() string {
	return e.Message
}

var InvalidJsonError = errors.New("")
var UnknownDisclosureError = errors.New("")
var ClaimNotFoundError = errors.New("")
