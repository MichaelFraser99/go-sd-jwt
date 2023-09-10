package error

type InvalidToken struct {
	Message string
}

func (e *InvalidToken) Error() string {
	return e.Message
}
