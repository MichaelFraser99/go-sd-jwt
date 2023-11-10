package go_sd_jwt

// Pointer is a helper method that returns a pointer to the given value.
func Pointer[T comparable](t T) *T {
	return &t
}

// PointerMap is a helper method that returns a pointer to the given map.
func PointerMap(m map[string]any) *map[string]any {
	return &m
}

// PointerSlice is a helper method that returns a pointer to the given slice.
func PointerSlice(s []any) *[]any {
	return &s
}
