package utils

import (
	"encoding/json"
	"errors"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/MichaelFraser99/go-sd-jwt/internal/model"
	"reflect"
	"strings"
)

func ValidateArrayClaims(s *[]any, currentDisclosure *disclosure.Disclosure, base64HashedDisclosure string) (found bool, err error) {
	for i, v := range *s {

		switch reflect.TypeOf(v).Kind() {

		case reflect.Slice:
			found, err = ValidateArrayClaims(PointerSlice(v.([]any)), currentDisclosure, base64HashedDisclosure)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}

		case reflect.Map:
			ad := &model.ArrayDisclosure{}
			vb, err := json.Marshal(v)
			if err != nil {
				return false, err
			}

			_ = json.Unmarshal(vb, ad)

			if ad.Digest != nil {
				if *ad.Digest == base64HashedDisclosure {
					(*s)[i] = currentDisclosure.Value
					return true, nil
				}
			}

			found, err = ValidateSDClaims(PointerMap(v.(map[string]any)), currentDisclosure, base64HashedDisclosure)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}
		}
	}

	return false, nil
}

func ValidateSDClaims(values *map[string]any, currentDisclosure *disclosure.Disclosure, base64HashedDisclosure string) (found bool, err error) {
	if _, ok := (*values)["_sd"]; ok {
		for _, digest := range (*values)["_sd"].([]any) {
			sDigest := digest.(string)
			if sDigest == base64HashedDisclosure {
				if currentDisclosure.Key != nil {
					(*values)[*currentDisclosure.Key] = currentDisclosure.Value
					return true, nil
				} else {
					return false, errors.New("invalid disclosure format for _sd claim")
				}
			}
		}
	}

	for k, v := range *values {
		if k != "_sd" && k != "_sd_alg" {
			if reflect.TypeOf(v).Kind() == reflect.Slice {
				found, err = ValidateArrayClaims(PointerSlice(v.([]any)), currentDisclosure, base64HashedDisclosure)
				if err != nil {
					return false, err
				}
			} else if reflect.TypeOf(v).Kind() == reflect.Map {
				found, err = ValidateSDClaims(PointerMap(v.(map[string]any)), currentDisclosure, base64HashedDisclosure)
				if err != nil {
					return found, err
				}
			}
			if found {
				return true, nil
			}
		}
	}
	return false, nil
}

func GetDigests(m map[string]any) []any {
	var digests []any
	for k, v := range m {
		if reflect.TypeOf(v).Kind() == reflect.Map {
			digests = append(digests, GetDigests(v.(map[string]any))...)
		} else if k == "_sd" {
			digests = append(digests, v.([]any)...)
		} else if reflect.TypeOf(v).Kind() == reflect.Slice {
			for _, v2 := range v.([]any) {
				b, err := json.Marshal(v2)
				if err == nil {
					var ArrayDisclosure model.ArrayDisclosure
					err = json.Unmarshal(b, &ArrayDisclosure)
					if err == nil && ArrayDisclosure.Digest != nil {
						digests = append(digests, *ArrayDisclosure.Digest)
					}
				}
			}
		}
	}
	return digests
}

func StripSDClaimsFromSlice(input []any) []any {
	var output []any
	for _, v := range input {
		switch reflect.TypeOf(v).Kind() {
		case reflect.Map:
			strippedValue := StripSDClaims(v.(map[string]any))
			if strippedValue != nil {
				output = append(output, strippedValue)
			}
		case reflect.Slice:
			strippedValue := StripSDClaimsFromSlice(v.([]any))
			if strippedValue != nil {
				output = append(output, strippedValue)
			}
		default:
			output = append(output, v)
		}
	}
	if len(output) > 0 {
		return output
	} else {
		return nil
	}
}

func StripSDClaims(body map[string]any) map[string]any {
	bodyMap := make(map[string]any)
	for k, v := range body {
		switch reflect.TypeOf(v).Kind() {
		case reflect.Map:
			strippedValue := StripSDClaims(v.(map[string]any))
			if strippedValue != nil {
				bodyMap[k] = strippedValue
			}
		case reflect.Slice:
			if k != "_sd" {
				strippedValue := StripSDClaimsFromSlice(v.([]any))
				if strippedValue != nil {
					bodyMap[k] = strippedValue
				}
			}
		default:
			if k != "_sd_alg" && k != "..." {
				bodyMap[k] = v
			}
		}
	}
	if len(bodyMap) > 0 {
		return bodyMap
	} else {
		return nil
	}
}

func StringifyDisclosures(disclosures []disclosure.Disclosure) string {
	result := "["
	for i, d := range disclosures {
		if d.Key != nil {
			result += "(" + *d.Key + ") "
		} else {
			result += " "
		}
		b, _ := json.Marshal(d.Value)
		result += string(b)
		if i != len(disclosures)-1 {
			result += ", "
		}
	}
	result += "]"
	return result
}

func ValidateDigests(body map[string]any) error {
	digests := GetDigests(body)

	for _, d := range digests {
		count := 0
		for _, d2 := range digests {
			if d == d2 {
				count++
			}
		}
		if count > 1 {
			return errors.New("duplicate digest found")
		}
	}
	return nil
}

func ValidateDisclosures(disclosures []string) ([]disclosure.Disclosure, error) {
	var disclosureArray []disclosure.Disclosure

	if len(disclosures) == 0 {
		return nil, errors.New("token has no specified disclosures")
	}

	for _, d := range disclosures {
		count := 0
		if d != "" {
			for _, d2 := range disclosures {
				if d == d2 {
					count++
				}
			}
			if count > 1 {
				return nil, errors.New("duplicate disclosure found")
			}
			dis, err := disclosure.NewFromDisclosure(d)
			if err != nil {
				return nil, err
			}
			disclosureArray = append(disclosureArray, *dis)
		}
	}
	return disclosureArray, nil
}

func CheckForKbJwt(candidate string) *string {
	if !strings.Contains(candidate, ".") {
		return nil
	}

	sections := strings.Split(candidate, ".")
	if len(sections) != 3 {
		return nil
	}

	return &candidate
}

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

func CopyMap(m map[string]any) map[string]any {
	cp := make(map[string]any)
	for k, v := range m {
		vm, mapOk := v.(map[string]any)
		vs, sliceOk := v.([]any)
		if mapOk {
			cp[k] = CopyMap(vm)
		} else if sliceOk {
			cp[k] = CopySlice(vs)
		} else {
			cp[k] = v
		}
	}

	return cp
}

func CopySlice(s []any) []any {
	cp := make([]any, len(s))
	for i, v := range s {
		vm, mapOk := v.(map[string]any)
		vs, sliceOk := v.([]any)
		if mapOk {
			cp[i] = CopyMap(vm)
		} else if sliceOk {
			cp[i] = CopySlice(vs)
		} else {
			cp[i] = v
		}
	}
	return cp
}
