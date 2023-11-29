package disclosure

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestNewFromObject(t *testing.T) {
	disclosure, err := NewFromObject("family_name", "Möbius", String("_26bc4LT-ac6q2KI6cBW5es"))
	if err != nil {
		t.Fatalf("no error expected: %s", err.Error())
	}

	if disclosure.Key == nil {
		t.Fatalf("key should not be nil")
	}
	if *disclosure.Key != "family_name" {
		t.Errorf("key should be family_name is: %s", *disclosure.Key)
	}
	if disclosure.Salt != "_26bc4LT-ac6q2KI6cBW5es" {
		t.Errorf("unexpected salt value returned: %s", disclosure.Salt)
	}
	strValue, ok := disclosure.Value.(string)
	if !ok {
		t.Fatalf("Returned value should be a string")
	}
	if strValue != "Möbius" {
		t.Errorf("unexpected disclosure value returned: %s", disclosure.Value)
	}
	if disclosure.EncodedValue != "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd" {
		t.Errorf("unexpected encoded value produced: %s", disclosure.EncodedValue)
	}
}

func TestNewFromArrayElement(t *testing.T) {
	disclosure, err := NewFromArrayElement("FR", String("lklxF5jMYlGTPUovMNIvCA"))
	if err != nil {
		t.Fatalf("no error expected: %s", err.Error())
	}

	if disclosure.Key != nil {
		t.Fatalf("key should not be nil, is: %s", *disclosure.Key)
	}
	if disclosure.Salt != "lklxF5jMYlGTPUovMNIvCA" {
		t.Errorf("unexpected salt value returned: %s", disclosure.Salt)
	}
	if string(disclosure.Value.(string)) != "FR" {
		t.Errorf("unexpected disclosure value returned: %s", disclosure.Value)
	}
	if disclosure.EncodedValue != "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwiRlIiXQ" {
		t.Errorf("unexpected encoded value produced: %s", disclosure.EncodedValue)
	}
}

func TestNewFromDisclosureObject(t *testing.T) {
	disclosures := []string{
		"WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
		"WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
		"WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
	}

	for i, d := range disclosures {
		t.Run(fmt.Sprintf("disclosure-%d", i), func(t *testing.T) {
			disclosure, err := NewFromDisclosure(d)
			if err != nil {
				t.Fatalf("no error expected: %s", err.Error())
			}

			if disclosure.Key == nil {
				t.Fatalf("key should not be nil")
			}
			if *disclosure.Key != "family_name" {
				t.Errorf("key should be family_name is: %s", *disclosure.Key)
			}
			if disclosure.Salt != "_26bc4LT-ac6q2KI6cBW5es" {
				t.Errorf("unexpected salt value returned: %s", disclosure.Salt)
			}
			if disclosure.Value.(string) != "Möbius" {
				t.Errorf("unexpected disclosure value returned: %s", disclosure.Value)
			}
			if disclosure.EncodedValue != d {
				t.Errorf("unexpected encoded value produced: %s", disclosure.EncodedValue)
			}
		})
	}
}

func TestNewFromDisclosureElementObject(t *testing.T) {
	disclosures := []string{
		"WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0",
		"WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwiRlIiXQ",
	}

	for i, d := range disclosures {
		t.Run(fmt.Sprintf("disclosure-%d", i), func(t *testing.T) {
			disclosure, err := NewFromDisclosure(d)
			if err != nil {
				t.Fatalf("no error expected: %s", err.Error())
			}

			if disclosure.Key != nil {
				t.Fatalf("key should not be nil, is: %s", *disclosure.Key)
			}
			if disclosure.Salt != "lklxF5jMYlGTPUovMNIvCA" {
				t.Errorf("unexpected salt value returned: %s", disclosure.Salt)
			}
			if disclosure.Value.(string) != "FR" {
				t.Errorf("unexpected disclosure value returned: %s", disclosure.Value)
			}
			if disclosure.EncodedValue != d {
				t.Errorf("unexpected encoded value produced: %s", disclosure.EncodedValue)
			}
		})
	}
}

func TestDisclosure_Hash(t *testing.T) {
	objectDisclosure, err := NewFromDisclosure("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
	if err != nil {
		t.Fatalf("no error expected: %s", err.Error())
	}

	arrayElementDisclosure, err := NewFromDisclosure("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0")
	if err != nil {
		t.Fatalf("no error expected: %s", err.Error())
	}

	hash := sha256.New()
	objectHash := objectDisclosure.Hash(hash)
	if string(objectHash) != "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY" {
		t.Errorf("unexpected hash result: %s", string(objectHash))
	}

	hash.Reset()
	arrayHash := arrayElementDisclosure.Hash(hash)
	if string(arrayHash) != "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs" {
		t.Errorf("unexpected hash result: %s", string(arrayHash))
	}
}
