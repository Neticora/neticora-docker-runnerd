// Package protocol provides generated host wire models and validated decoding.
// A decoded value is transport data, never authenticated host authority.
package protocol

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema.gen.json
var schemaBytes []byte

var compiled = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseLoader(offlineLoader{})
	if err := registerQualifiedURI(c); err != nil {
		return nil, err
	}
	const uri = "urn:neticora:host-protocol"
	if err := c.AddResource(uri, doc); err != nil {
		return nil, err
	}
	components := doc.(map[string]any)["components"].(map[string]any)["schemas"].(map[string]any)
	result := make(map[string]*jsonschema.Schema, len(components))
	for name := range components {
		schema, err := c.Compile(uri + "#/components/schemas/" + name)
		if err != nil {
			return nil, err
		}
		result[name] = schema
	}
	return result, nil
})

type offlineLoader struct{}

func (offlineLoader) Load(uri string) (any, error) {
	return nil, fmt.Errorf("external schema loading prohibited: %s", uri)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing host JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid host JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid host JSON")
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid host JSON")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate host JSON key")
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim('}') {
			return fmt.Errorf("invalid host JSON")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim(']') {
			return fmt.Errorf("invalid host JSON")
		}
	default:
		return fmt.Errorf("invalid host JSON")
	}
	return nil
}

// Validate checks the exact schema dialect without coercing or stripping fields.
func Validate(schema string, data []byte) error {
	if err := checkWireBudget(data); err != nil {
		return err
	}
	if err := validateJSONUnicode(data); err != nil {
		return err
	}
	schemas, err := compiled()
	if err != nil {
		return fmt.Errorf("host protocol schema unavailable: %w", err)
	}
	validator, ok := schemas[schema]
	if !ok {
		return fmt.Errorf("unknown host protocol schema: %s", schema)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return fmt.Errorf("invalid host JSON")
	}
	if _, err := canonicalValue(value); err != nil {
		return err
	}
	if err := validator.Validate(value); err != nil {
		// Validator details may include transient credentials from the payload.
		return fmt.Errorf("invalid host protocol %s payload", schema)
	}
	return nil
}

func decode(schema string, data []byte, destination any) error {
	if err := Validate(schema, data); err != nil {
		return err
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("host protocol %s model binding failed", schema)
	}
	return nil
}

// DecodeWire validates original bytes and returns the generated schema model.
// Use the generated DecodeHostHeartbeat/DecodeStartCommand/etc. for typed calls.
func DecodeWire(schema string, data []byte) (any, error) {
	decoder, ok := wireDecoders[schema]
	if !ok {
		return nil, fmt.Errorf("unknown host protocol schema: %s", schema)
	}
	return decoder(data)
}
