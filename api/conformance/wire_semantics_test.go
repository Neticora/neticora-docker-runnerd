package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Independent lexical qualification before encoding/json can replace Unicode.
// Count backslash runs rather than relying on the protocol package's scanner.
func requireUnicode(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid Unicode")
	}
	for offset := 0; offset < len(data); {
		if data[offset] != '\\' {
			offset++
			continue
		}
		start := offset
		for offset < len(data) && data[offset] == '\\' {
			offset++
		}
		if (offset-start)%2 == 0 || offset == len(data) || data[offset] != 'u' {
			continue
		}
		if offset+5 > len(data) {
			return fmt.Errorf("invalid Unicode")
		}
		unit, err := strconv.ParseUint(string(data[offset+1:offset+5]), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid Unicode")
		}
		offset += 5
		if unit >= 0xdc00 && unit <= 0xdfff {
			return fmt.Errorf("invalid Unicode")
		}
		if unit < 0xd800 || unit > 0xdbff {
			continue
		}
		if offset+6 > len(data) || string(data[offset:offset+2]) != `\u` {
			return fmt.Errorf("invalid Unicode")
		}
		low, err := strconv.ParseUint(string(data[offset+2:offset+6]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return fmt.Errorf("invalid Unicode")
		}
		offset += 6
	}
	return nil
}

func strictRawValue(data []byte) (any, error) {
	if err := requireUnicode(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := decodeStrictValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return value, nil
}

func fixtureCompiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(load(t, "host-protocol.v1.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseLoader(offlineLoader{})
	// The independent schema harness also qualifies URI versus IRI semantics.
	base := jsonschema.NewCompiler()
	base.AssertFormat()
	base.UseLoader(offlineLoader{})
	if err := base.AddResource("urn:neticora:uri-check", map[string]any{"type": "string", "format": "uri"}); err != nil {
		t.Fatal(err)
	}
	uri, err := base.Compile("urn:neticora:uri-check")
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterFormat(&jsonschema.Format{Name: "uri", Validate: func(value any) error {
		if text, ok := value.(string); ok {
			for _, ch := range text {
				if ch > 127 {
					return fmt.Errorf("non-ASCII URI")
				}
			}
		}
		return uri.Validate(value)
	}})
	if err := c.AddResource("urn:neticora:host-protocol", doc); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUnicodeWireContract(t *testing.T) {
	c := fixtureCompiler(t)
	var fixtures []struct {
		ID, Schema, Hex, Canonical, SHA256 string
		Valid                              bool
	}
	if err := json.Unmarshal(load(t, "fixtures/unicode-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			schema, err := c.Compile("urn:neticora:host-protocol#/components/schemas/" + f.Schema)
			if err != nil {
				t.Fatal(err)
			}
			value, err := strictRawValue(raw)
			valid := err == nil && schema.Validate(value) == nil
			if valid != f.Valid {
				t.Fatalf("accepted=%v expected=%v", valid, f.Valid)
			}
			if !valid {
				return
			}
			text, err := canonical(value)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(text))
			if text != f.Canonical || hex.EncodeToString(sum[:]) != f.SHA256 {
				t.Fatal("canonical Unicode bytes/hash mismatch")
			}
		})
	}
}

func TestOutboundWireContract(t *testing.T) {
	c := fixtureCompiler(t)
	var fixtures []struct {
		ID, Schema, HashField, CanonicalPayload, SHA256 string
		Value                                           json.RawMessage
		Valid, HashValid                                bool
	}
	if err := json.Unmarshal(load(t, "fixtures/outbound-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			value, err := strictRawValue(f.Value)
			if err != nil {
				t.Fatal(err)
			}
			schema, err := c.Compile("urn:neticora:host-protocol#/components/schemas/" + f.Schema)
			if err != nil {
				t.Fatal(err)
			}
			valid := schema.Validate(value) == nil
			if valid != f.Valid {
				t.Fatalf("valid=%v expected=%v", valid, f.Valid)
			}
			if !valid {
				return
			}
			object := value.(map[string]any)
			payload := map[string]any{}
			for key, child := range object {
				if key != f.HashField {
					payload[key] = child
				}
			}
			text, err := canonical(payload)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(text))
			actual := hex.EncodeToString(sum[:])
			if text != f.CanonicalPayload || actual != f.SHA256 {
				t.Fatal("outbound hash preimage mismatch")
			}
			if (object[f.HashField] == actual) != f.HashValid {
				t.Fatal("mutated payload/hash conflict not detected")
			}
		})
	}
}

func TestCanonicalRejectsInvalidNativeGoStrings(t *testing.T) {
	for _, value := range []any{string([]byte{0x80}), map[string]any{string([]byte{0xed, 0xa0, 0x80}): "x"}} {
		if _, err := canonical(value); err == nil {
			t.Fatal("canonicalization replaced invalid native Go Unicode")
		}
	}
}
