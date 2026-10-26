package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSharedUnicodeWire(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/unicode-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID, Schema, Hex, Canonical string
		Valid                      bool
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			input, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := DecodeWire(f.Schema, input)
			if (err == nil) != f.Valid {
				t.Fatalf("accepted=%v expected=%v: %v", err == nil, f.Valid, err)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("decoder mutated wire bytes")
			}
			if !f.Valid {
				return
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(jsonValue(t, encoded), jsonValue(t, []byte(f.Canonical))) {
				t.Fatal("Unicode or nullable fields changed during binding")
			}
		})
	}
}

func TestSharedOutboundWire(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/outbound-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID, Schema string
		Value      json.RawMessage
		Valid      bool
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			value, err := DecodeWire(f.Schema, f.Value)
			if (err == nil) != f.Valid {
				t.Fatalf("accepted=%v expected=%v: %v", err == nil, f.Valid, err)
			}
			if !f.Valid {
				return
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(f.Schema, encoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(jsonValue(t, encoded), jsonValue(t, f.Value)) {
				t.Fatal("generated union changed validated payload")
			}
		})
	}
}

func TestUnicodeRejectionDoesNotLeakPayload(t *testing.T) {
	secret := "canary-credential-not-for-logs"
	_, err := DecodeTokenRequest([]byte(`{"assertion":"` + secret + `\ud800"}`))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("missing or unsafe Unicode rejection")
	}
}
