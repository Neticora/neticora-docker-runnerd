package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func readCorpus(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestPublicCanonicalCorpus(t *testing.T) {
	var fixtures []struct {
		ID                string
		Value             json.RawMessage
		Canonical, SHA256 string
	}
	if err := json.Unmarshal(readCorpus(t, "canonicalization.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			data, err := CanonicalizeJSON(f.Value)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := LogicalHashJSON(f.Value)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != f.Canonical || hash != f.SHA256 {
				t.Fatal("canonical bytes/hash mismatch")
			}
		})
	}
}
func TestPublicRawUnicodeCorpus(t *testing.T) {
	var fixtures []struct {
		ID, Schema, Hex, Canonical, SHA256 string
		Valid                              bool
	}
	if err := json.Unmarshal(readCorpus(t, "unicode-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			data, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			message, err := EncodeValidatedJSON(f.Schema, data)
			if (err == nil) != f.Valid {
				t.Fatalf("acceptance mismatch: %v", err)
			}
			if f.Valid {
				if string(message.Bytes()) != f.Canonical {
					t.Fatal("canonical mismatch")
				}
				hash, err := LogicalHashJSON(data)
				if err != nil || hash != f.SHA256 {
					t.Fatal("hash mismatch")
				}
			}
		})
	}
}
func TestPublicOutboundCorpus(t *testing.T) {
	var fixtures []struct {
		ID, Schema, HashField, CanonicalPayload, SHA256 string
		Value                                           json.RawMessage
		Valid, HashValid                                bool
	}
	if err := json.Unmarshal(readCorpus(t, "outbound-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			_, err := EncodeValidatedJSON(f.Schema, f.Value)
			inboundErr := ValidateInboundJSON(f.Schema, f.Value)
			if (inboundErr == nil) != (f.Valid && f.HashValid) {
				t.Fatalf("inbound integrity acceptance mismatch: %v", inboundErr)
			}
			if (err == nil) != (f.Valid && f.HashValid) {
				t.Fatalf("outbound acceptance mismatch: %v", err)
			}
			if f.Valid {
				model, err := DecodeWire(f.Schema, f.Value)
				if err != nil {
					t.Fatal(err)
				}
				_, err = EncodeValidated(f.Schema, model)
				if (err == nil) != f.HashValid {
					t.Fatalf("generated outbound acceptance mismatch: %v", err)
				}
				hash, err := PayloadHashJSON(f.Schema, f.Value)
				if err != nil || hash != f.SHA256 {
					t.Fatalf("payload hash mismatch: %v", err)
				}
			}
		})
	}
}
func TestCanonicalHostileInputAndBounds(t *testing.T) {
	for _, data := range []string{
		`{"x":1,"\u0078":2}`, `"\ud800"`, `"\udc00"`, "\xef\xbb\xbf{}", `{} {}`,
		`9007199254740992`, `-9007199254740992`, `1.1`, `1e9999999999`, `1e-9999999999`,
		strings.Repeat("[", MaxWireDepth+2) + strings.Repeat("]", MaxWireDepth+2),
		`"` + strings.Repeat("x", MaxWireBytes) + `"`,
	} {
		if _, err := CanonicalizeJSON([]byte(data)); err == nil {
			t.Fatalf("accepted invalid input (length %d)", len(data))
		}
	}
	for input, expected := range map[string]string{`1.00e2`: "100", `100e-2`: "1", `0e9999999999999`: "0", `-0.0`: "0", `90071992547409910e-1`: "9007199254740991", `"\u2028\u2029"`: "\"\u2028\u2029\""} {
		got, err := CanonicalizeJSON([]byte(input))
		if err != nil || string(got) != expected {
			t.Fatalf("%s: %s %v", input, got, err)
		}
	}
	if _, err := CanonicalizeJSON([]byte("\"\x80\"")); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
func TestOutboundSnapshotAndMutation(t *testing.T) {
	var fixtures []struct {
		Schema string
		Value  json.RawMessage
	}
	if err := json.Unmarshal(readCorpus(t, "outbound-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(fixtures[1].Value, &object); err != nil {
		t.Fatal(err)
	}
	message, err := EncodeValidated("HostCommand", object)
	if err != nil {
		t.Fatal(err)
	}
	original := message.Bytes()
	copyBytes := message.Bytes()
	copyBytes[0] = '!'
	object["executionId"] = "another"
	if !bytes.Equal(original, message.Bytes()) {
		t.Fatal("caller changed snapshot")
	}
	if _, err := EncodeValidated("HostCommand", object); err == nil {
		t.Fatal("stale hash accepted")
	}
	var out bytes.Buffer
	n, err := message.WriteTo(&out)
	if err != nil || n != int64(len(original)) || !bytes.Equal(original, out.Bytes()) {
		t.Fatal("transmission changed snapshot")
	}
	if _, err := (Outbound{}).WriteTo(io.Discard); err == nil {
		t.Fatal("zero message accepted")
	}
	object["executionId"] = string([]byte{0x80})
	if _, err := EncodeValidated("HostCommand", object); err == nil {
		t.Fatal("native invalid Unicode replaced")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := EncodeValidated("HostCommand", cycle); err == nil {
		t.Fatal("cycle accepted")
	}
	if _, err := PayloadHashJSON("Timestamp", []byte(`"2026-10-25T00:00:00.000Z"`)); err == nil {
		t.Fatal("arbitrary hash field exclusion allowed")
	}
}
func TestNestedMessageHashVerification(t *testing.T) {
	var fixtures []struct {
		Schema string
		Value  json.RawMessage
	}
	if err := json.Unmarshal(readCorpus(t, "outbound-wire.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if err := json.Unmarshal(fixtures[0].Value, &command); err != nil {
		t.Fatal(err)
	}
	command["spec"].(map[string]any)["poolId"] = "changed"
	raw, _ := json.Marshal(command)
	hash, err := PayloadHashJSON("HostCommand", raw)
	if err != nil {
		t.Fatal(err)
	}
	command["payloadHash"] = hash
	if _, err := EncodeValidated("HostCommand", command); err == nil {
		t.Fatal("nested stale spec hash accepted")
	}
	updated, _ := json.Marshal(command)
	if err := ValidateInboundJSON("HostCommand", updated); err == nil {
		t.Fatal("inbound nested stale spec hash accepted")
	}
	for _, f := range fixtures {
		if f.Schema == "HostEvent" {
			batch := []byte(fmt.Sprintf(`{"events":[%s]}`, f.Value))
			if err := Validate("HostEvent", f.Value); err == nil {
				_, err = EncodeValidatedJSON("EventBatch", batch)
				_, directErr := EncodeValidatedJSON("HostEvent", f.Value)
				if (err == nil) != (directErr == nil) {
					t.Fatal("batch bypassed event hash validation")
				}
			}
		}
	}
}
