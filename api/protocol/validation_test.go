package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func jsonValue(t *testing.T, raw []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGeneratedModelsAgainstCanonicalCorpus(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID     string          `json:"id"`
		Schema string          `json:"schema"`
		Value  json.RawMessage `json:"value"`
		Valid  bool            `json:"valid"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			value, err := DecodeWire(fixture.Schema, fixture.Value)
			if (err == nil) != fixture.Valid {
				t.Fatalf("model decode accepted=%v expected=%v: %v", err == nil, fixture.Valid, err)
			}
			if !fixture.Valid {
				return
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(jsonValue(t, encoded), jsonValue(t, fixture.Value)) {
				t.Fatalf("generated model changed wire meaning for %s", fixture.ID)
			}
			if err := Validate(fixture.Schema, encoded); err != nil {
				t.Fatalf("model re-encoding invalid: %v", err)
			}
		})
	}
}

func TestOptionalNullableAndExactCounters(t *testing.T) {
	for _, field := range []string{"", `,"encryptedBootstrap":null`, `,"encryptedBootstrap":""`, `,"encryptedBootstrap":"ciphertext"`} {
		raw := []byte(`{"issuanceId":"i","state":"UNCERTAIN"` + field + `}`)
		value, err := DecodeStartResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(jsonValue(t, raw), jsonValue(t, encoded)) {
			t.Fatal("absent, null and empty must remain distinct")
		}
	}
	for _, counter := range []string{"9223372036854775807", "9223372036854775808", "18446744073709551615"} {
		value, err := DecodeUInt64String([]byte(`"` + counter + `"`))
		if err != nil || value != counter {
			t.Fatalf("exact uint64 lost: %v", err)
		}
	}
	if _, err := DecodeUInt64String([]byte(`"18446744073709551616"`)); err == nil {
		t.Fatal("uint64 overflow accepted")
	}
}

func TestMalformedInputDoesNotLeakCredentials(t *testing.T) {
	secret := "canary-secret-not-for-diagnostics"
	for _, raw := range []string{`{"assertion":"` + secret + `","unknown":true}`, `{"assertion":"` + secret + `"} {}`} {
		_, err := DecodeTokenRequest([]byte(raw))
		if err == nil {
			t.Fatal("malformed input accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("validation error leaked payload")
		}
	}
	if _, err := DecodeWire("NotASchema", []byte(`{}`)); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestGeneratedEnumHelpersCannotBypassCanonicalValidation(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		if fixture.ID != "provider-event" {
			continue
		}
		value := jsonValue(t, fixture.Value).(map[string]any)
		observation := value["providerObservation"].(map[string]any)
		observation["conclusion"] = "<nil>"
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeHostEvent(encoded); err == nil {
			t.Fatal("generator convenience enum constant bypassed canonical enum")
		}
		return
	}
	t.Fatal("provider fixture missing")
}

func TestDuplicateKeyFixtures(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/duplicate-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID     string `json:"id"`
		Schema string `json:"schema"`
		Raw    string `json:"raw"`
		Valid  bool   `json:"valid"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			err := Validate(fixture.Schema, []byte(fixture.Raw))
			if (err == nil) != fixture.Valid {
				t.Fatalf("validate accepted=%v expected=%v: %v", err == nil, fixture.Valid, err)
			}
		})
	}
}

func TestHostEventMutationSemantics(t *testing.T) {
	t.Run("decode-modify-reencode", func(t *testing.T) {
		raw := []byte(`{"eventId":"event-a","executionId":"exec-a","attemptId":"attempt-a","generation":"1","sequence":"1","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observation":{"runtimeRef":{"engine":"docker","scope":"engine-a","resourceKind":"container","resourceId":"immutable-a","executionId":"exec-a","generation":"1","specHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"state":"running","observedAt":"2026-10-25T00:00:00.000Z"}}`)
		value, err := DecodeHostEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		value.Sequence = "2"
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate("HostEvent", encoded); err != nil {
			t.Fatalf("reencoded mutation invalid: %v", err)
		}
		got := jsonValue(t, encoded).(map[string]any)
		if got["sequence"] != "2" {
			t.Fatal("modified sequence not serialized")
		}
	})

	t.Run("clear-observation-removes-stale-union-field", func(t *testing.T) {
		raw := []byte(`{"eventId":"event-a","executionId":"exec-a","attemptId":"attempt-a","generation":"1","sequence":"1","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observation":{"runtimeRef":{"engine":"docker","scope":"engine-a","resourceKind":"container","resourceId":"immutable-a","executionId":"exec-a","generation":"1","specHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"state":"running","observedAt":"2026-10-25T00:00:00.000Z"}}`)
		value, err := DecodeHostEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		value.Observation = nil
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		object := jsonValue(t, encoded).(map[string]any)
		if _, found := object["observation"]; found {
			t.Fatal("stale observation retained after clearing field")
		}
		if err := Validate("HostEvent", encoded); err == nil {
			t.Fatal("cleared event unexpectedly remained valid")
		}
	})

	t.Run("construct-entirely-through-generated-apis", func(t *testing.T) {
		value := HostEvent{
			AttemptId:   "attempt-a",
			EventId:     "event-a",
			ExecutionId: "exec-a",
			Generation:  "1",
			PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Sequence:    "1",
			Observation: &RuntimeObservation{
				RuntimeRef: RuntimeRef{
					Engine:       "docker",
					Scope:        "engine-a",
					ResourceKind: "container",
					ResourceId:   "immutable-a",
					ExecutionId:  "exec-a",
					Generation:   "1",
					SpecHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
				State:      "running",
				ObservedAt: "2026-10-25T00:00:00.000Z",
			},
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate("HostEvent", encoded); err != nil {
			t.Fatalf("constructed event invalid: %v", err)
		}
	})

	t.Run("switch-variants-does-not-retain-stale-raw-fields", func(t *testing.T) {
		raw := []byte(`{"eventId":"event-a","executionId":"exec-a","attemptId":"attempt-a","generation":"1","sequence":"1","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","providerObservation":{"provider":"github","organization":"org-a","pool":"pool-a","agentId":"123","agentName":"runner-a","registered":true,"observedAt":"2026-10-25T00:00:00.000Z"}}`)
		value, err := DecodeHostEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		value.ProviderObservation = nil
		value.Observation = &RuntimeObservation{
			RuntimeRef: RuntimeRef{
				Engine:       "docker",
				Scope:        "engine-a",
				ResourceKind: "container",
				ResourceId:   "immutable-a",
				ExecutionId:  "exec-a",
				Generation:   "1",
				SpecHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			State:      "running",
			ObservedAt: "2026-10-25T00:00:00.000Z",
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		object := jsonValue(t, encoded).(map[string]any)
		if _, found := object["providerObservation"]; found {
			t.Fatal("stale providerObservation retained after variant switch")
		}
		if _, found := object["observation"]; !found {
			t.Fatal("observation missing after variant switch")
		}
		if err := Validate("HostEvent", encoded); err != nil {
			t.Fatalf("switched variant invalid: %v", err)
		}
	})
}

func TestHostCommandMutationSemantics(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Schema string          `json:"schema"`
		Value  json.RawMessage `json:"value"`
		Valid  bool            `json:"valid"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	var startRaw, controlRaw json.RawMessage
	for _, fixture := range fixtures {
		if fixture.Schema != "HostCommand" || !fixture.Valid {
			continue
		}
		value := jsonValue(t, fixture.Value).(map[string]any)
		kind, _ := value["kind"].(string)
		switch kind {
		case "start":
			if startRaw == nil {
				startRaw = fixture.Value
			}
		case "cancel":
			if controlRaw == nil {
				controlRaw = fixture.Value
			}
		}
	}
	if startRaw == nil || controlRaw == nil {
		t.Fatal("missing HostCommand start/cancel fixtures")
	}

	command, err := DecodeHostCommand(startRaw)
	if err != nil {
		t.Fatal(err)
	}
	startVariant, err := command.AsStartCommand()
	if err != nil {
		t.Fatal(err)
	}

	controlVariant, err := DecodeControlCommand(controlRaw)
	if err != nil {
		t.Fatal(err)
	}
	merged := command
	if err := merged.MergeControlCommand(controlVariant); err != nil {
		t.Fatal(err)
	}
	mergedBytes, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate("HostCommand", mergedBytes); err == nil {
		t.Fatal("generated merge retained invalid start/control fields without rejection")
	}
	if err := command.FromControlCommand(controlVariant); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate("HostCommand", encoded); err != nil {
		t.Fatalf("control variant invalid after switch: %v", err)
	}
	controlObject := jsonValue(t, encoded).(map[string]any)
	if controlObject["kind"] != "cancel" {
		t.Fatal("control variant kind not serialized")
	}
	if _, found := controlObject["spec"]; found {
		t.Fatal("stale start spec retained after switching to control variant")
	}

	if err := command.FromStartCommand(startVariant); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate("HostCommand", encoded); err != nil {
		t.Fatalf("start variant invalid after switching back: %v", err)
	}
	startObject := jsonValue(t, encoded).(map[string]any)
	if startObject["kind"] != "start" {
		t.Fatal("start variant kind not serialized")
	}
	if _, found := startObject["executionId"]; found {
		t.Fatal("stale control executionId retained after switching back to start variant")
	}
}
