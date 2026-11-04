package transport

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTypeScriptBootstrapEnvelope(t *testing.T) {
	raw, err := os.ReadFile("testdata/bootstrap.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PrivateKey string           `json:"privateKey"`
		PublicKey  string           `json:"publicKey"`
		Binding    BootstrapBinding `json:"binding"`
		Bootstrap  string           `json:"bootstrap"`
		Sealed     string           `json:"sealed"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(vector.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	plain, err := OpenBootstrap(vector.Sealed, key, vector.Binding, now)
	if err != nil || string(plain) != vector.Bootstrap {
		t.Fatalf("interoperability failed: %v", err)
	}
	t.Run("expiry", func(t *testing.T) {
		if _, err := OpenBootstrap(vector.Sealed, key, vector.Binding, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
			t.Fatal("expired bootstrap accepted")
		}
	})
	for _, field := range []string{"host", "tenant", "execution", "generation", "start", "spec"} {
		t.Run(field, func(t *testing.T) {
			binding := vector.Binding
			switch field {
			case "host":
				binding.HostID = "another"
			case "tenant":
				binding.TenantID = "another"
			case "execution":
				binding.ExecutionID = "another"
			case "generation":
				binding.Generation = "8"
			case "start":
				binding.StartRequestID = "another"
			case "spec":
				binding.SpecHash = strings.Repeat("b", 64)
			}
			if _, err := OpenBootstrap(vector.Sealed, key, binding, now); err == nil {
				t.Fatal("binding mismatch accepted")
			}
		})
	}
	t.Run("tamper", func(t *testing.T) {
		raw, _ := base64.RawURLEncoding.DecodeString(vector.Sealed)
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		object["ciphertext"] = strings.Repeat("A", 48)
		data, _ := json.Marshal(object)
		if _, err := OpenBootstrap(base64.RawURLEncoding.EncodeToString(data), key, vector.Binding, now); err == nil {
			t.Fatal("ciphertext tamper accepted")
		}
	})
	t.Run("duplicate-key", func(t *testing.T) {
		raw, _ := base64.RawURLEncoding.DecodeString(vector.Sealed)
		raw = append([]byte(`{"hostId":"duplicate",`), raw[1:]...)
		if _, err := OpenBootstrap(base64.RawURLEncoding.EncodeToString(raw), key, vector.Binding, now); err == nil {
			t.Fatal("duplicate key accepted")
		}
	})
}
