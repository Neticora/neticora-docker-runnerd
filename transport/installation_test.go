package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstallationRequiresAuthenticatedStrictResponse(t *testing.T) {
	valid := map[string]any{"identity": map[string]string{"hostId": "11111111-1111-4111-8111-111111111111", "keyId": "22222222-2222-4222-8222-222222222222", "keyVersion": "1", "sessionEpoch": "1"}, "tenantId": "tenant", "installationId": "enrollment:original", "runnerDeploymentId": "pool", "enrollmentRequestId": "request", "publicKeyFingerprint": strings.Repeat("a", 64)}
	for _, scenario := range []string{"valid", "missing-pool", "unknown", "duplicate", "redirect", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/runner-hosts/me/installation" || r.Header.Get("Authorization") != "Bearer secret" {
					t.Error("authentication or endpoint changed")
				}
				copy := map[string]any{}
				for k, v := range valid {
					copy[k] = v
				}
				switch scenario {
				case "missing-pool":
					delete(copy, "runnerDeploymentId")
				case "unknown":
					copy["admissionEnabled"] = true
				case "redirect":
					w.Header().Set("Location", "https://elsewhere.invalid")
					w.WriteHeader(302)
					return
				case "duplicate":
					_, _ = w.Write([]byte(`{"tenantId":"a","tenantId":"b"}`))
					return
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("a", 16385)))
					return
				}
				_ = json.NewEncoder(w).Encode(copy)
			}))
			defer server.Close()
			c := trustedClient(t, server)
			c.base.Path = "/runner-hosts"
			_, e := c.Installation(context.Background(), "secret")
			if (e == nil) != (scenario == "valid") {
				t.Fatalf("unexpected response acceptance: %v", e)
			}
			if _, e = c.Installation(context.Background(), ""); e == nil {
				t.Fatal("missing access token accepted")
			}
		})
	}
}
