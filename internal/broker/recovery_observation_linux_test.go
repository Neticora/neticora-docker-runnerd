//go:build linux

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryObservationRequiresProtectedModeAndCurrentPeer(t *testing.T) {
	for _, name := range []string{"normal-mode", "recovery", "changed-peer", "lookup", "target"} {
		t.Run(name, func(t *testing.T) {
			e, r, _, _, _ := physicalFixture(t)
			e.recoveryOnly = name != "normal-mode"
			e.runtimeEndpoint = e.scope.EndpointIdentity
			if name == "changed-peer" {
				r.peerChanged = true
			}
			q := Request{Version: Version, Operation: "ProbeRecoveryRuntime"}
			if name == "lookup" {
				q.Lookup = &Lookup{}
			}
			if name == "target" {
				q.Target = "arbitrary-runtime"
			}
			h := handler{config: Config{ControllerUID: 1000}, executor: e}
			raw, _ := json.Marshal(q)
			request := httptest.NewRequest(http.MethodPost, "/v1/request", bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(context.WithValue(request.Context(), caller{}, uint32(1000)))
			reply := httptest.NewRecorder()
			h.ServeHTTP(reply, request)
			if name == "recovery" {
				var value Response
				json.Unmarshal(reply.Body.Bytes(), &value)
				if reply.Code != 200 || value.Ready || value.Code != "recovery_runtime_observed" || value.Endpoint != e.scope.EndpointIdentity {
					t.Fatal("recovery scope masked normal readiness", reply.Code, value)
				}
			} else if reply.Code == 200 {
				t.Fatal("unsafe recovery observation accepted")
			}
			if r.creates+r.starts+r.stops+r.removes+r.pulls != 0 {
				t.Fatal("observation mutated runtime")
			}
		})
	}
}
