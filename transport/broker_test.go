package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
)

func TestBrokerGrantFixedAuthenticatedTransport(t *testing.T) {
	raw, err := os.ReadFile("../internal/broker/testdata/platform-execution-grant.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Request broker.ExecutionGrantRequest `json:"request"`
		Signed  broker.SignedExecutionGrant  `json:"signed"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/me/broker/grant" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("wrong issuer path/credential")
		}
		var request broker.ExecutionGrantRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request != vector.Request {
			t.Error("request changed")
		}
		_ = json.NewEncoder(w).Encode(vector.Signed)
	}))
	defer server.Close()
	client := trustedClient(t, server)
	got, err := client.BrokerGrant(context.Background(), "secret", vector.Request)
	if err != nil || got.Signature != vector.Signed.Signature || got.Grant.OperationID != vector.Request.OperationID {
		t.Fatal("grant relay failed", err)
	}
	vector.Request.Operation = "ExecuteShellCommand"
	if _, err = client.BrokerGrant(context.Background(), "secret", vector.Request); err == nil || calls != 1 {
		t.Fatal("invalid operation reached issuer")
	}
}

func TestBrokerCommitFixedAuthenticatedTransport(t *testing.T) {
	raw, err := os.ReadFile("../internal/broker/testdata/platform-commit.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Request     broker.ExecutionGrantRequest `json:"request"`
		Grant       broker.SignedExecutionGrant  `json:"grant"`
		Certificate broker.SignedCommit          `json:"certificate"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/me/broker/commit" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("wrong commit authority path")
		}
		var request broker.CommitRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Request != v.Request || request.Grant.Signature != v.Grant.Signature {
			t.Error("changed commit request")
		}
		_ = json.NewEncoder(w).Encode(v.Certificate)
	}))
	defer server.Close()
	client := trustedClient(t, server)
	got, err := client.BrokerCommit(context.Background(), "secret", v.Request, v.Grant)
	if err != nil || got.Signature != v.Certificate.Signature {
		t.Fatal("commit relay failed", err)
	}
}
