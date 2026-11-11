//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLostEnrollmentResponseRetainsIdenticalRequest(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	state := filepath.Join(dir, "enrollment")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("token", 16)), 0600); err != nil {
		t.Fatal(err)
	}
	var first []byte
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			data, _ := io.ReadAll(r.Body)
			calls++
			if calls == 1 {
				first = data
				http.Error(w, "lost reply", 503)
				return
			}
			if !bytes.Equal(data, first) {
				t.Error("retry changed durable enrollment request")
			}
			io.WriteString(w, `{"identity":{"hostId":"host-1","keyId":"key-1","keyVersion":"1","sessionEpoch":"1"},"protocol":{"version":"1.0.0","minimumRecoveryVersion":"1.0.0","minimumAdmissionVersion":"1.0.0"}}`)
		case "/token":
			io.WriteString(w, `{"accessToken":"private-access","expiresAt":"2099-01-01T00:00:00.000Z"}`)
		case "/me/config":
			if r.Header.Get("Authorization") != "Bearer private-access" {
				t.Error("missing signed authentication")
			}
			io.WriteString(w, `{"admissionEnabled":false,"protocol":{"version":"1.0.0","minimumRecoveryVersion":"1.0.0","minimumAdmissionVersion":"1.0.0"},"policy":{"generation":"1","allowedTrustClasses":[],"allowedProfiles":[],"limits":{"cpuMillis":"0","memoryBytes":"0","storageBytes":"0","slots":"0"}}}`)
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	args := []string{"--endpoint", server.URL, "--tenant-id", "tenant-1", "--state-dir", state, "--token-file", token, "--ca-file", ca}
	if err := runArgs(args); err == nil {
		t.Fatal("uncertain enrollment accepted")
	} else {
		t.Log(err)
	}
	persisted, err := os.ReadFile(filepath.Join(state, "attempt.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The source token may be removed after the durable attempt exists.
	os.Remove(token)
	if err := runArgs(args); err != nil {
		t.Fatal(err)
	}
	if err := runArgs(args); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("confirmed receipt unnecessarily enrolled again")
	}
	after, _ := os.ReadFile(filepath.Join(state, "attempt.json"))
	if !bytes.Equal(after, persisted) {
		t.Fatal("persisted key changed")
	}
	for _, name := range []string{"attempt.json", "enrollment.json", "instance.lock"} {
		info, err := os.Stat(filepath.Join(state, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe private file", name)
		}
	}
	var a attempt
	json.Unmarshal(persisted, &a)
	a.BootID = "replacement-boot"
	changed, _ := json.Marshal(a)
	os.WriteFile(filepath.Join(state, "attempt.json"), changed, 0600)
	if err := runArgs(args); err == nil {
		t.Fatal("new boot silently accepted")
	}
}

func TestEnrollmentRejectsUnsafeStateAndToken(t *testing.T) {
	for _, kind := range []string{"directory", "token", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			state := filepath.Join(dir, "state")
			os.Mkdir(state, 0700)
			token := filepath.Join(dir, "token")
			os.WriteFile(token, []byte(strings.Repeat("secret", 10)), 0600)
			switch kind {
			case "directory":
				os.Chmod(state, 0755)
			case "token":
				os.Chmod(token, 0644)
			case "symlink":
				os.Symlink(token, filepath.Join(state, "attempt.json"))
			}
			if err := runArgs([]string{"--endpoint", "https://example.invalid", "--tenant-id", "tenant", "--state-dir", state, "--token-file", token}); err == nil {
				t.Fatal("unsafe local state accepted")
			}
		})
	}
}
