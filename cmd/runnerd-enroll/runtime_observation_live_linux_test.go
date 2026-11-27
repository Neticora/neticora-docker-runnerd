//go:build linux

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionedRootObservationWithoutDockerAuthority(t *testing.T) {
	path := os.Getenv("RUNNERD_F3_RUNTIME_OBSERVATION")
	if path == "" {
		t.Skip("explicit root-provisioned observation required")
	}
	if os.Geteuid() != 10003 {
		t.Fatal("dedicated unprivileged F3 service UID required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v runtimeObservation
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("invalid public observation")
	}
	peer, err := readRuntimeObservation(path, v.InstallationID, v.TenantID, v.HostID, v.BootID)
	if err != nil || peer != v.EndpointIdentity {
		t.Fatal("trusted root observation unavailable", err)
	}
	parent, err := os.MkdirTemp("/var/lib/neticora-runnerd-f3/client", "observation-negative-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	fake := filepath.Join(parent, "fake.json")
	if os.WriteFile(fake, raw, 0600) != nil {
		t.Fatal("fake fixture")
	}
	if _, err = readRuntimeObservation(fake, v.InstallationID, v.TenantID, v.HostID, v.BootID); err == nil {
		t.Fatal("service-writable observation accepted")
	}
	link := filepath.Join(parent, "link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink fixture")
	}
	if _, err = readRuntimeObservation(link, v.InstallationID, v.TenantID, v.HostID, v.BootID); err == nil {
		t.Fatal("observation alias accepted")
	}
	socket := "/run/runnerd09-docker.sock"
	if _, err = os.Stat(socket); err != nil {
		t.Fatal("live positive-control socket absent", err)
	}
	conn, err := net.Dial("unix", socket)
	if err == nil {
		conn.Close()
		t.Fatal("service obtained independent Docker access")
	}
	t.Log("original root observation accepted; service-owned replacement and alias rejected; live Docker access denied")
}
