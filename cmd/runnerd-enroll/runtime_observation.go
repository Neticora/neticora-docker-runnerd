package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"time"
)

type runtimeObservation struct {
	Version          string `json:"version"`
	InstallationID   string `json:"installationId"`
	TenantID         string `json:"tenantId"`
	HostID           string `json:"hostId"`
	BootID           string `json:"bootId"`
	EndpointIdentity string `json:"endpointIdentity"`
	ObservedAt       string `json:"observedAt"`
}

func decodeRuntimeObservation(raw []byte, installation, tenant, host, boot string, now time.Time) (string, error) {
	var v runtimeObservation
	if len(raw) > 16384 {
		return "", errors.New("oversized runtime observation")
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return "", errors.New("invalid runtime observation")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Version != "runnerd-runtime-observation-v1" || v.InstallationID != installation || v.TenantID != tenant || v.HostID != host || v.BootID != boot || installation == "" || tenant == "" || host == "" || boot == "" || len(v.EndpointIdentity) != 71 || v.EndpointIdentity[:7] != "docker-" {
		return "", errors.New("runtime observation scope mismatch")
	}
	if _, err := hex.DecodeString(v.EndpointIdentity[7:]); err != nil {
		return "", errors.New("invalid observed runtime peer")
	}
	observed, err := time.Parse(time.RFC3339Nano, v.ObservedAt)
	if err != nil || observed.After(now) || now.Sub(observed) > 5*time.Minute {
		return "", errors.New("stale runtime observation")
	}
	return v.EndpointIdentity, nil
}
