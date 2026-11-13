package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// InstallationBinding is an authenticated onboarding view, not execution authority.
// It is deliberately separate from the versioned execution wire protocol.
type InstallationBinding struct {
	Identity             protocol.HostIdentity `json:"identity"`
	InstallationID       string                `json:"installationId"`
	TenantID             string                `json:"tenantId"`
	RunnerDeploymentID   string                `json:"runnerDeploymentId"`
	EnrollmentRequestID  string                `json:"enrollmentRequestId"`
	PublicKeyFingerprint string                `json:"publicKeyFingerprint"`
}

func (c *Client) Installation(ctx context.Context, token string) (InstallationBinding, error) {
	var result InstallationBinding
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return result, errors.New("invalid host credential")
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/me/installation"
	u.RawPath = ""
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, errors.New("invalid installation request")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	response, err := c.http.Do(r)
	if err != nil {
		return result, errors.New("installation request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return result, errors.New("installation request rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return result, errors.New("invalid installation response")
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return result, errors.New("invalid installation response")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || result.InstallationID == "" || result.TenantID == "" || result.RunnerDeploymentID == "" || result.EnrollmentRequestID == "" || len(result.PublicKeyFingerprint) != 64 {
		return InstallationBinding{}, errors.New("incomplete installation response")
	}
	id, _ := json.Marshal(result.Identity)
	if protocol.ValidateInboundJSON("HostIdentity", id) != nil {
		return InstallationBinding{}, errors.New("invalid installation identity")
	}
	return result, nil
}
