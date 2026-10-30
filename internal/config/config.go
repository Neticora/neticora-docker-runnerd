package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

const MaxConfigBytes = 65536

type Config struct {
	ControlPlaneURL       string `json:"controlPlaneUrl"`
	StateDir              string `json:"stateDir"`
	RuntimeEndpoint       string `json:"runtimeEndpoint"`
	CredentialFile        string `json:"credentialFile"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds"`
}

func Parse(data []byte) (Config, error) {
	var c Config
	if len(data) > MaxConfigBytes {
		return c, errors.New("configuration exceeds size limit")
	}
	if _, err := protocol.CanonicalizeJSON(data); err != nil {
		return c, errors.New("invalid configuration JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Config{}, errors.New("invalid configuration fields")
	}
	u, err := url.Parse(c.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, errors.New("control plane must use HTTPS without embedded credentials")
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir {
		return Config{}, errors.New("state directory must be an absolute clean path")
	}
	endpoint, err := url.Parse(c.RuntimeEndpoint)
	if err != nil || endpoint.Scheme != "unix" || endpoint.Host != "" || !filepath.IsAbs(endpoint.Path) || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return Config{}, errors.New("runtime endpoint must name an explicit local Unix socket")
	}
	if !filepath.IsAbs(c.CredentialFile) || filepath.Clean(c.CredentialFile) != c.CredentialFile || filepath.Dir(c.CredentialFile) == c.StateDir {
		return Config{}, errors.New("credentials must have a separate absolute path outside state")
	}
	rel, err := filepath.Rel(c.StateDir, c.CredentialFile)
	if err != nil || rel == "." || (rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator)))) {
		return Config{}, errors.New("credentials must remain outside state directory")
	}
	if c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 60 {
		return Config{}, errors.New("request timeout must be between 1 and 60 seconds")
	}
	return c, nil
}
func (c Config) Timeout() time.Duration { return time.Duration(c.RequestTimeoutSeconds) * time.Second }
