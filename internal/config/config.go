package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

const MaxConfigBytes = 65536

type Config struct {
	ControlPlaneURL       string     `json:"controlPlaneUrl"`
	StateDir              string     `json:"stateDir"`
	RuntimeEndpoint       string     `json:"runtimeEndpoint"`
	CredentialFile        string     `json:"credentialFile"`
	RequestTimeoutSeconds int        `json:"requestTimeoutSeconds"`
	Execution             *Execution `json:"execution,omitempty"`
}

// Execution is an explicit operator opt-in. Old foundation configurations remain
// drained and never open Docker or contact the platform.
type Execution struct {
	Kata                *Kata  `json:"kata,omitempty"`
	Repository          string `json:"repository"`
	CustomCAFile        string `json:"customCaFile,omitempty"`
	Enabled             bool   `json:"enabled"`
	PolicyFile          string `json:"policyFile"`
	CapabilitiesFile    string `json:"capabilitiesFile"`
	ImageRepository     string `json:"imageRepository"`
	NetworkID           string `json:"networkId"`
	BootstrapRoot       string `json:"bootstrapRoot"`
	KeysDirectory       string `json:"keysDirectory"`
	TrustRoots          string `json:"trustRoots"`
	ImageBundles        string `json:"imageBundles"`
	TrustProvisionedAt  string `json:"trustProvisionedAt"`
	Organization        string `json:"organization"`
	Pool                string `json:"pool"`
	PidsLimit           int64  `json:"pidsLimit"`
	MinRuntimeFreeBytes uint64 `json:"minRuntimeFreeBytes,omitempty"`
}

// Kata is a dedicated-host opt-in; no default runtime or unqualified tuple is
// inferred. The descriptor is independently signed, private and immutable.
type Kata struct {
	ObserverSocket    string `json:"observerSocket"`
	ProfileFile       string `json:"profileFile"`
	PublicKeyFile     string `json:"publicKeyFile"`
	EvidenceDirectory string `json:"evidenceDirectory"`
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
	if x := c.Execution; x != nil && x.Enabled {
		if x.Kata != nil {
			for _, path := range []string{x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, x.Kata.ObserverSocket} {
				if !filepath.IsAbs(path) || filepath.Clean(path) != path {
					return Config{}, errors.New("Kata paths must be protected absolute paths")
				}
				for _, exposed := range []string{c.StateDir, x.BootstrapRoot} {
					rel, e := filepath.Rel(exposed, path)
					if e != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
						return Config{}, errors.New("Kata trust/evidence must remain outside journal and guest handoff")
					}
				}
			}
		}
		if x.MinRuntimeFreeBytes != 0 && x.MinRuntimeFreeBytes < 64<<20 {
			return Config{}, errors.New("runtime storage headroom must be at least 64 MiB")
		}
		for _, private := range []string{c.CredentialFile, x.KeysDirectory, x.PolicyFile, x.CapabilitiesFile, x.TrustRoots, x.ImageBundles, x.CustomCAFile} {
			if private == "" {
				continue
			}
			rel, e := filepath.Rel(x.BootstrapRoot, private)
			if e != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return Config{}, errors.New("host credentials, policy and trust must remain outside bootstrap mounts")
			}
		}
		if x.Kata != nil {
			healthRoot := x.BootstrapRoot + "-health"
			for _, private := range []string{c.StateDir, c.CredentialFile, x.BootstrapRoot, x.KeysDirectory, x.PolicyFile, x.CapabilitiesFile, x.TrustRoots, x.ImageBundles, x.CustomCAFile, x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, x.Kata.ObserverSocket} {
				if private != "" && (private == healthRoot || strings.HasPrefix(private, healthRoot+string(filepath.Separator)) || strings.HasPrefix(healthRoot, private+string(filepath.Separator))) {
					return Config{}, errors.New("private state and trust must remain separate from guest health output")
				}
			}
		}
		repo := strings.Split(x.Repository, "/")
		if len(repo) != 2 || repo[0] != x.Organization || repo[1] == "" || strings.ContainsAny(x.Repository, "?#\\\r\n ") {
			return Config{}, errors.New("execution repository must match the configured GitHub organization")
		}
		if x.CustomCAFile != "" && (!filepath.IsAbs(x.CustomCAFile) || filepath.Clean(x.CustomCAFile) != x.CustomCAFile) {
			return Config{}, errors.New("custom CA path must be explicit and absolute")
		}
		for _, path := range []string{x.PolicyFile, x.CapabilitiesFile, x.BootstrapRoot, x.KeysDirectory, x.TrustRoots, x.ImageBundles} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return Config{}, errors.New("execution paths must be explicit absolute clean paths")
			}
			rel, e := filepath.Rel(c.StateDir, path)
			if e != nil || rel == "." || (rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator)))) {
				return Config{}, errors.New("execution trust and secrets must remain outside journal")
			}
		}
		if x.Organization == "" || x.Pool == "" || x.ImageRepository == "" || x.NetworkID == "" || x.PidsLimit < 16 || x.PidsLimit > 4096 {
			return Config{}, errors.New("incomplete execution configuration")
		}
		if _, e := time.Parse(time.RFC3339Nano, x.TrustProvisionedAt); e != nil {
			return Config{}, errors.New("invalid provisioned trust timestamp")
		}
	}
	return c, nil
}
func (c Config) Timeout() time.Duration { return time.Duration(c.RequestTimeoutSeconds) * time.Second }
