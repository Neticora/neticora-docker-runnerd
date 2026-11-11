//go:build linux

// Package provision renders reviewable configuration; it never installs files,
// starts services, copies credentials or grants host/platform admission.
package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

var ErrProvision = errors.New("configuration provisioning rejected")

type Bundle struct {
	Version  string                   `json:"version"`
	Daemon   config.Config            `json:"daemon"`
	Observer katalinux.ObserverConfig `json:"observer"`
}

// Parse checks one coherent layout. Signature/trust acceptance is deliberately
// separate: this function never certifies unavailable qualification artifacts.
func Parse(raw []byte) (Bundle, error) {
	var b Bundle
	if len(raw) > 131072 {
		return b, ErrProvision
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return b, ErrProvision
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || b.Version != "runnerd09-config-bundle-v1" {
		return b, ErrProvision
	}
	dr, _ := json.Marshal(b.Daemon)
	c, err := config.Parse(dr)
	if err != nil || c.Execution == nil || !c.Execution.Enabled || c.Execution.Kata == nil {
		return b, ErrProvision
	}
	x, o := c.Execution, b.Observer
	if o.ServiceUID < 1 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(o.NetworkID) || o.HostID == "" || o.InstallationID == "" || o.PidsLimit < 16 || o.PidsLimit > 4096 {
		return b, ErrProvision
	}
	if o.RuntimeEndpoint != c.RuntimeEndpoint || o.JournalDirectory != c.StateDir || o.Socket != x.Kata.ObserverSocket || o.EvidenceDirectory != x.Kata.EvidenceDirectory || o.BootstrapRoot != x.BootstrapRoot || o.NetworkID != x.NetworkID || o.PidsLimit != x.PidsLimit {
		return b, ErrProvision
	}
	for _, path := range []string{o.Socket, o.ProfileDirectory, o.PublicKeyFile, o.EvidenceDirectory, o.JournalDirectory, o.BootstrapRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return b, ErrProvision
		}
	}
	// Root observer material and service-owned copies need separate paths.
	if filepath.Join(o.ProfileDirectory, filepath.Base(x.Kata.ProfileFile)) == x.Kata.ProfileFile || o.PublicKeyFile == x.Kata.PublicKeyFile {
		return b, ErrProvision
	}
	files := map[string]bool{}
	for _, path := range []string{c.CredentialFile, x.PolicyFile, x.CapabilitiesFile, x.CustomCAFile, x.Kata.ProfileFile, x.Kata.PublicKeyFile, o.PublicKeyFile, o.Socket} {
		if path == "" {
			continue
		}
		if files[path] {
			return b, ErrProvision
		}
		files[path] = true
	}
	// A root-owned profile directory cannot contain service-owned material.
	for _, path := range []string{c.CredentialFile, x.PolicyFile, x.CapabilitiesFile, x.CustomCAFile, x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.KeysDirectory, x.TrustRoots, x.ImageBundles} {
		if path != "" && (path == o.ProfileDirectory || strings.HasPrefix(path, o.ProfileDirectory+"/")) {
			return b, ErrProvision
		}
	}
	private := []string{c.StateDir, c.CredentialFile, x.KeysDirectory, x.PolicyFile, x.CapabilitiesFile, x.TrustRoots, x.ImageBundles, x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, o.ProfileDirectory, o.PublicKeyFile, o.Socket}
	for _, path := range private {
		for _, exposed := range []string{x.BootstrapRoot, x.BootstrapRoot + "-health"} {
			if path == exposed || strings.HasPrefix(path, exposed+"/") || strings.HasPrefix(exposed, path+"/") {
				return b, ErrProvision
			}
		}
	}
	return b, nil
}

type Artifact struct {
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	OwnerUID    int    `json:"ownerUid"`
	Mode        string `json:"mode"`
	Destination string `json:"destination"`
}
type Receipt struct {
	Version           string     `json:"version"`
	Artifacts         []Artifact `json:"artifacts"`
	ArtifactsVerified bool       `json:"qualificationArtifactsVerified"`
	AdmissionChanged  bool       `json:"admissionChanged"`
	RequiredFiles     []string   `json:"requiredFiles"`
}

// Write creates a fresh owner-private bundle and durable receipt. Existing or
// dangling-link outputs are never reused, and partial output remains reviewable.
func Write(output string, b Bundle) (Receipt, error) {
	var receipt Receipt
	raw, _ := json.Marshal(b)
	checked, err := Parse(raw)
	if err != nil || !reflect.DeepEqual(checked, b) {
		return receipt, ErrProvision
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || hostfs.CheckAncestors(filepath.Dir(output)) != nil {
		return receipt, ErrProvision
	}
	if err = os.Mkdir(output, 0700); err != nil {
		return receipt, ErrProvision
	}
	root, err := hostfs.OpenState(output)
	if err != nil {
		return receipt, err
	}
	defer root.Close()
	receipt.Version = "runnerd09-provision-receipt-v1"
	for _, item := range []struct {
		name, destination string
		uid               int
		value             any
	}{{"daemon.json", "/etc/neticora-runnerd/config.json", b.Observer.ServiceUID, b.Daemon}, {"observer.json", "/etc/neticora-runnerd-kata-observer/config.json", 0, b.Observer}} {
		data, _ := json.MarshalIndent(item.value, "", "  ")
		data = append(data, '\n')
		f, e := root.OpenFile(item.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return receipt, e
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return receipt, e
		}
		sum := sha256.Sum256(data)
		receipt.Artifacts = append(receipt.Artifacts, Artifact{item.name, hex.EncodeToString(sum[:]), item.uid, "0600", item.destination})
	}
	x := b.Daemon.Execution
	receipt.RequiredFiles = []string{b.Daemon.CredentialFile, x.PolicyFile, x.CapabilitiesFile, x.Kata.ProfileFile, x.Kata.PublicKeyFile, b.Observer.PublicKeyFile, b.Observer.ProfileDirectory, x.TrustRoots, x.ImageBundles}
	if x.CustomCAFile != "" {
		receipt.RequiredFiles = append(receipt.RequiredFiles, x.CustomCAFile)
	}
	data, _ := json.MarshalIndent(receipt, "", "  ")
	data = append(data, '\n')
	f, err := root.OpenFile("receipt.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return receipt, err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return receipt, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return receipt, err
	}
	err = dir.Sync()
	err = errors.Join(err, dir.Close())
	if err != nil {
		return receipt, err
	}
	parent, err := os.Open(filepath.Dir(output))
	if err != nil {
		return receipt, err
	}
	err = parent.Sync()
	err = errors.Join(err, parent.Close())
	return receipt, err
}
