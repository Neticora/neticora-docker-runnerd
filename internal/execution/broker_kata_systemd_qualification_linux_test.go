//go:build linux && runnerd_broker_qualification

package execution

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

// These permissions belong only to the disposable qualification service. The
// shipped unit and production runtime gate remain unchanged. Privileged storage
// operations retain the signed pool, device directory and lifecycle owner.
func phaseE2KataBrokerUnit(body string, c broker.Config, m katalinux.Manifest) (string, error) {
	if c.Runtime == nil || c.Runtime.Kata == nil {
		return body, nil
	}
	if c.Runtime.Kata.QualificationPin == "" || m.Storage.Block == nil || m.Version != katalinux.MultiBlockVersion || m.Qualified || len(m.Acceptance) != 0 {
		return "", fmt.Errorf("explicit unqualified block-backed Kata fixture required")
	}
	paths := append([]string{c.Runtime.Kata.EvidenceDirectory, m.Storage.Block.Pool.Root, m.Storage.Block.DeviceDirectory}, m.SandboxRoots...)
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsAny(p, " \t\r\n\"\\") {
			return "", fmt.Errorf("invalid Kata service path")
		}
	}
	for _, fs := range []katalinux.Filesystem{m.Storage.Block.Pool, m.Storage.Runtime} {
		if !strings.HasPrefix(fs.BackingDevice, "/dev/disk/by-id/") || filepath.Clean(fs.BackingDevice) != fs.BackingDevice || strings.ContainsAny(fs.BackingDevice, " \t\r\n\"\\") {
			return "", fmt.Errorf("pinned physical backing device required")
		}
	}
	body = strings.ReplaceAll(body, "PrivateDevices=yes", "PrivateDevices=no")
	body += "\n# Root-only Kata qualification additions; controller capabilities remain empty.\nEnvironment=RUNNERD09_LIVE_QUALIFICATION=1\nReadWritePaths=" + strings.Join(paths, " ") + "\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_MKNOD\nDevicePolicy=closed\nDeviceAllow=/dev/loop-control rw\nDeviceAllow=block-loop rwm\n"
	body += "DeviceAllow=" + m.Storage.Block.Pool.BackingDevice + " r\nDeviceAllow=" + m.Storage.Runtime.BackingDevice + " r\n"
	return body, nil
}
func phaseE2BrokerUnitFromConfig(body, config string) (string, error) {
	raw, err := hostfs.ReadPrivate(config, broker.MaxMessage)
	if err != nil {
		return "", err
	}
	var c broker.Config
	if json.Unmarshal(raw, &c) != nil {
		return "", fmt.Errorf("invalid broker service fixture")
	}
	if c.Runtime == nil || c.Runtime.Kata == nil {
		return body, nil
	}
	raw, err = hostfs.ReadPrivate(c.Runtime.Kata.ProfileFile, 131072)
	if err != nil {
		return "", err
	}
	var signed struct {
		Manifest katalinux.Manifest `json:"manifest"`
	}
	if json.Unmarshal(raw, &signed) != nil {
		return "", fmt.Errorf("invalid Kata service profile")
	}
	body, err = phaseE2KataBrokerUnit(body, c, signed.Manifest)
	if err != nil {
		return "", err
	}
	// systemd bind allowances require their parent directories before namespace
	// setup. Provision only declared sandbox parents on the existing runtime
	// volume, without changing any execution directory or ownership record.
	runtimeRoot, err := hostfs.OpenState(signed.Manifest.Storage.Runtime.Root)
	if err != nil {
		return "", err
	}
	defer runtimeRoot.Close()
	for _, path := range signed.Manifest.SandboxRoots {
		rel, e := filepath.Rel(signed.Manifest.Storage.Runtime.Root, path)
		if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("sandbox parent outside qualified runtime volume")
		}
		current := "."
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			if e = runtimeRoot.Mkdir(current, 0755); e != nil && !os.IsExist(e) {
				return "", e
			}
			info, e := runtimeRoot.Lstat(current)
			if e != nil {
				return "", e
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			// Existing Kata shared directories may be 0777, behind the validated
			// root-only 0700 runtime anchor. Never repair their original permissions.
			if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 {
				return "", fmt.Errorf("invalid sandbox parent")
			}
		}
	}
	return body, nil
}
func phaseE2ControllerPaths(p phaseDPublic) (string, error) {
	if p.KataProfileID == "" {
		return "", nil
	}
	var m katalinux.Manifest
	if json.Unmarshal(p.KataManifest, &m) != nil || m.Storage.Block == nil {
		return "", fmt.Errorf("Kata manifest absent")
	}
	paths := []string{p.KataEvidenceDirectory, p.KataJournalDirectory, m.Storage.Block.Pool.Root, m.Storage.Block.DeviceDirectory}
	var masked []string
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, " \t\r\n\"\\") {
			return "", fmt.Errorf("invalid controller mask")
		}
		masked = append(masked, "-"+path)
	}
	return "InaccessiblePaths=" + strings.Join(masked, " ") + "\n", nil
}
func TestPhaseE2UnitSeparatesKataStorageFromController(t *testing.T) {
	c := broker.Config{Runtime: &broker.RuntimeConfig{Kata: &broker.KataConfig{QualificationPin: "pinned", EvidenceDirectory: "/var/lib/kata-evidence"}}}
	m := katalinux.Manifest{Version: katalinux.MultiBlockVersion, SandboxRoots: []string{"/run/kata-containers", "/run/vc/vm"}}
	m.Storage.Block = &katalinux.BlockStorage{Pool: katalinux.Filesystem{Root: "/var/lib/kata-pool", BackingDevice: "/dev/disk/by-id/virtio-pool"}, DeviceDirectory: "/run/kata-devices"}
	m.Storage.Runtime.BackingDevice = "/dev/disk/by-id/virtio-runtime"
	body, err := phaseE2KataBrokerUnit("PrivateDevices=yes\n", c, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PrivateDevices=no", "DevicePolicy=closed", "DeviceAllow=block-loop rwm", "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_MKNOD", "/var/lib/kata-evidence"} {
		if !strings.Contains(body, required) {
			t.Fatal("missing qualified root restriction", required)
		}
	}
	p := phaseDPublic{KataProfileID: "pinned", KataEvidenceDirectory: "/var/lib/kata-evidence", KataJournalDirectory: "/var/lib/kata-journal", KataManifest: phaseDJSON(m)}
	masks, err := phaseE2ControllerPaths(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(masks, "-/var/lib/kata-pool") || !strings.Contains(masks, "-/run/kata-devices") {
		t.Fatal("controller retains Kata storage access")
	}
	m.Storage.Block.Pool.Root = "/"
	if _, err = phaseE2KataBrokerUnit("", c, m); err == nil {
		t.Fatal("unconfined filesystem writable")
	}
}
