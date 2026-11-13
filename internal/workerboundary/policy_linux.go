//go:build linux

package workerboundary

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// PreflightPolicyVersion is deliberately not a Kata runtime admission policy.
// It permits native confinement checks, not VM devices, mounts or containerd
// authority. Extending it requires another reviewed, explicitly versioned policy.
const PreflightPolicyVersion = "runnerd09-worker-preflight-apparmor-v1"

type PinnedExecutable struct {
	Path   string
	SHA256 string
}

type PreflightPolicy struct {
	Domain       string
	WorkRoot     string
	MetadataRoot string
	StateRoot    string
	Executables  []PinnedExecutable
}

func literalPath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || len(p) > 512 {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-", c)) {
			return false
		}
	}
	return true
}

func pathWithin(root, path string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func (p PreflightPolicy) Name() string {
	return "neticora-worker-" + strings.TrimPrefix(p.Domain, "nrd-")
}

// Render validates private original roots and pinned executables. All policy
// paths are literals selected by the trusted caller, never controller IPC fields.
// Root directories themselves are read-only: workers cannot chmod/chown the
// ownership guard and expose its children to an outside unprivileged process.
func (p PreflightPolicy) Render() ([]byte, error) {
	if !strings.HasPrefix(p.Domain, "nrd-") || !digest(strings.TrimPrefix(p.Domain, "nrd-")) || len(p.Executables) == 0 || len(p.Executables) > 16 {
		return nil, ErrBoundary
	}
	roots := []string{p.WorkRoot, p.MetadataRoot, p.StateRoot}
	for i, path := range roots {
		if !literalPath(path) {
			return nil, ErrBoundary
		}
		for _, other := range roots[:i] {
			if pathWithin(path, other) || pathWithin(other, path) {
				return nil, ErrBoundary
			}
		}
		root, err := hostfs.OpenState(path)
		if err != nil {
			return nil, err
		}
		root.Close()
	}
	scratch := filepath.Join(p.WorkRoot, "scratch")
	root, err := hostfs.OpenState(scratch)
	if err != nil {
		return nil, err
	}
	root.Close()
	paths := make([]string, 0, len(p.Executables))
	for _, executable := range p.Executables {
		if !literalPath(executable.Path) || pathWithin(scratch, executable.Path) || pathWithin(p.MetadataRoot, executable.Path) || pathWithin(p.StateRoot, executable.Path) || pinnedExecutable(executable.Path, executable.SHA256) != nil || slices.Contains(paths, executable.Path) {
			return nil, ErrBoundary
		}
		paths = append(paths, executable.Path)
	}
	slices.Sort(paths)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\nprofile %s flags=(attach_disconnected,mediate_deleted) {\n", PreflightPolicyVersion, p.Name())
	// The kernel represents an opened namespace inode as a disconnected root
	// path. Permit root-directory read, never a recursive host filesystem read;
	// descriptor classification still refuses namespace transfer.
	b.WriteString("  / r,\n  /etc/ld.so.cache r,\n  /etc/localtime r,\n  /{,usr/}lib{,32,64}/** mr,\n  /dev/null rw,\n  /dev/{u,}random r,\n  /proc/** r,\n")
	fmt.Fprintf(&b, "  %s/ r,\n  %s/ r,\n  %s/?* rwkl,\n  %s/?*/** rwkl,\n", p.WorkRoot, scratch, scratch, scratch)
	fmt.Fprintf(&b, "  %s/ r,\n  %s/?* rwkl,\n  %s/?*/** rwkl,\n", p.MetadataRoot, p.MetadataRoot, p.MetadataRoot)
	fmt.Fprintf(&b, "  %s/worker.log rw,\n  %s/ancestor-pidns r,\n  %s/outside.sock rw,\n", p.WorkRoot, p.WorkRoot, p.WorkRoot)
	fmt.Fprintf(&b, "  deny %s/{,**} rwklm,\n", p.StateRoot)
	for _, path := range paths {
		fmt.Fprintf(&b, "  %s rmix,\n  deny %s wkl,\n", path, path)
	}
	b.WriteString("  unix (create, getattr, setattr, getopt, setopt, shutdown) type=seqpacket,\n  unix (create, getattr, setattr, getopt, setopt, shutdown) type=stream,\n")
	// Pathname sockets use the exact file rule above. Fine-grained unix addr
	// rules cover abstract/anonymous sockets only; never grant abstract connect
	// to unconfined peers merely to support a pathname diagnostic socket.
	fmt.Fprintf(&b, "  unix (send, receive) type=seqpacket addr=none peer=(addr=none label=%s),\n", p.Name())
	b.WriteString("  unix (receive) type=seqpacket addr=none peer=(addr=none label=unconfined),\n")
	fmt.Fprintf(&b, "  ptrace (read) peer=%s,\n  ptrace (readby, tracedby) peer=unconfined,\n", p.Name())
	fmt.Fprintf(&b, "  signal (send, receive) peer=%s,\n  signal (receive) peer=unconfined,\n}\n", p.Name())
	return []byte(b.String()), nil
}
