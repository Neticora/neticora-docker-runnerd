//go:build linux

package workerboundary

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

const RecordVersion = "runnerd09-worker-domain-v1"

type Binding struct {
	InstallationID string `json:"installationId"`
	TenantID       string `json:"tenantId"`
	HostID         string `json:"hostId"`
	SessionEpoch   string `json:"sessionEpoch"`
	Endpoint       string `json:"endpointIdentity"`
	ExecutionID    string `json:"executionId"`
	Generation     string `json:"generation"`
	SpecHash       string `json:"specHash"`
	Profile        string `json:"profile"`
	Name           string `json:"name"`
}
type Record struct {
	Version             string    `json:"version"`
	Binding             Binding   `json:"binding"`
	CreationOperationID string    `json:"creationOperationId"`
	RemovalOperationID  string    `json:"removalOperationId,omitempty"`
	Owner               string    `json:"owner"`
	HelperSHA256        string    `json:"helperSha256"`
	PolicySHA256        string    `json:"policySha256"`
	Phase               string    `json:"phase"`
	Quarantined         bool      `json:"quarantined"`
	VerifiedAt          string    `json:"verifiedAt,omitempty"`
	Identity            *Identity `json:"identity,omitempty"`
}

// Registry is protected broker storage, not an IPC authority. The caller must
// hold its original lifecycle lock, verify the original platform commitment and
// pin the enforcing policy/commands before making any worker request.
type Registry struct{ Directory string }

func digest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func (b Binding) valid() bool {
	generation, e := strconv.ParseUint(b.Generation, 10, 64)
	epoch, epochError := strconv.ParseUint(b.SessionEpoch, 10, 64)
	return e == nil && generation > 0 && strconv.FormatUint(generation, 10) == b.Generation &&
		epochError == nil && epoch > 0 && strconv.FormatUint(epoch, 10) == b.SessionEpoch &&
		b.InstallationID != "" && b.TenantID != "" && b.HostID != "" && b.Endpoint != "" && b.ExecutionID != "" && digest(b.SpecHash) &&
		strings.HasPrefix(b.Name, "nrd-") && digest(strings.TrimPrefix(b.Name, "nrd-")) && b.Profile != ""
}
func canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return protocol.CanonicalizeJSON(raw)
}
func (r Record) valid() bool {
	if r.Version != RecordVersion || !r.Binding.valid() || !digest(r.CreationOperationID) || !digest(r.Owner) || !digest(r.HelperSHA256) || !digest(r.PolicySHA256) {
		return false
	}
	switch r.Phase {
	case "INTENT":
		return r.Identity == nil && r.VerifiedAt == "" && r.RemovalOperationID == ""
	case "READY":
		if r.RemovalOperationID != "" {
			return false
		}
	case "RETIRING", "RETIRED":
		if !digest(r.RemovalOperationID) {
			return false
		}
	default:
		return false
	}
	if r.Identity == nil || r.Identity.PID < 2 || r.Identity.PIDNamespaceDevice == 0 || r.Identity.PIDNamespaceInode == 0 || r.Identity.MountNamespaceDevice == 0 || r.Identity.MountNamespaceInode == 0 || r.Identity.Boot == "" || r.Identity.Profile == "" || !filepath.IsAbs(r.Identity.Socket) {
		return false
	}
	start, e := strconv.ParseUint(r.Identity.Start, 10, 64)
	if e != nil || start == 0 {
		return false
	}
	_, e = time.Parse(time.RFC3339Nano, r.VerifiedAt)
	return e == nil && !(r.Phase == "RETIRED" && r.Quarantined)
}
func (g Registry) read(b Binding) (Record, error) {
	var r Record
	if !b.valid() {
		return r, ErrBoundary
	}
	raw, e := hostfs.ReadPrivate(filepath.Join(g.Directory, b.Name+".domain.json"), 32768)
	if e != nil {
		return r, e
	}
	checked, e := protocol.CanonicalizeJSON(raw)
	if e != nil {
		return r, e
	}
	var envelope struct {
		Record Record `json:"record"`
		Hash   string `json:"hash"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(checked)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		return r, ErrBoundary
	}
	body, e := canonical(envelope.Record)
	if e != nil {
		return r, e
	}
	sum := sha256.Sum256(body)
	r = envelope.Record
	if envelope.Hash != hex.EncodeToString(sum[:]) || r.Binding != b || !r.valid() {
		return r, ErrBoundary
	}
	if r.Identity != nil {
		r.Identity.verified = true
	} // Only this protected original record.
	return r, nil
}
func (g Registry) write(r Record) error {
	if !r.valid() || (r.Identity != nil && !r.Identity.verified) {
		return ErrBoundary
	}
	root, e := hostfs.OpenState(g.Directory)
	if e != nil {
		return e
	}
	defer root.Close()
	body, e := canonical(r)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(body)
	raw, e := canonical(struct {
		Record Record `json:"record"`
		Hash   string `json:"hash"`
	}{r, hex.EncodeToString(sum[:])})
	if e != nil {
		return e
	}
	name := r.Binding.Name + ".domain.json"
	pending := name + "." + rand.Text()
	f, e := root.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = root.Rename(pending, name); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func pinnedExecutable(path, want string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !digest(want) || hostfs.CheckAncestors(filepath.Dir(path)) != nil {
		return ErrBoundary
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return e
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0100 == 0 || before.Size() > 64<<20 {
		return ErrBoundary
	}
	hash := sha256.New()
	if _, e = io.Copy(hash, io.LimitReader(f, 64<<20+1)); e != nil {
		return e
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hex.EncodeToString(hash.Sum(nil)) != want {
		return ErrBoundary
	}
	return nil
}

// Create durably records the original consumed creation operation before any
// namespace effect. Ambiguous INTENT never adopts a surviving socket or launches
// a replacement namespace. Historical and incomplete records remain retained.
func (g Registry) Create(ctx context.Context, b Binding, operation, helper, helperHash, policyHash, socket, profile string, cgroupFD int) (Record, error) {
	var r Record
	if !b.valid() || !digest(operation) || !digest(policyHash) || pinnedExecutable(helper, helperHash) != nil {
		return r, ErrBoundary
	}
	root, e := hostfs.OpenState(g.Directory)
	if e != nil {
		return r, e
	}
	defer root.Close()
	_, e = root.Lstat(b.Name + ".domain.json")
	if e == nil {
		r, e = g.read(b)
		if e != nil || r.CreationOperationID != operation || r.HelperSHA256 != helperHash || r.PolicySHA256 != policyHash || r.Phase != "READY" || r.Quarantined || r.Identity.Socket != socket || r.Identity.Profile != profile {
			return r, ErrBoundary
		}
		return r, r.Identity.Check()
	}
	if !errors.Is(e, os.ErrNotExist) {
		return r, e
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return r, e
	}
	r = Record{Version: RecordVersion, Binding: b, CreationOperationID: operation, Owner: hex.EncodeToString(nonce), HelperSHA256: helperHash, PolicySHA256: policyHash, Phase: "INTENT"}
	if e = g.write(r); e != nil {
		return r, e
	}
	id, e := Start(ctx, helper, socket, profile, cgroupFD)
	if e != nil {
		r.Quarantined = true
		return r, errors.Join(e, g.write(r))
	}
	r.Identity = &id
	r.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.Phase = "READY"
	return r, g.write(r)
}

func (g Registry) Load(b Binding) (Record, error) { return g.read(b) }

// Quarantine preserves the exact original phase and ownership. It cannot mint
// new execution authority or turn a failed guardian into disposal evidence.
func (g Registry) Quarantine(b Binding) (Record, error) {
	r, err := g.read(b)
	if err != nil || r.Phase == "RETIRED" {
		return r, ErrBoundary
	}
	r.Quarantined = true
	return r, g.write(r)
}

// BeginRetirement is the durable ordering point before signaling the original
// namespace. Keeping it explicit also permits recovery to observe an interrupted
// kernel effect without replaying it or changing its authority.
func (g Registry) BeginRetirement(b Binding, operation string) (Record, error) {
	r, err := g.read(b)
	if err != nil || !digest(operation) || r.Phase == "INTENT" {
		return r, ErrBoundary
	}
	if r.RemovalOperationID != "" && r.RemovalOperationID != operation {
		return r, ErrBoundary
	}
	if r.Phase == "READY" {
		r.Phase = "RETIRING"
		r.RemovalOperationID = operation
		r.Quarantined = false
		return r, g.write(r)
	}
	return r, nil
}

// Retire requires the exact original removal operation. A crash after init exit
// resumes the same intent through read-only kernel lifetime verification; it
// never signals a reused PID, repairs an owner or creates replacement authority.
func (g Registry) Retire(ctx context.Context, b Binding, operation string) (r Record, err error) {
	r, err = g.BeginRetirement(b, operation)
	if err != nil {
		return r, ErrBoundary
	}
	if r.RemovalOperationID != "" && r.RemovalOperationID != operation {
		return r, ErrBoundary
	}
	if r.Phase == "RETIRED" {
		return r, r.Identity.CheckRetired()
	}
	defer func() {
		if err != nil {
			current, e := g.read(b)
			if e == nil && current.Phase != "RETIRED" {
				current.Quarantined = true
				err = errors.Join(err, g.write(current))
			}
		}
	}()
	if r.Identity.CheckRetired() != nil {
		if err = r.Identity.Retire(ctx); err != nil {
			return r, err
		}
	}
	if err = r.Identity.CheckRetired(); err != nil {
		return r, err
	}
	r.Phase = "RETIRED"
	r.Quarantined = false
	err = g.write(r)
	return r, err
}
func (g Registry) CheckRetired(b Binding, operation string) (Record, error) {
	r, e := g.read(b)
	if e != nil || r.Phase != "RETIRED" || r.Quarantined || r.RemovalOperationID != operation || !digest(operation) || r.Identity == nil {
		return r, ErrBoundary
	}
	return r, r.Identity.CheckRetired()
}

// SameOriginal compares the immutable birth and authority, excluding monotonic
// retirement phase/quarantine. It is useful to retain independent recovery evidence.
func (a Record) SameOriginal(b Record) bool {
	return a.Binding == b.Binding && a.Owner == b.Owner && a.CreationOperationID == b.CreationOperationID && a.HelperSHA256 == b.HelperSHA256 && a.PolicySHA256 == b.PolicySHA256 && a.VerifiedAt == b.VerifiedAt && reflect.DeepEqual(a.Identity, b.Identity)
}
