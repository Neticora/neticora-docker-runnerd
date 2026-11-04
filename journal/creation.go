// Package journal implements the durable creation boundary used by never-started
// evidence. The executor MUST claim this boundary before any runtime create call.
// Open retains the original Runnerd05 file-fence API. OpenRecovery adds SQLite
// under the same installation owner; neither API is a runtime executor.
package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

const Version = "runnerd05-file-fence-v1"

var ErrFenced = errors.New("creation is durably fenced")
var ErrCreationClaimed = errors.New("creation boundary already crossed or uncertain")

type Authority struct{ TenantID, HostID, SessionEpoch, EndpointIdentity, KeyID string }
type record struct {
	Binding   map[string]string `json:"binding"`
	State     string            `json:"state"`
	JournalID string            `json:"journalId"`
	FencedAt  string            `json:"fencedAt,omitempty"`
}
type Store struct {
	mu   sync.Mutex
	path string
	root *os.Root
	lock *os.File
}

// Open requires a protected, pre-provisioned directory. One process holds its
// existing hostfs lock for the store lifetime. Never delete or compact markers.
func Open(path string) (*Store, error) {
	root, err := hostfs.OpenState(path)
	if err != nil {
		return nil, err
	}
	lock, err := hostfs.Lock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	return &Store{path: path, root: root, lock: lock}, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.lock.Close()
	if e := s.root.Close(); err == nil {
		err = e
	}
	return err
}
func canonical(value any) ([]byte, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	return protocol.CanonicalizeJSON(b)
}
func hash(value any) (string, error) {
	b, e := canonical(value)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func decode(name string, raw []byte) (map[string]any, error) {
	if e := protocol.Validate(name, raw); e != nil {
		return nil, e
	}
	var v map[string]any
	if e := json.Unmarshal(raw, &v); e != nil {
		return nil, e
	}
	field := "payloadHash"
	if name == "ExecutionSpec" {
		field = "specHash"
	}
	expected, ok := v[field].(string)
	if !ok {
		return nil, errors.New("missing logical digest")
	}
	delete(v, field)
	actual, e := hash(v)
	v[field] = expected
	if e != nil || expected != actual {
		return nil, errors.New("logical digest mismatch")
	}
	return v, nil
}
func binding(start map[string]any, a Authority) (map[string]string, error) {
	spec, ok := start["spec"].(map[string]any)
	if !ok || start["kind"] != "start" {
		return nil, errors.New("start required")
	}
	raw, e := json.Marshal(spec)
	if e != nil {
		return nil, e
	}
	if _, e = decode("ExecutionSpec", raw); e != nil {
		return nil, e
	}
	if a.TenantID == "" || a.HostID == "" || a.SessionEpoch == "" || a.EndpointIdentity == "" || a.KeyID == "" {
		return nil, errors.New("authority required")
	}
	b := map[string]string{"tenantId": a.TenantID, "hostId": a.HostID, "sessionEpoch": a.SessionEpoch, "endpointIdentity": a.EndpointIdentity}
	for k, from := range map[string]string{"executionId": "executionId", "generation": "generation", "specHash": "specHash", "attemptId": "attemptId"} {
		b[k], ok = spec[from].(string)
		if !ok {
			return nil, errors.New("invalid start identity")
		}
	}
	if start["generation"] != spec["generation"] {
		return nil, errors.New("start scope mismatch")
	}
	b["startCommandId"], _ = start["commandId"].(string)
	b["startPayloadHash"], _ = start["payloadHash"].(string)
	return b, nil
}
func (s *Store) marker(b map[string]string, state string, now time.Time) (record, error) {
	scope := map[string]string{}
	for _, k := range []string{"tenantId", "hostId", "executionId", "generation"} {
		scope[k] = b[k]
	}
	name, e := hash(scope)
	if e != nil {
		return record{}, e
	}
	name += ".creation.json"
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return record{}, e
	}
	r := record{Binding: b, State: state, JournalID: hex.EncodeToString(id)}
	if state == "FENCED" {
		r.FencedAt = now.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	f, e := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(e, os.ErrExist) {
		raw, err := hostfs.ReadPrivate(filepath.Join(s.path, name), 8192)
		if err != nil {
			return record{}, err
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			return record{}, errors.New("corrupt creation marker; retain and require operator review")
		}
		x, _ := hash(r.Binding)
		y, _ := hash(b)
		if x != y {
			return record{}, errors.New("creation marker binding conflict")
		}
		// Re-sync an earlier marker as well: a former writer may have lost fsync.
		old, err := s.root.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return record{}, err
		}
		err = old.Sync()
		old.Close()
		if err != nil {
			return record{}, err
		}
	} else if e != nil {
		return record{}, e
	} else {
		raw, err := canonical(r)
		if err == nil {
			_, err = f.Write(raw)
		}
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return record{}, err
		}
	}
	dir, e := s.root.Open(".")
	if e != nil {
		return record{}, e
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return record{}, e
	}
	return r, nil
}

// ClaimCreation must succeed exactly once BEFORE calling Docker/create. A crash
// after the durable claim remains uncertain and can never produce no-create proof.
func (s *Store) ClaimCreation(startRaw []byte, a Authority) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	start, e := decode("StartCommand", startRaw)
	if e != nil {
		return e
	}
	b, e := binding(start, a)
	if e != nil {
		return e
	}
	// O_EXCL distinguishes first creation from replay. The permanent claim is
	// deliberately never retried as a runtime create action after a lost result.
	scope := map[string]string{}
	for _, k := range []string{"tenantId", "hostId", "executionId", "generation"} {
		scope[k] = b[k]
	}
	name, e := hash(scope)
	if e != nil {
		return e
	}
	if _, e = s.root.Lstat(name + ".creation.json"); e == nil {
		return ErrFenced
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	r, e := s.marker(b, "CREATION_CLAIMED", time.Now())
	if e != nil {
		return e
	}
	if r.State != "CREATION_CLAIMED" {
		return ErrFenced
	}
	return nil
}

// FenceNeverStarted persists and fsyncs a permanent tombstone before producing a
// proof or allowing a durable ACK. A creation claim (even without a container ID)
// forbids this proof. Collect fresh complete inventory AFTER this proof is signed.
func (s *Store) FenceNeverStarted(startRaw, fenceRaw []byte, a Authority, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	start, e := decode("StartCommand", startRaw)
	if e != nil {
		return nil, e
	}
	b, e := binding(start, a)
	if e != nil {
		return nil, e
	}
	fence, e := decode("NeverStartedCommand", fenceRaw)
	if e != nil {
		return nil, e
	}
	for k, v := range b {
		if k == "attemptId" {
			continue
		}
		if fence[k] != v {
			return nil, errors.New("fence binding mismatch")
		}
	}
	issued, e := time.Parse(time.RFC3339Nano, fence["issuedAt"].(string))
	if e != nil || issued.After(now) {
		return nil, errors.New("invalid fence time")
	}
	r, e := s.marker(b, "FENCED", now)
	if e != nil {
		return nil, e
	}
	if r.State != "FENCED" {
		return nil, ErrCreationClaimed
	}
	proof := map[string]any{"domain": "neticora-runnerd-never-started-v1", "journalVersion": Version, "journalId": r.JournalID, "journalSequence": "1", "keyId": a.KeyID,
		"fencedAt": r.FencedAt, "attestedAt": now.UTC().Format("2006-01-02T15:04:05.000Z"), "fenceCommandId": fence["commandId"], "fencePayloadHash": fence["payloadHash"], "challenge": fence["challenge"]}
	for k, v := range b {
		proof[k] = v
	}
	raw, e := canonical(proof)
	if e != nil {
		return nil, e
	}
	proof["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))
	raw, e = canonical(proof)
	if e != nil {
		return nil, e
	}
	if e = protocol.Validate("NeverStartedProof", raw); e != nil {
		return nil, e
	}
	return raw, nil
}
