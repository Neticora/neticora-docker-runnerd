//go:build linux && runnerd_qualification

// Package qualfixture is an isolated durable control-plane oracle for the
// tagged Kata harness. It is not SaaS qualification or provider authority.
package qualfixture

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

var ErrFixture = errors.New("isolated fixture rejected")

type Config struct {
	Version                    string                  `json:"version"`
	CaseID                     string                  `json:"caseId"`
	Identity                   protocol.HostIdentity   `json:"identity"`
	BootID                     string                  `json:"bootId"`
	EndpointIdentity           string                  `json:"endpointIdentity"`
	HostPublicKey              string                  `json:"hostPublicKey"`
	Start                      protocol.StartCommand   `json:"start"`
	Cleanup                    protocol.ControlCommand `json:"cleanup"`
	Policy                     protocol.LocalPolicy    `json:"policy"`
	BootstrapFile              string                  `json:"bootstrapFile"`
	BootstrapExpiresAt         string                  `json:"bootstrapExpiresAt"`
	InitialInventoryGeneration string                  `json:"initialInventoryGeneration,omitempty"`
	PreviousStateHash          string                  `json:"previousStateHash,omitempty"`
	InitialNonces              map[string]int64        `json:"initialNonces,omitempty"`
}
type State struct {
	Version               string                  `json:"version"`
	CaseID                string                  `json:"caseId"`
	ConfigHash            string                  `json:"configHash"`
	InventoryGeneration   string                  `json:"inventoryGeneration"`
	InventoryResources    int                     `json:"inventoryResources"`
	CleanupInventoryFloor string                  `json:"cleanupInventoryFloor"`
	Receipts              map[string]string       `json:"receipts"`
	Nonces                map[string]int64        `json:"nonces"`
	Events                map[string]string       `json:"events"`
	Sequence              string                  `json:"sequence"`
	Exited                bool                    `json:"exited"`
	ReservationReleased   bool                    `json:"reservationReleased"`
	StartRequestHash      string                  `json:"startRequestHash,omitempty"`
	StartResponse         *protocol.StartResponse `json:"startResponse,omitempty"`
	CleanupRequestHash    string                  `json:"cleanupRequestHash,omitempty"`
	CleanupReason         string                  `json:"cleanupReason,omitempty"`
}
type Server struct {
	mu           sync.Mutex
	config       Config
	root         *os.Root
	lock         *os.File
	state        State
	public       ed25519.PublicKey
	token        string
	tokenExpires time.Time
}

func New(raw []byte, directory string) (*Server, error) {
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return nil, ErrFixture
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Version != "runnerd09-control-fixture-v1" || c.Identity.HostId != "runnerd09-lab-"+c.CaseID || c.Start.Spec.PoolId != c.Identity.HostId || c.Start.Spec.IsolationProfile != "isolated" || c.Start.Spec.Resources.Slots != "1" || c.Policy.Generation != c.Start.Spec.PolicyGeneration || c.BootID == "" || c.EndpointIdentity == "" {
		return nil, ErrFixture
	}
	initial := "0"
	if c.InitialInventoryGeneration != "" {
		n, err := strconv.ParseUint(c.InitialInventoryGeneration, 10, 64)
		previous, decodeErr := hex.DecodeString(c.PreviousStateHash)
		if err != nil || strconv.FormatUint(n, 10) != c.InitialInventoryGeneration || decodeErr != nil || len(previous) != 32 {
			return nil, ErrFixture
		}
		initial = c.InitialInventoryGeneration
	}
	if len(c.InitialNonces) > 10000 {
		return nil, ErrFixture
	}
	for nonce, expiry := range c.InitialNonces {
		decoded, err := hex.DecodeString(nonce)
		if err != nil || len(decoded) != 32 || expiry > time.Now().Unix()+65 {
			return nil, ErrFixture
		}
	}
	for schema, value := range map[string]any{"HostIdentity": c.Identity, "HostCommand": c.Start} {
		b, _ := json.Marshal(value)
		if protocol.ValidateInboundJSON(schema, b) != nil {
			return nil, ErrFixture
		}
	}
	control, _ := json.Marshal(c.Cleanup)
	if protocol.ValidateInboundJSON("HostCommand", control) != nil || c.Cleanup.Kind != "cleanup" || c.Cleanup.ExecutionId != c.Start.Spec.ExecutionId || c.Cleanup.Generation != c.Start.Generation {
		return nil, ErrFixture
	}
	key, rest := pem.Decode([]byte(c.HostPublicKey))
	if key == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrFixture
	}
	parsed, err := x509.ParsePKIXPublicKey(key.Bytes)
	if err != nil {
		return nil, ErrFixture
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, ErrFixture
	}
	root, err := hostfs.OpenState(directory)
	if err != nil {
		return nil, err
	}
	lock, err := hostfs.Lock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			lock.Close()
			root.Close()
		}
	}()
	canonical, _ := protocol.CanonicalizeJSON(raw)
	hash := sha256.Sum256(canonical)
	s := &Server{config: c, root: root, lock: lock, public: public, state: State{Version: "runnerd09-fixture-state-v1", CaseID: c.CaseID, ConfigHash: hex.EncodeToString(hash[:]), InventoryGeneration: initial, Sequence: "0", Receipts: map[string]string{}, Nonces: map[string]int64{}, Events: map[string]string{}}}
	for nonce, expiry := range c.InitialNonces {
		if expiry > time.Now().Unix() {
			s.state.Nonces[nonce] = expiry
		}
	}
	if _, err = root.Lstat("state.json"); err == nil {
		b, err := readRoot(root, "state.json")
		if err != nil {
			root.Close()
			return nil, err
		}
		var saved State
		if json.Unmarshal(b, &saved) != nil || saved.Version != s.state.Version || saved.ConfigHash != s.state.ConfigHash || saved.CaseID != c.CaseID || saved.Receipts == nil || saved.Nonces == nil || saved.Events == nil {
			root.Close()
			return nil, ErrFixture
		}
		s.state = saved
		// Only committed state is authoritative. Retain stale pending bytes as
		// crash evidence; they cannot advance nonces, events or issuance.
		if _, err := root.Lstat("state.pending"); err == nil {
			if err = root.Rename("state.pending", "pending-crash-"+rand.Text()); err != nil {
				return nil, err
			}
			if err = syncRoot(root); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, ErrFixture
		}
	} else if !os.IsNotExist(err) {
		root.Close()
		return nil, ErrFixture
	} else if err = s.save(); err != nil {
		root.Close()
		return nil, err
	}
	opened = true
	return s, nil
}
func readRoot(root *os.Root, name string) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrFixture
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, ErrFixture
	}
	raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, ErrFixture
	}
	return raw, nil
}
func (s *Server) Close() error { return errors.Join(s.lock.Close(), s.root.Close()) }

func syncRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Server) save() error {
	f, err := s.root.OpenFile("state.pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(s.state)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = s.root.Rename("state.pending", "state.json"); err != nil {
		return err
	}
	return syncRoot(s.root)
}
func (s *Server) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.state)
	var state State
	json.Unmarshal(raw, &state)
	state.StartResponse = nil
	state.Nonces = nil
	return state
}
func (s *Server) configResponse() protocol.ConfigResponse {
	return protocol.ConfigResponse{AdmissionEnabled: !s.state.ReservationReleased, Policy: s.config.Policy, Protocol: protocol.ProtocolCompatibility{MinimumAdmissionVersion: "1.0.0", MinimumRecoveryVersion: "1.0.0", Version: "1.0.0"}}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Failed batches/save attempts must not advance the in-memory oracle. The
	// committed state is reloaded even after an HTTP error or partial batch.
	defer func() {
		if raw, err := readRoot(s.root, "state.json"); err == nil {
			var committed State
			if json.Unmarshal(raw, &committed) == nil {
				s.state = committed
			}
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || !strings.HasPrefix(r.URL.Path, "/api/v1/runner-hosts/") {
		http.Error(w, "rejected", 403)
		return
	}
	route := strings.TrimPrefix(r.URL.Path, "/api/v1/runner-hosts")
	raw, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxWireBytes+1))
	if err != nil || len(raw) > protocol.MaxWireBytes {
		http.Error(w, "rejected", 400)
		return
	}
	if route == "/token" && r.Method == "POST" {
		s.authenticate(w, raw)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.token == "" || !s.tokenExpires.After(time.Now()) || subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		http.Error(w, "rejected", 401)
		return
	}
	write := func(value any) { json.NewEncoder(w).Encode(value) }
	if route == "/me/config" && r.Method == "GET" {
		write(s.configResponse())
		return
	}
	if route == "/me/commands" && r.Method == "GET" {
		if request, err := readRoot(s.root, "cleanup.request.json"); err == nil {
			var control struct {
				CaseID string `json:"caseId"`
				Reason string `json:"reason"`
			}
			// Local-file only; no HTTP administrator/production endpoint.
			_, canonicalErr := protocol.CanonicalizeJSON(request)
			if canonicalErr != nil || json.Unmarshal(request, &control) != nil || control.CaseID != s.config.CaseID || len(control.Reason) < 10 || len(control.Reason) > 512 {
				http.Error(w, "rejected", 409)
				return
			}
			hash := digest(request)
			if s.state.CleanupRequestHash != "" && s.state.CleanupRequestHash != hash {
				http.Error(w, "rejected", 409)
				return
			}
			s.state.CleanupRequestHash, s.state.CleanupReason = hash, control.Reason
			if s.save() != nil {
				http.Error(w, "rejected", 409)
				return
			}
		} else if _, statErr := s.root.Lstat("cleanup.request.json"); !os.IsNotExist(statErr) {
			http.Error(w, "rejected", 409)
			return
		}
		rows := []any{}
		if s.state.Receipts[s.config.Start.CommandId] == "" {
			rows = append(rows, s.config.Start)
		}
		if (s.state.Exited || s.state.CleanupRequestHash != "") && s.state.Receipts[s.config.Cleanup.CommandId] == "" {
			rows = append(rows, s.config.Cleanup)
		}
		write(rows)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "rejected", 405)
		return
	}
	switch route {
	case "/me/heartbeat":
		if protocol.ValidateInboundJSON("HostHeartbeat", raw) != nil {
			break
		}
		write(s.configResponse())
		return
	case "/me/commands/ack":
		var ack protocol.CommandAck
		if protocol.ValidateInboundJSON("CommandAck", raw) != nil || json.Unmarshal(raw, &ack) != nil {
			break
		}
		want := ""
		if ack.CommandId == s.config.Start.CommandId {
			want = s.config.Start.PayloadHash
		}
		if ack.CommandId == s.config.Cleanup.CommandId && (s.state.Exited || s.state.CleanupRequestHash != "") {
			want = s.config.Cleanup.PayloadHash
		}
		if want == "" || ack.PayloadHash != want {
			break
		}
		if ack.CommandId == s.config.Cleanup.CommandId && s.state.Receipts[ack.CommandId] == "" {
			s.state.CleanupInventoryFloor = s.state.InventoryGeneration
		}
		s.state.Receipts[ack.CommandId] = want
		if s.save() != nil {
			break
		}
		w.WriteHeader(204)
		return
	case "/me/inventory":
		var inventory protocol.InventorySnapshot
		if protocol.ValidateInboundJSON("InventorySnapshot", raw) != nil || json.Unmarshal(raw, &inventory) != nil || inventory.EndpointIdentity != s.config.EndpointIdentity || !inventory.Complete || len(inventory.Resources) > 1 {
			break
		}
		n, _ := strconv.ParseUint(inventory.InventoryGeneration, 10, 64)
		old, _ := strconv.ParseUint(s.state.InventoryGeneration, 10, 64)
		if n <= old {
			break
		}
		for _, resource := range inventory.Resources {
			if resource.RuntimeRef.ExecutionId != s.config.Start.Spec.ExecutionId || resource.RuntimeRef.SpecHash != s.config.Start.Spec.SpecHash {
				http.Error(w, "rejected", 409)
				return
			}
		}
		s.state.InventoryGeneration = inventory.InventoryGeneration
		s.state.InventoryResources = len(inventory.Resources)
		if s.save() != nil {
			break
		}
		w.WriteHeader(204)
		return
	case "/me/recovery":
		var request protocol.RecoveryRequest
		if protocol.ValidateInboundJSON("RecoveryRequest", raw) != nil || json.Unmarshal(raw, &request) != nil {
			break
		}
		entries := []protocol.RecoveryEntry{}
		for _, entry := range request.Entries {
			if entry.ExecutionId != s.config.Start.Spec.ExecutionId || entry.Generation != s.config.Start.Generation {
				http.Error(w, "rejected", 409)
				return
			}
			entries = append(entries, protocol.RecoveryEntry{ExecutionId: entry.ExecutionId, Generation: entry.Generation, CommandId: s.config.Start.CommandId, SpecHash: s.config.Start.Spec.SpecHash, ContiguousSequence: s.state.Sequence})
		}
		write(protocol.RecoveryState{Identity: s.config.Identity, EndpointIdentity: s.config.EndpointIdentity, InventoryGeneration: s.state.InventoryGeneration, Entries: entries})
		return
	case "/me/events":
		acks, err := s.events(raw)
		if err != nil {
			break
		}
		if s.save() != nil {
			break
		}
		write(acks)
		return
	case "/me/start":
		response, err := s.start(raw)
		if err != nil {
			break
		}
		if s.save() != nil {
			break
		}
		write(response)
		return
	}
	http.Error(w, "rejected", 409)
}

func (s *Server) authenticate(w http.ResponseWriter, raw []byte) {
	var request protocol.TokenRequest
	refuse := func() { http.Error(w, "rejected", 401) }
	if protocol.ValidateInboundJSON("TokenRequest", raw) != nil || json.Unmarshal(raw, &request) != nil {
		refuse()
		return
	}
	parts := strings.Split(request.Assertion, ".")
	if len(parts) != 3 {
		refuse()
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(s.public, []byte(parts[0]+"."+parts[1]), signature) {
		refuse()
		return
	}
	headerRaw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	claimsRaw, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	var claims struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
		BootID             string `json:"bootId"`
		SessionEpoch       string `json:"sessionEpoch"`
		KeyVersion         string `json:"keyVersion"`
	}
	if e1 != nil || e2 != nil || json.Unmarshal(headerRaw, &header) != nil || json.Unmarshal(claimsRaw, &claims) != nil || header.Alg != "EdDSA" || header.Typ != "JWT" || header.Kid != s.config.Identity.KeyId || claims.Iss != s.config.Identity.HostId || claims.Sub != claims.Iss || claims.Aud != "neticora-runner-hosts" || claims.BootID != s.config.BootID || claims.SessionEpoch != s.config.Identity.SessionEpoch || claims.KeyVersion != s.config.Identity.KeyVersion || claims.Exp <= time.Now().Unix() || claims.Iat > time.Now().Unix()+5 || claims.Exp-claims.Iat > 60 || len(claims.Jti) < 16 || len(claims.Jti) > 256 {
		refuse()
		return
	}
	for nonce, expiry := range s.state.Nonces {
		if expiry <= time.Now().Unix() {
			delete(s.state.Nonces, nonce)
		}
	}
	sum := sha256.Sum256([]byte(claims.Jti))
	nonce := hex.EncodeToString(sum[:])
	if s.state.Nonces[nonce] != 0 || len(s.state.Nonces) > 10000 {
		refuse()
		return
	}
	s.state.Nonces[nonce] = claims.Exp
	if s.save() != nil {
		refuse()
		return
	}
	s.token = rand.Text() + rand.Text()
	s.tokenExpires = time.Now().Add(time.Minute)
	json.NewEncoder(w).Encode(protocol.TokenResponse{AccessToken: s.token, ExpiresAt: s.tokenExpires.UTC().Format("2006-01-02T15:04:05.000Z")})
}

func (s *Server) events(raw []byte) ([]protocol.EventAck, error) {
	var batch protocol.EventBatch
	if protocol.ValidateInboundJSON("EventBatch", raw) != nil || json.Unmarshal(raw, &batch) != nil {
		return nil, ErrFixture
	}
	for _, event := range batch.Events {
		if event.ExecutionId != s.config.Start.Spec.ExecutionId || event.Generation != s.config.Start.Generation || event.AttemptId != s.config.Start.Spec.AttemptId {
			return nil, ErrFixture
		}
		encoded, _ := json.Marshal(event)
		hash, err := protocol.PayloadHashJSON("HostEvent", encoded)
		if err != nil || hash != event.PayloadHash {
			return nil, ErrFixture
		}
		if previous := s.state.Events[event.Sequence]; previous != "" {
			if previous != event.PayloadHash {
				return nil, ErrFixture
			}
			continue
		}
		sequence, _ := strconv.ParseUint(event.Sequence, 10, 64)
		current, _ := strconv.ParseUint(s.state.Sequence, 10, 64)
		if sequence != current+1 {
			return nil, ErrFixture
		}
		if event.Observation != nil {
			if event.Observation.RuntimeRef.ExecutionId != event.ExecutionId || event.Observation.RuntimeRef.Scope != s.config.EndpointIdentity {
				return nil, ErrFixture
			}
			state := string(event.Observation.State)
			if state == "exited" || state == "cleanup-pending" {
				s.state.Exited = true
			}
			if state == "cleaned" {
				inventory, _ := strconv.ParseUint(s.state.InventoryGeneration, 10, 64)
				floor, _ := strconv.ParseUint(s.state.CleanupInventoryFloor, 10, 64)
				if !s.state.Exited || s.state.Receipts[s.config.Cleanup.CommandId] == "" || s.state.InventoryResources != 0 || inventory <= floor {
					return nil, ErrFixture
				}
				s.state.ReservationReleased = true
			}
		}
		s.state.Events[event.Sequence] = event.PayloadHash
		s.state.Sequence = event.Sequence
	}
	return []protocol.EventAck{{ExecutionId: s.config.Start.Spec.ExecutionId, Generation: s.config.Start.Generation, ContiguousSequence: s.state.Sequence}}, nil
}

func (s *Server) start(raw []byte) (protocol.StartResponse, error) {
	var request protocol.StartRequest
	if protocol.ValidateInboundJSON("StartRequest", raw) != nil || json.Unmarshal(raw, &request) != nil {
		return protocol.StartResponse{}, ErrFixture
	}
	if request.ExecutionId != s.config.Start.Spec.ExecutionId || request.SpecHash != s.config.Start.Spec.SpecHash || request.Generation != s.config.Start.Generation || request.BootstrapPublicKey == nil {
		return protocol.StartResponse{}, ErrFixture
	}
	canonical, _ := protocol.CanonicalizeJSON(raw)
	digest := sha256.Sum256(canonical)
	hash := hex.EncodeToString(digest[:])
	if s.state.StartResponse != nil {
		if s.state.StartRequestHash != hash {
			return protocol.StartResponse{}, ErrFixture
		}
		return *s.state.StartResponse, nil
	}
	plain, err := hostfs.ReadPrivate(s.config.BootstrapFile, 131072)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	defer clear(plain)
	bootstrapExpiry, err := time.Parse(time.RFC3339Nano, s.config.BootstrapExpiresAt)
	if err != nil || !bootstrapExpiry.After(time.Now().Add(30*time.Second)) {
		return protocol.StartResponse{}, ErrFixture
	}
	expires := time.Now().Add(2 * time.Minute)
	if expires.After(bootstrapExpiry) {
		expires = bootstrapExpiry
	}
	expiry := expires.UTC().Format("2006-01-02T15:04:05.000Z")
	peerRaw, err := base64.RawURLEncoding.DecodeString(*request.BootstrapPublicKey)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	secret, err := private.ECDH(peer)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	defer clear(secret)
	envelope := map[string]any{"version": "runnerd05-sealed-v1", "tenantId": s.config.Identity.HostId, "hostId": s.config.Identity.HostId, "executionId": request.ExecutionId, "generation": request.Generation, "startRequestId": request.StartRequestId, "specHash": request.SpecHash, "expiresAt": expiry, "recipient": *request.BootstrapPublicKey, "ephemeral": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())}
	aadRaw, _ := json.Marshal(envelope)
	aad, _ := protocol.CanonicalizeJSON(aadRaw)
	salt := sha256.Sum256(aad)
	key, err := hkdf.Key(sha256.New, secret, salt[:], "neticora-runnerd-bootstrap-v1", 32)
	if err != nil {
		return protocol.StartResponse{}, err
	}
	defer clear(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	envelope["nonce"] = base64.RawURLEncoding.EncodeToString(nonce)
	envelope["ciphertext"] = base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, aad))
	data, _ := json.Marshal(envelope)
	responseRaw, _ := json.Marshal(map[string]any{"state": "ISSUED", "issuanceId": "runnerd09-fixture-" + request.StartRequestId, "bootstrapExpiresAt": bootstrapExpiry.UTC().Format("2006-01-02T15:04:05.000Z"), "recoveryExpiresAt": expiry, "encryptedBootstrap": base64.RawURLEncoding.EncodeToString(data)})
	response, err := protocol.DecodeStartResponse(responseRaw)
	if err != nil {
		return response, err
	}
	s.state.StartRequestHash = hash
	s.state.StartResponse = &response
	return response, nil
}
