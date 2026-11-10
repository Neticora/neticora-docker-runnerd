//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type observerRequest struct {
	Binding   string            `json:"binding"`
	Profile   string            `json:"profile"`
	Container string            `json:"container"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
}

func observerBinding(base standardlinux.Settings, evidence, journal string) string {
	raw, _ := json.Marshal(struct {
		Network, Bootstrap, Evidence, Journal string
		UID                                   int
		Pids                                  int64
	}{base.NetworkID, base.BootstrapRoot, evidence, journal, base.RunnerUID, base.PidsLimit})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

type ObserverConfig struct {
	Socket            string `json:"socket"`
	ServiceUID        int    `json:"serviceUid"`
	ProfileDirectory  string `json:"profileDirectory"`
	PublicKeyFile     string `json:"publicKeyFile"`
	EvidenceDirectory string `json:"evidenceDirectory"`
	JournalDirectory  string `json:"journalDirectory"`
	RuntimeEndpoint   string `json:"runtimeEndpoint"`
	InstallationID    string `json:"installationId"`
	HostID            string `json:"hostId"`
	NetworkID         string `json:"networkId"`
	BootstrapRoot     string `json:"bootstrapRoot"`
	PidsLimit         int64  `json:"pidsLimit"`
}

func peerUID(conn net.Conn) (uint32, error) {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, ErrQualification
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		inner = err
		if err == nil {
			uid = cred.Uid
		}
	})
	if e != nil {
		return 0, e
	}
	return uid, inner
}
func (p *Profile) remote(ctx context.Context, op, id string, plan dockerengine.Plan) error {
	response, err := p.request(ctx, op, id, plan)
	if err != nil {
		return err
	}
	if string(response) != "{\"ok\":true}\n" {
		return ErrQualification
	}
	return nil
}

// Only an authenticated root peer can return host evidence. No proxy, TCP,
// redirect or guest-generated artifact participates in this channel.
func (p *Profile) request(ctx context.Context, op, id string, plan dockerengine.Plan) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, e := (&net.Dialer{}).DialContext(ctx, "unix", p.ObserverSocket)
		if e != nil {
			return nil, e
		}
		uid, e := peerUID(conn)
		if e != nil || uid != 0 {
			conn.Close()
			return nil, ErrQualification
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	labels := map[string]string(nil)
	if plan.Config != nil {
		labels = plan.Config.Labels
	}
	body, err := json.Marshal(observerRequest{Binding: observerBinding(p.Base, p.EvidenceDirectory, p.JournalDirectory), Profile: p.ID, Container: id, Name: plan.Name, Labels: labels})
	if err != nil {
		return nil, ErrQualification
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://kata-observer/v1/"+op, bytes.NewReader(body))
	if err != nil {
		return nil, ErrQualification
	}
	r, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrQualification }}).Do(req)
	if err != nil {
		return nil, ErrQualification
	}
	defer r.Body.Close()
	response, err := io.ReadAll(io.LimitReader(r.Body, 32769))
	if err != nil || len(response) > 32768 || r.StatusCode != http.StatusOK {
		return nil, ErrQualification
	}
	return response, nil
}

type callerKey struct{}

// ServeObserver has no container create/start/stop/delete API. It reads trusted
// host evidence and manages only signed-profile execution storage roots. It is
// deliberately separate from provider authority and customer network settings.
func ServeObserver(ctx context.Context, file string) error {
	return serveObserver(ctx, file, Load)
}

func serveObserver(ctx context.Context, file string, load func(string, string, string, string, standardlinux.Settings) (*Profile, error)) error {
	if os.Geteuid() != 0 {
		return ErrQualification
	}
	raw, e := hostfs.ReadPrivate(file, 65536)
	if e != nil {
		return e
	}
	if _, e = protocol.CanonicalizeJSON(raw); e != nil {
		return e
	}
	var c ObserverConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || c.ServiceUID < 1 || c.InstallationID == "" || c.HostID == "" || len(c.NetworkID) != 64 || c.PidsLimit < 16 || c.PidsLimit > 4096 {
		return ErrQualification
	}
	for _, path := range []string{c.Socket, c.ProfileDirectory, c.PublicKeyFile, c.EvidenceDirectory, c.JournalDirectory, c.BootstrapRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return ErrQualification
		}
	}
	lifecycle, e := lockObserverLifecycle(c.EvidenceDirectory)
	if e != nil {
		return e
	}
	defer lifecycle.Close()
	for _, path := range []string{c.ProfileDirectory, c.EvidenceDirectory} {
		root, e := hostfs.OpenState(path)
		if e != nil {
			return e
		}
		root.Close()
	}
	parent := filepath.Dir(c.Socket)
	if hostfs.CheckAncestors(parent) != nil {
		return ErrQualification
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		return ErrQualification
	}
	ownerStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || ownerStat.Uid != 0 {
		return ErrQualification
	}
	// Parent is root-owned/private: clients cannot replace the listener pathname.
	if e = removeStaleObserverSocket(ctx, c.Socket, c.ServiceUID); e != nil {
		return e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if e != nil {
		return e
	}
	listener.SetUnlinkOnClose(true)
	defer listener.Close()
	if e = os.Chown(c.Socket, c.ServiceUID, -1); e != nil {
		return e
	}
	if e = os.Chmod(c.Socket, 0600); e != nil {
		return e
	}
	var owner sync.Mutex
	var gate sync.Mutex
	var handlers sync.WaitGroup
	closing := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gate.Lock()
		if closing {
			gate.Unlock()
			http.Error(w, "stopping", http.StatusServiceUnavailable)
			return
		}
		handlers.Add(1)
		gate.Unlock()
		defer handlers.Done()
		uid, ok := r.Context().Value(callerKey{}).(uint32)
		if !ok || uid != uint32(c.ServiceUID) || r.Method != http.MethodPost {
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil {
			http.Error(w, "rejected", 400)
			return
		}
		if _, e = protocol.CanonicalizeJSON(body); e != nil {
			http.Error(w, "rejected", 400)
			return
		}
		var req observerRequest
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || len(req.Profile) != len("docker-kata-rs-qemu-v1-")+64 || (!strings.HasPrefix(req.Profile, "docker-kata-rs-qemu-v1-") && !strings.HasPrefix(req.Profile, "docker-kata-rs-qemu-v2-") && !strings.HasPrefix(req.Profile, "docker-kata-rs-qemu-v3-")) {
			http.Error(w, "rejected", 400)
			return
		}
		if _, e = hex.DecodeString(req.Profile[len("docker-kata-rs-qemu-v1-"):]); e != nil {
			http.Error(w, "rejected", 400)
			return
		}
		owner.Lock()
		defer owner.Unlock()
		base := standardlinux.Settings{ImageRepository: "qualified-profile", NetworkID: c.NetworkID, BootstrapRoot: c.BootstrapRoot, RunnerUID: c.ServiceUID, PidsLimit: c.PidsLimit}
		p, e := load(filepath.Join(c.ProfileDirectory, req.Profile+".json"), c.PublicKeyFile, c.EvidenceDirectory, c.JournalDirectory, base)
		if e != nil || p.ID != req.Profile || p.Manifest.ObserverConfig != file || req.Binding != observerBinding(base, c.EvidenceDirectory, c.JournalDirectory) {
			http.Error(w, "unverified", 409)
			return
		}
		p.storageInstallationID = c.InstallationID
		p.storageHostID = c.HostID
		p.Base.ImageRepository = p.Manifest.ImageRepository
		engine, e := dockerengine.OpenReadOnly(c.RuntimeEndpoint, c.InstallationID, nil)
		if e != nil {
			http.Error(w, "unavailable", 409)
			return
		}
		defer engine.Close()
		op := strings.TrimPrefix(r.URL.Path, "/v1/")
		var exported json.RawMessage
		e = func() error {
			if op == "check" {
				endpoint, err := engine.Probe(r.Context())
				if err != nil || endpoint != p.Manifest.EndpointIdentity {
					return ErrQualification
				}
				return p.Probe(r.Context(), engine)
			}
			if op == "check-recovery" {
				return p.RecoverProbe(r.Context(), engine)
			}
			labels := req.Labels
			if labels[dockerengine.LabelPrefix+"installation"] != c.InstallationID || labels[dockerengine.LabelPrefix+"host"] != c.HostID || labels[dockerengine.LabelPrefix+"endpoint"] != p.Manifest.EndpointIdentity {
				return ErrQualification
			}
			scope := agent.StoreScope{InstallationID: c.InstallationID, HostID: c.HostID, TenantID: labels[dockerengine.LabelPrefix+"tenant"], EndpointIdentity: p.Manifest.EndpointIdentity}
			spec := protocol.ExecutionSpec{ExecutionId: labels[dockerengine.LabelPrefix+"execution"], AttemptId: labels[dockerengine.LabelPrefix+"attempt"], Generation: labels[dockerengine.LabelPrefix+"generation"], SpecHash: labels[dockerengine.LabelPrefix+"spec"], IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: p.template(), ImageDigest: p.Manifest.ImageDigest, Resources: p.Manifest.Budget.Effective}
			var plan dockerengine.Plan
			var err error
			if op == "prepare" || op == "verify-block" {
				plan, err = p.Plan(scope, spec)
			} else {
				plan, err = p.RecoveryPlan(scope, spec)
			}
			if err != nil || plan.Name != req.Name || !reflect.DeepEqual(plan.Config.Labels, labels) {
				return ErrQualification
			}
			if err = p.layout(); err != nil {
				return err
			}
			if op == "verify-block" {
				return p.VerifyStorage(r.Context(), plan)
			}
			if op == "prepare" {
				if _, inspectErr := engine.Inspect(r.Context(), plan.Name, plan); inspectErr == nil {
					return p.VerifyStorage(r.Context(), plan)
				} else if !errors.Is(inspectErr, dockerengine.ErrAbsent) {
					return ErrQualification
				}
				if err = p.Probe(r.Context(), engine); err != nil {
					return err
				}
				if p.Manifest.Storage.Block != nil {
					return p.prepareBlock(r.Context(), plan)
				}
				return p.Prepare(plan)
			}
			object, inspectErr := engine.Inspect(r.Context(), req.Container, plan)
			switch op {
			case "evidence":
				if !errors.Is(inspectErr, dockerengine.ErrAbsent) {
					return ErrQualification
				}
				if err = engine.VerifyNetworkDetached(r.Context(), req.Container, c.NetworkID); err != nil {
					return err
				}
				record, err := p.PhysicalEvidence(r.Context(), req.Container, plan)
				if err != nil {
					return err
				}
				if err = p.CheckReadOnlyAbsence(r.Context(), req.Container, plan, record); err != nil {
					return err
				}
				endpoint, err := engine.Probe(r.Context())
				if err != nil || endpoint != p.Manifest.EndpointIdentity {
					return ErrQualification
				}
				exported, err = json.Marshal(record)
				return err
			case "prepared":
				if inspectErr != nil || object.State != "prepared" {
					return ErrQualification
				}
				return p.CapturePrepared(req.Container, plan)
			case "capture":
				if inspectErr != nil || object.State != "running" {
					return ErrQualification
				}
				return p.Capture(r.Context(), req.Container, plan)
			case "absent":
				if !errors.Is(inspectErr, dockerengine.ErrAbsent) {
					return ErrQualification
				}
				if err = engine.VerifyNetworkDetached(r.Context(), req.Container, c.NetworkID); err != nil {
					return err
				}
				if err = p.VerifyAbsent(r.Context(), req.Container, plan, func() error {
					_, err := engine.Inspect(r.Context(), req.Container, plan)
					if !errors.Is(err, dockerengine.ErrAbsent) {
						return ErrQualification
					}
					if err := engine.VerifyNetworkDetached(r.Context(), req.Container, c.NetworkID); err != nil {
						return err
					}
					endpoint, err := engine.Probe(r.Context())
					if err != nil || endpoint != p.Manifest.EndpointIdentity {
						return ErrQualification
					}
					return nil
				}); err != nil {
					return err
				}
				_, err = engine.Probe(r.Context())
				return err
			case "discard":
				if _, err = engine.Inspect(r.Context(), plan.Name, plan); !errors.Is(err, dockerengine.ErrAbsent) {
					return ErrQualification
				}
				if p.Manifest.Storage.Block != nil {
					if _, e := p.blockRecord(plan); e != nil {
						if _, e := os.Lstat(p.rawPath(plan.Name)); errors.Is(e, os.ErrNotExist) {
							return nil
						}
						return ErrQualification
					}
					if err := p.releaseBlock(r.Context(), plan); err != nil {
						return err
					}
					_, err := p.releaseHostCgroup(r.Context(), plan)
					return err
				}
				for _, fs := range []Filesystem{p.Manifest.Storage.Graph, p.Manifest.Storage.Workspace} {
					root, err := hostfs.OpenState(fs.Root)
					if err != nil {
						return err
					}
					err = root.Remove(plan.Name)
					root.Close()
					if err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
				}
				return nil
			default:
				return ErrQualification
			}
		}()
		if e != nil {
			http.Error(w, "unverified", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if exported != nil {
			_, _ = w.Write(append(exported, '\n'))
			return
		}
		io.WriteString(w, "{\"ok\":true}\n")
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		uid, e := peerUID(conn)
		if e != nil {
			return ctx
		}
		return context.WithValue(ctx, callerKey{}, uid)
	}}
	// Serve returns when shutdown begins, before active handlers necessarily
	// finish. Keep the lifecycle lock until those handlers have actually exited.
	defer func() {
		gate.Lock()
		closing = true
		gate.Unlock()
		server.Close()
		handlers.Wait()
	}()
	stopShutdown := make(chan struct{})
	defer close(stopShutdown)
	go func() {
		select {
		case <-ctx.Done():
		case <-stopShutdown:
			return
		}
		timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(timeout)
	}()
	e = server.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func (p *Profile) DiscardPrepared(ctx context.Context, plan dockerengine.Plan) error {
	return p.remote(ctx, "discard", "", plan)
}
