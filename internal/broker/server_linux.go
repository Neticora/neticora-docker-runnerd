//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type Config struct {
	Socket                  string         `json:"socket"`
	StateDirectory          string         `json:"stateDirectory"`
	ControllerUID           uint32         `json:"controllerUid"`
	ControllerGID           uint32         `json:"controllerGid"`
	Audience                string         `json:"audience"`
	AuthorityPublicKey      string         `json:"authorityPublicKey"`
	ExecutionGrantPublicKey string         `json:"executionGrantPublicKey,omitempty"`
	Scope                   Binding        `json:"scope"`
	Runtime                 *RuntimeConfig `json:"runtime,omitempty"`
}

type caller struct{}

func peerUID(connection net.Conn) (uint32, error) {
	u, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, ErrRejected
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *syscall.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || socketErr != nil || credential == nil {
		return 0, ErrRejected
	}
	return credential.Uid, nil
}

type handler struct {
	config       Config
	key          ed25519.PublicKey
	executionKey ed25519.PublicKey
	ledger       *Ledger
	executor     *physicalExecutor
	disposalKey  ed25519.PrivateKey
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	respond := func(status int, result Response) {
		slog.Info("broker request outcome", "code", result.Code, "status", status)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(result)
	}
	deny := func(status int, code string) { respond(status, Response{Version: Version, Code: code}) }
	uid, ok := r.Context().Value(caller{}).(uint32)
	if !ok || uid != h.config.ControllerUID {
		deny(403, "unauthorized_peer")
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/request" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		deny(400, "invalid_request")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessage))
	var request Request
	if err != nil || decode(raw, &request) != nil {
		deny(400, "invalid_request")
		return
	}
	if request.Version != Version {
		deny(409, "unsupported_version")
		return
	}
	if h.runtimeRequest(w, r, request) {
		return
	}
	if request.Lookup != nil || request.MinimumFreeBytes != 0 || request.DisposalChallenge != nil || request.BootCertificate != nil {
		deny(400, "invalid_request")
		return
	}
	switch request.Operation {
	case "GetBrokerHealth":
		if request.Target != "" || request.Authorization != nil || request.ExecutionRequest != nil || request.ExecutionGrant != nil || request.ExecutionCommit != nil {
			deny(400, "invalid_request")
			return
		}
		capabilities := []string{"GetBrokerHealth", "GetOperationStatus"}
		if len(h.executionKey) == ed25519.PublicKeySize {
			capabilities = append(capabilities, "IssueExecutionChallenge", "AuthorizeExecution")
		}
		respond(200, Response{Version: Version, Code: "foundation_only", Ready: false, Capabilities: capabilities})
	case "GetOperationStatus":
		if request.ExecutionRequest != nil || request.ExecutionGrant != nil || request.ExecutionCommit != nil {
			deny(400, "invalid_request")
			return
		}
		if verify(request, h.key, h.config.Audience, h.config.Scope, time.Now()) != nil {
			deny(403, "unauthorized_operation")
			return
		}
		receipt, err := h.ledger.Get(request.Target)
		if os.IsNotExist(err) {
			deny(404, "operation_absent")
			return
		}
		if err != nil {
			deny(503, "reconciliation_required")
			return
		}
		if receipt.Binding != request.Authorization.Grant.Binding {
			deny(403, "unauthorized_operation")
			return
		}
		respond(200, Response{Version: Version, Code: "reconciliation_required", Receipt: &receipt})
	case "IssueExecutionChallenge":
		if request.Target != "" || request.Authorization != nil || request.ExecutionRequest == nil || request.ExecutionGrant != nil || request.ExecutionCommit != nil || len(h.executionKey) != ed25519.PublicKeySize {
			deny(400, "invalid_request")
			return
		}
		challenge, err := h.ledger.IssueChallenge(*request.ExecutionRequest, time.Now())
		if err != nil {
			deny(409, "challenge_refused")
			return
		}
		respond(200, Response{Version: Version, Code: "challenge_issued", Ready: false, Challenge: &challenge})
	case "AuthorizeExecution":
		if request.Target != "" || request.Authorization != nil || request.ExecutionRequest == nil || request.ExecutionGrant == nil || request.ExecutionCommit == nil {
			deny(400, "invalid_request")
			return
		}
		receipt, _, err := h.ledger.AcceptExecutionIntent(*request.ExecutionGrant, *request.ExecutionRequest, h.executionKey, h.config.Scope, time.Now(), *request.ExecutionCommit)
		if err != nil {
			deny(403, "execution_authority_rejected")
			return
		}
		respond(200, Response{Version: Version, Code: "authorized_intent_only", Ready: false, Receipt: &receipt})
	default:
		deny(400, "unsupported_operation")
	}
}

// Serve defaults to foundation-only. Runtime configuration is rejected by the
// shipping build; the qualification build additionally requires an expiring,
// root-owned disposable-host marker. Neither claims production readiness.
func Serve(ctx context.Context, file string) error {
	if os.Geteuid() != 0 {
		return ErrRejected
	}
	raw, err := hostfs.ReadPrivate(file, MaxMessage)
	if err != nil {
		return err
	}
	var c Config
	if decode(raw, &c) != nil || c.ControllerUID == 0 || c.ControllerGID == 0 || c.Audience == "" || len(c.Audience) > 256 {
		return ErrRejected
	}
	// Config scope contains host/session origin only; per-execution binding comes
	// from independently signed grants, never this service's caller UID.
	check := c.Scope
	check.ExecutionID, check.Generation, check.AttemptID, check.SpecHash = "validate", "1", "validate", strings.Repeat("0", 64)
	if !check.valid() || c.Scope.ExecutionID != "" || c.Scope.Generation != "" || c.Scope.AttemptID != "" || c.Scope.SpecHash != "" {
		return ErrRejected
	}
	key, err := base64.StdEncoding.Strict().DecodeString(c.AuthorityPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return ErrRejected
	}
	var executionKey []byte
	if c.ExecutionGrantPublicKey != "" {
		executionKey, err = base64.StdEncoding.Strict().DecodeString(c.ExecutionGrantPublicKey)
		if err != nil || len(executionKey) != ed25519.PublicKeySize {
			return ErrRejected
		}
	}
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || c.Socket == "/" || !filepath.IsAbs(c.StateDirectory) || filepath.Clean(c.StateDirectory) != c.StateDirectory {
		return ErrRejected
	}
	parent := filepath.Dir(c.Socket)
	if hostfs.CheckAncestors(parent) != nil {
		return ErrRejected
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return ErrRejected
	}
	ledger, err := OpenLedger(c.StateDirectory)
	if err != nil {
		return err
	}
	defer ledger.Close()
	executor, disposalKey, closeRuntime, err := openRuntime(ctx, c, ledger, executionKey)
	if err != nil {
		return err
	}
	defer closeRuntime()
	// Ledger lock covers stale listener replacement and the entire server lifetime.
	if err = staleSocket(ctx, c.Socket, c.ControllerGID); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if os.Chown(c.Socket, 0, int(c.ControllerGID)) != nil || os.Chmod(c.Socket, 0660) != nil {
		return ErrRejected
	}
	server := &http.Server{Handler: handler{config: c, key: key, executionKey: executionKey, ledger: ledger, executor: executor, disposalKey: disposalKey}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 6 * time.Minute, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		uid, err := peerUID(conn)
		if err != nil {
			return ctx
		}
		return context.WithValue(ctx, caller{}, uid)
	}}
	stopped := make(chan struct{})
	defer close(stopped)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-stopped:
			return
		}
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}

func staleSocket(ctx context.Context, path string, gid uint32) error {
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || before.Mode().Type() != os.ModeSocket || before.Mode().Perm() != 0660 {
		return ErrRejected
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid || stat.Nlink != 1 {
		return ErrRejected
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	if err == nil {
		conn.Close()
		return ErrConflict
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || ctx.Err() != nil {
		return ErrRejected
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		return ErrRejected
	}
	return os.Remove(path)
}
