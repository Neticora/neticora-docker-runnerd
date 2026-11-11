//go:build linux

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

type peerKey struct{}
type Snapshot struct {
	ExecutionReason  string `json:"executionReason,omitempty"`
	ExecutionEnabled bool   `json:"executionEnabled,omitempty"`
	State            string `json:"state"`
	AdmissionEnabled bool   `json:"admissionEnabled"`
	RuntimeQualified bool   `json:"runtimeQualified"`
	RecoveryReady    bool   `json:"recoveryReady"`
	RecoveryReason   string `json:"recoveryReason"`
}
type Server struct {
	drainAction *drainAction
	mux         *http.ServeMux
	http        *http.Server
	listener    *socketListener
}

type drainAction struct{ run func() error }

func (s *Server) SetDurableDrain(action func() error) { s.drainAction.run = action }

// Listen uses a service-owned directory and never removes an existing socket.
// Stale sockets require explicit operator inspection, not a destructive reset.
func Listen(path string, snapshot func() Snapshot, drain func(), audit func(string)) (*Server, error) {
	listener, err := listenSocket(path)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	action := &drainAction{run: func() error { drain(); return nil }}
	write := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot())
	}
	for _, route := range []string{"/status", "/doctor", "/capabilities"} {
		mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) { write(w) })
	}
	mux.HandleFunc("POST /drain", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || (uid != 0 && int(uid) != os.Geteuid()) {
			audit("drain rejected")
			http.Error(w, "administrative permission required", http.StatusForbidden)
			return
		}
		if err := action.run(); err != nil {
			audit("drain persistence failed")
			http.Error(w, "drain persistence failed; admission remains fenced", http.StatusServiceUnavailable)
			return
		}
		audit("drain accepted")
		write(w)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if limited, ok := c.(*limitConn); ok {
			c = limited.Conn
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return ctx
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return ctx
		}
		var uid uint32
		valid := false
		if err = raw.Control(func(fd uintptr) {
			cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if e == nil {
				uid = cred.Uid
				valid = true
			}
		}); err == nil && valid {
			return context.WithValue(ctx, peerKey{}, uid)
		}
		return ctx
	}}
	return &Server{http: server, listener: listener, mux: mux, drainAction: action}, nil
}

// ExposeExecutions adds a sensitive read-only diagnostic, restricted to the
// service owner/root rather than the ordinary status-observer group.
func (s *Server) ExposeExecutions(list func(context.Context, string, string) (any, error)) {
	s.mux.HandleFunc("GET /executions", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || (uid != 0 && int(uid) != os.Geteuid()) {
			http.Error(w, "administrative permission required", http.StatusForbidden)
			return
		}
		value, err := list(r.Context(), r.URL.Query().Get("afterExecutionId"), r.URL.Query().Get("afterGeneration"))
		if err != nil {
			http.Error(w, "recovery diagnostic unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	})
}

// Qualification diagnostics have the same owner/root boundary as journal export;
// ordinary status observers and guest workloads cannot request host signatures.
func (s *Server) ExposeKataEvidence(read func(context.Context, string, string) (any, error)) {
	s.mux.HandleFunc("GET /kata-evidence", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || (uid != 0 && int(uid) != os.Geteuid()) {
			http.Error(w, "administrative permission required", http.StatusForbidden)
			return
		}
		query := r.URL.Query()
		id, generation := query.Get("executionId"), query.Get("generation")
		if len(query) != 2 || len(query["executionId"]) != 1 || len(query["generation"]) != 1 || len(id) < 1 || len(id) > 256 || len(generation) < 1 || len(generation) > 20 {
			http.Error(w, "explicit execution scope required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		value, err := read(ctx, id, generation)
		if err != nil {
			http.Error(w, "trusted Kata evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	})
}
func (s *Server) Serve() error {
	err := s.http.Serve(newLimitListener(s.listener, 32))
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return errors.Join(err, s.listener.Close())
}

// Shutdown also closes a bound listener when Serve has not started yet.
func (s *Server) Shutdown(ctx context.Context) error {
	closeErr := s.listener.Close()
	return errors.Join(closeErr, s.http.Shutdown(ctx))
}

// Close forcibly closes active local-control connections and the owned listener.
// It does not act on workflow runtimes or installation locks.
func (s *Server) Close() error { return errors.Join(s.listener.Close(), s.http.Close()) }
