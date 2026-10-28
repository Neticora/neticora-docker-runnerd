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
	State            string `json:"state"`
	AdmissionEnabled bool   `json:"admissionEnabled"`
	RuntimeQualified bool   `json:"runtimeQualified"`
}
type Server struct {
	http     *http.Server
	listener *socketListener
}

// Listen uses a service-owned directory and never removes an existing socket.
// Stale sockets require explicit operator inspection, not a destructive reset.
func Listen(path string, snapshot func() Snapshot, drain func(), audit func(string)) (*Server, error) {
	listener, err := listenSocket(path)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
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
			http.Error(w, "administrative permission required", http.StatusForbidden)
			return
		}
		drain()
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
	return &Server{http: server, listener: listener}, nil
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
