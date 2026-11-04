package service

import (
	"context"
	"errors"
	"log"
	"sync/atomic"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/control"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

// Run starts the bounded local service shell. No execution controller is wired
// yet; admission remains disabled. Shutdown never invokes runtime Stop/Remove.
func Run(ctx context.Context, c config.Config, socket string) error {
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	var draining atomic.Bool
	draining.Store(true)
	server, err := control.Listen(socket, func() control.Snapshot {
		state := "not-ready"
		if draining.Load() {
			state = "drained"
		}
		healthCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		health := store.Health(healthCtx)
		return control.Snapshot{State: state, AdmissionEnabled: false, RuntimeQualified: false, RecoveryReady: health.Ready, RecoveryReason: health.Reason}
	}, func() { draining.Store(true) }, func(event string) { log.Print(event) })
	if err != nil {
		return err
	}
	defer server.Close()
	result := make(chan error, 1)
	go func() { result <- server.Serve() }()
	select {
	case err = <-result:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdown)
		if shutdownErr != nil {
			closeErr := server.Close()
			serveErr := <-result
			return errors.Join(errors.New("control shutdown failed"), shutdownErr, closeErr, serveErr)
		}
		return <-result
	}
}
