//go:build !linux

package broker

import "github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"

type handoffManager struct{}

func (*handoffManager) Prepare(dockerengine.Plan) error                  { return ErrRejected }
func (*handoffManager) Dispose(dockerengine.Plan) error                  { return ErrRejected }
func (*handoffManager) DisposeUnstarted(dockerengine.Plan) error         { return ErrRejected }
func (*handoffManager) CheckDisposed(dockerengine.Plan) error            { return ErrRejected }
func (*handoffManager) BootAbsent(dockerengine.Plan, string, bool) error { return ErrRejected }
