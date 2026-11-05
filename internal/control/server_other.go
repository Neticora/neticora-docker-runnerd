//go:build !linux

package control

import (
	"context"
	"errors"
)

type Snapshot struct {
	ExecutionReason  string `json:"executionReason,omitempty"`
	ExecutionEnabled bool   `json:"executionEnabled,omitempty"`
	State            string `json:"state"`
	AdmissionEnabled bool   `json:"admissionEnabled"`
	RuntimeQualified bool   `json:"runtimeQualified"`
	RecoveryReady    bool   `json:"recoveryReady"`
	RecoveryReason   string `json:"recoveryReason"`
}
type Server struct{}

func (*Server) SetDurableDrain(func() error) {}

func (*Server) ExposeExecutions(func(context.Context, string, string) (any, error)) {}

func Listen(string, func() Snapshot, func(), func(string)) (*Server, error) {
	return nil, errors.New("local control supports Linux only")
}
func (*Server) Serve() error                   { return errors.New("unsupported platform") }
func (*Server) Shutdown(context.Context) error { return nil }

func (*Server) Close() error { return nil }
