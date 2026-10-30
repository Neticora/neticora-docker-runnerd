//go:build !linux

package control

import (
	"context"
	"errors"
)

type Snapshot struct {
	State            string `json:"state"`
	AdmissionEnabled bool   `json:"admissionEnabled"`
	RuntimeQualified bool   `json:"runtimeQualified"`
}
type Server struct{}

func Listen(string, func() Snapshot, func(), func(string)) (*Server, error) {
	return nil, errors.New("local control supports Linux only")
}
func (*Server) Serve() error                   { return errors.New("unsupported platform") }
func (*Server) Shutdown(context.Context) error { return nil }

func (*Server) Close() error { return nil }
