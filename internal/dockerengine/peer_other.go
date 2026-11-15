//go:build !linux

package dockerengine

import (
	"context"
	"net"
)

func peerIdentity(context.Context, string) (string, error) { return "", ErrUnavailable }
func peerIdentityConnection(net.Conn) (string, error)      { return "", ErrUnavailable }

func authenticatedConnection(_ context.Context, conn net.Conn) (net.Conn, string, error) {
	return conn, "", diagnostic(ErrUnsupported)
}
