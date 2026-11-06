//go:build !linux

package dockerengine

import (
	"context"
	"net"
)

func peerIdentity(context.Context, string) (string, error) { return "", ErrUnavailable }
func peerIdentityConnection(net.Conn) (string, error)      { return "", ErrUnavailable }
