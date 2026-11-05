//go:build !linux

package dockerengine

import "context"

func peerIdentity(context.Context, string) (string, error) { return "", ErrUnavailable }
