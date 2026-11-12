//go:build !linux

package broker

import "context"

// Broker transport never substitutes an unauthenticated or direct runtime path.
func Call(context.Context, string, Request) (Response, error) { return Response{}, ErrRejected }
