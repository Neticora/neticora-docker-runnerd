//go:build !linux

package dockerengine

import "context"

func (*Engine) RecoveryDomain(context.Context) (string, error) { return "", ErrUnavailable }
func (*Engine) VerifyRecoveryNetworkDetached(context.Context, string, string, string) error {
	return ErrUnavailable
}
