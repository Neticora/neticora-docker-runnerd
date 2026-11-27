//go:build !linux

package dockerengine

import "context"

func (*Engine) verifyKataStartupConfig(context.Context, string, string, string, string, string) error {
	return ErrConflict
}

func matchingSignedKataConfig(string, string, string, string, string) bool { return false }
