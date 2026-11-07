//go:build !linux

package dockerengine

import "context"

func (*Engine) verifyKataStartupConfig(context.Context, string, string, string, string, string) error {
	return ErrConflict
}
