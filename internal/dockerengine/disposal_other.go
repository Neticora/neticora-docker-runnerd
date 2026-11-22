//go:build !linux

package dockerengine

import "context"

func (e *Engine) VerifyStorageReleased(context.Context, string, Plan) error { return ErrConflict }
