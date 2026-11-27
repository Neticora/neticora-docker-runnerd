//go:build !linux

package dockerengine

func checkQuotaFilesystem(string) error { return ErrConflict }
