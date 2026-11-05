//go:build !linux

package execution

func volatileDirectory(string) error   { return ErrReconcile }
func persistentDirectory(string) error { return ErrReconcile }
