//go:build !linux

package execution

func volatileDirectory(string) error   { return ErrReconcile }
func persistentDirectory(string) error { return ErrReconcile }

func backingHeadroom(string, uint64) error { return ErrReconcile }
