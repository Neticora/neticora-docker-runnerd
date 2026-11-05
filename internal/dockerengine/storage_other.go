//go:build !linux

package dockerengine

func storageAvailable(string) (uint64, error) { return 0, ErrStoragePressure }
