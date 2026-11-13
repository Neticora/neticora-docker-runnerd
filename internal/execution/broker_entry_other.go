//go:build !linux

package execution

func CheckBrokerEntryDescriptors() error { return ErrReconcile }
