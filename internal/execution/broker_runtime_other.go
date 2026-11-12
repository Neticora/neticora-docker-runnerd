//go:build !linux

package execution

func checkBrokerContainment(string) error { return ErrReconcile }

// Open rejects non-Linux execution before constructing a runtime.
func brokerRuntimeFor(*Controller, *HostRemote, string) Runtime { return nil }
