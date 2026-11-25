//go:build linux

package katalinux

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func requireKVM() error {
	const kvmGetAPIVersion = 0xAE00
	const kvmAPIVersion = 12

	f, err := os.OpenFile("/dev/kvm", os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		version, err := unix.IoctlRetInt(int(f.Fd()), kvmGetAPIVersion)
		if err == nil && version == kvmAPIVersion {
			return nil
		}
	}
	return errors.New("standalone Kata requires working KVM at /dev/kvm")
}
