//go:build linux

package updatetrust

import (
	"os"
	"syscall"
)

func openRegular(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
