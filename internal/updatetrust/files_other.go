//go:build !linux

package updatetrust

import (
	"errors"
	"os"
)

func openRegular(*os.Root, string) (*os.File, error) {
	return nil, errors.New("update verification is qualified only on Linux")
}
