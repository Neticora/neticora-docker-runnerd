//go:build !linux

package hostfs

import (
	"errors"
	"os"
)

func ReadPrivate(string, int64) ([]byte, error) {
	return nil, errors.New("local service supports Linux only")
}
func OpenState(string) (*os.Root, error) { return nil, errors.New("local service supports Linux only") }
func Lock(*os.Root) (*os.File, error)    { return nil, errors.New("local service supports Linux only") }

func CheckAncestors(string) error { return errors.New("local service supports Linux only") }
