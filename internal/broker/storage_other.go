//go:build !linux

package broker

import "os"

func durableStorage(*os.Root) error { return ErrRejected }
func ownedRecord(os.FileInfo) bool  { return false }
