//go:build !linux

package journal

import "errors"

func localStorage(string) error             { return errors.New("SQLite recovery supports Linux only") }
func availableBytes(string) (uint64, error) { return 0, localStorage("") }
func privateFile(string, bool) error        { return localStorage("") }
