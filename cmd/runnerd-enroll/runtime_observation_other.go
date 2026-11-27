//go:build !linux

package main

import "errors"

func writeRuntimeObservation(string, string, string, string, string) error {
	return errors.New("runtime observation requires Linux")
}
func readRuntimeObservation(string, string, string, string, string) (string, error) {
	return "", errors.New("runtime observation requires Linux")
}
