//go:build !linux

package onboarding

func Command([]string) (bool, error) { return false, nil }
