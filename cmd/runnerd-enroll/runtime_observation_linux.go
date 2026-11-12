//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func rootObservationParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute clean root observation path required")
	}
	parent := filepath.Dir(path)
	for {
		s, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || s.Mode().Perm()&0022 != 0 {
			return errors.New("runtime observation requires root-owned non-writable ancestors")
		}
		if parent == "/" {
			return nil
		}
		parent = filepath.Dir(parent)
	}
}
func writeRuntimeObservation(path, endpoint, installation, tenant, host string) error {
	if os.Geteuid() != 0 {
		return errors.New("root operator required for runtime observation")
	}
	if err := rootObservationParent(path); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine, err := dockerengine.OpenReadOnly(endpoint, installation, nil)
	if err != nil {
		return err
	}
	defer engine.Close()
	peer, err := engine.Probe(ctx)
	if err != nil {
		return errors.New("runtime observation probe failed")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	v := runtimeObservation{"runnerd-runtime-observation-v1", installation, tenant, host, strings.TrimSpace(string(boot)), peer, time.Now().UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func readRuntimeObservation(path, installation, tenant, host, boot string) (string, error) {
	if err := rootObservationParent(path); err != nil {
		return "", err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	s, err := file.Stat()
	if err != nil {
		return "", err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || s.Mode().Perm()&0022 != 0 {
		return "", errors.New("untrusted runtime observation")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil {
		return "", err
	}
	return decodeRuntimeObservation(raw, installation, tenant, host, boot, time.Now())
}
