//go:build linux

package dockerengine

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// peerIdentity supports a directly owned dockerd Unix socket. Socket-activation
// proxies and remote engines need separate continuity qualification, not a made-up
// universal Docker boot identity. This is observation only; no host changes.
func peerIdentity(ctx context.Context, path string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return "", ErrUnavailable
	}
	defer conn.Close()
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return "", ErrUnavailable
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return "", ErrUnavailable
	}
	var cred *syscall.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || sockErr != nil || cred == nil || cred.Uid != 0 || cred.Pid <= 1 {
		return "", ErrUnavailable
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/stat")
	if err != nil {
		return "", ErrUnavailable
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 || !strings.Contains(string(stat[:end]), "(dockerd") {
		return "", ErrUnavailable
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return "", ErrUnavailable
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", ErrUnavailable
	}
	return strings.TrimSpace(string(boot)) + ":" + strconv.Itoa(int(cred.Pid)) + ":" + fields[19], nil
}
