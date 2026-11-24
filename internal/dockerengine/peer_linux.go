//go:build linux

package dockerengine

import (
	"context"
	"net"
	"os"
	"os/exec"
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
	return peerIdentityConnection(conn)
}

// peerIdentityConnection inspects SO_PEERCRED on the same connected socket the
// HTTP transport will use. Checking another connection leaves a replacement race.
func peerIdentityConnection(conn net.Conn) (string, error) {
	return dockerSocketPeer(conn, false)
}

func dockerSocketPeer(conn net.Conn, allowSystemd bool) (string, error) {
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
	if err != nil || sockErr != nil || cred == nil || cred.Uid != 0 || cred.Pid < 1 {
		return "", ErrUnavailable
	}
	pid := cred.Pid
	if pid == 1 && allowSystemd {
		// Stock docker.socket is opened by PID 1. Bind continuity to the
		// daemon selected by the native service manager, not to PID 1.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", "docker.service")
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		raw, err := cmd.Output()
		value, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil || parseErr != nil || value <= 1 {
			return "", ErrUnavailable
		}
		pid = int32(value)
	}
	if pid <= 1 {
		return "", ErrUnavailable
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
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
	return strings.TrimSpace(string(boot)) + ":" + strconv.Itoa(int(pid)) + ":" + fields[19], nil
}

// standalonePeer allows socket activation only on the standard local Docker
// socket. All other configured Unix endpoints use the direct dockerd check.
func standalonePeer(conn net.Conn, path string) (string, error) {
	return dockerSocketPeer(conn, path == "/run/docker.sock")
}
