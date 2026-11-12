//go:build linux

package execution

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defense in depth; deployment must also deny these sockets with kernel
// permissions and a root-owned service mount namespace. This check is not a
// substitute for the controller-compromise qualification campaign.
func checkBrokerContainment(endpoint string) error {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("%w: controller UID/GID is privileged", ErrReconcile)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, gid := range groups {
		if gid == 0 {
			return fmt.Errorf("%w: privileged supplementary group", ErrReconcile)
		}
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "CapInh:", "CapPrm:", "CapEff:", "CapAmb:":
			bits, e := strconv.ParseUint(fields[1], 16, 64)
			if e != nil || bits != 0 {
				return fmt.Errorf("%w: controller retains %s", ErrReconcile, fields[0])
			}
		}
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, fd := range fds {
		n, e := strconv.Atoi(fd.Name())
		if e != nil || n < 3 {
			continue
		}
		target, e := os.Readlink("/proc/self/fd/" + fd.Name())
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if strings.HasPrefix(target, "socket:[") {
			return fmt.Errorf("%w: inherited socket descriptor %d", ErrReconcile, n)
		}
	}
	paths := []string{"/run/docker.sock", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/k3s/containerd/containerd.sock"}
	for _, value := range []string{endpoint, os.Getenv("DOCKER_HOST"), os.Getenv("CONTAINERD_ADDRESS")} {
		if value == "" {
			continue
		}
		u, e := url.Parse(value)
		if e != nil {
			return ErrReconcile
		}
		if u.Scheme == "unix" {
			paths = append(paths, u.Path)
		} else if strings.HasPrefix(value, "/") {
			paths = append(paths, value)
		} else {
			return ErrReconcile
		}
	}
	for _, path := range paths {
		connection, e := net.DialTimeout("unix", path, 250*time.Millisecond)
		if e == nil {
			connection.Close()
			return fmt.Errorf("%w: direct runtime socket accessible: %s", ErrReconcile, path)
		}
		// Unexpected errors cannot establish denied access.
		if !errors.Is(e, os.ErrNotExist) && !errors.Is(e, os.ErrPermission) {
			return fmt.Errorf("%w: runtime denial uncertain: %s: %v", ErrReconcile, path, e)
		}
	}
	return nil
}
