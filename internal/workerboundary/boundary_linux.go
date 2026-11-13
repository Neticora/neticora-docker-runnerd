//go:build linux

// Package workerboundary supplies a kernel PID lifetime boundary and an
// inherited denial of outbound descriptor transfer. Runtime authorization and
// durable ownership remain the caller broker's responsibility. Native controls
// cannot authorize resource disposal or production admission.
package workerboundary

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ErrBoundary = errors.New("worker acquisition boundary unavailable; retain ownership")

type Identity struct {
	verified             bool   // Only a checked birth or protected original record can mint it.
	PID                  int    `json:"pid"`
	Start                string `json:"start"`
	Boot                 string `json:"boot"`
	PIDNamespaceDevice   uint64 `json:"pidNamespaceDevice"`
	PIDNamespaceInode    uint64 `json:"pidNamespaceInode"`
	MountNamespaceDevice uint64 `json:"mountNamespaceDevice"`
	MountNamespaceInode  uint64 `json:"mountNamespaceInode"`
	Socket               string `json:"socket"`
	Profile              string `json:"profile"`
}

func processStart(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", ErrBoundary
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "", ErrBoundary
	}
	return fields[19], nil
}
func bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(raw)), err
}
func stamp(path string) (uint64, uint64, error) {
	var s syscall.Stat_t
	err := syscall.Stat(path, &s)
	return uint64(s.Dev), s.Ino, err
}

// Start must be called only after the original broker intent is durable and its
// empty owned cgroup has been independently verified. The returned kernel identity
// MUST be durably recorded before Run is called. There is no adoption fallback.
func Start(ctx context.Context, helper, socket, profile string, cgroupFD int) (Identity, error) {
	var id Identity
	if err := ctx.Err(); err != nil {
		return id, err
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 || !filepath.IsAbs(helper) || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || len(socket) > 100 || profile == "" || strings.ContainsAny(profile, " \n\x00") || cgroupFD < 0 {
		return id, ErrBoundary
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		return id, ErrBoundary
	}
	cmd := exec.Command(helper, "init", socket, profile)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: cgroupFD}
	// No context cancellation kill: a broker crash cannot silently erase the
	// ownership obligation. A failed launch remains an original pending intent.
	if err := cmd.Start(); err != nil {
		return id, err
	}
	id.PID = cmd.Process.Pid
	// Reap only this child after its eventual exit. Command has no cancellation
	// hook or parent-death signal: losing the broker preserves the original
	// namespace/ownership. Release without Wait would leak zombies in a live
	// long-running broker after successful retirement.
	go func() { _ = cmd.Wait() }()
	var err error
	id.Start, err = processStart(id.PID)
	if err != nil {
		return id, ErrBoundary
	}
	id.Boot, err = bootID()
	if err != nil {
		return id, ErrBoundary
	}
	id.Socket, id.Profile = socket, profile
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if _, err = os.Lstat(socket); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return id, ctx.Err()
		case <-deadline.C:
			return id, ErrBoundary
		case <-time.After(10 * time.Millisecond):
		}
	}
	id.PIDNamespaceDevice, id.PIDNamespaceInode, err = stamp(fmt.Sprintf("/proc/%d/ns/pid", id.PID))
	if err != nil {
		return id, ErrBoundary
	}
	id.MountNamespaceDevice, id.MountNamespaceInode, err = stamp(fmt.Sprintf("/proc/%d/ns/mnt", id.PID))
	if err != nil {
		return id, ErrBoundary
	}
	id.verified = true
	if err = id.Check(); err != nil {
		id.verified = false
		return id, err
	}
	return id, nil
}

func (id Identity) Check() error {
	if !id.verified {
		return ErrBoundary
	}
	boot, err := bootID()
	if err != nil || boot != id.Boot || id.PID < 2 || id.Start == "" || id.PIDNamespaceInode == 0 || id.MountNamespaceInode == 0 {
		return ErrBoundary
	}
	before, err := processStart(id.PID)
	if err != nil || before != id.Start {
		return ErrBoundary
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", id.PID))
	if err != nil {
		return ErrBoundary
	}
	init := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			f := strings.Fields(line)
			init = len(f) == 3 && f[1] == strconv.Itoa(id.PID) && f[2] == "1"
		}
	}
	if !init {
		return ErrBoundary
	}
	for kind, expected := range map[string][2]uint64{"pid": {id.PIDNamespaceDevice, id.PIDNamespaceInode}, "mnt": {id.MountNamespaceDevice, id.MountNamespaceInode}} {
		dev, ino, e := stamp(fmt.Sprintf("/proc/%d/ns/%s", id.PID, kind))
		if e != nil || dev != expected[0] || ino != expected[1] {
			return ErrBoundary
		}
		_, host, e := stamp("/proc/self/ns/" + kind)
		if e != nil || host == ino {
			return ErrBoundary
		}
	}
	after, err := processStart(id.PID)
	if err != nil || after != before {
		return ErrBoundary
	}
	return nil
}
func (id Identity) connect(ctx context.Context) (*net.UnixConn, error) {
	if id.Check() != nil {
		return nil, ErrBoundary
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unixpacket", id.Socket)
	if err != nil {
		return nil, err
	}
	c := connection.(*net.UnixConn)
	raw, err := c.SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		peer, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = e == nil && peer.Uid == 0 && int(peer.Pid) == id.PID
	})
	if err != nil || !valid || id.Check() != nil {
		c.Close()
		return nil, ErrBoundary
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	return c, nil
}

// Run accepts only broker-selected pinned executables/arguments and explicit
// stdio descriptors. No environment, shell, host PID or cgroup is an RPC field.
// The caller must independently pin helper, profile and command hashes/paths.
func (id Identity) Run(ctx context.Context, argv []string, stdio [3]*os.File) error {
	if len(argv) == 0 || len(argv) > 127 || !filepath.IsAbs(argv[0]) {
		return ErrBoundary
	}
	payload := []byte("RUN\x00")
	for _, a := range argv {
		if a == "" || strings.ContainsRune(a, 0) {
			return ErrBoundary
		}
		payload = append(payload, []byte(a)...)
		payload = append(payload, 0)
	}
	if len(payload) > 65536 {
		return ErrBoundary
	}
	c, err := id.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stopCancellation()
	descriptors := make([]int, 3)
	for i, f := range stdio {
		if f == nil {
			return ErrBoundary
		}
		descriptors[i] = int(f.Fd())
	}
	n, _, err := c.WriteMsgUnix(payload, unix.UnixRights(descriptors...), nil)
	if err != nil || n != len(payload) {
		return ErrBoundary
	}
	var result [4]byte
	n, err = c.Read(result[:])
	if err != nil || n != 4 {
		return ErrBoundary
	}
	status := int32(binary.LittleEndian.Uint32(result[:]))
	if status != 0 {
		return fmt.Errorf("%w: worker status %d", ErrBoundary, status)
	}
	return nil
}

// Retire exits ONLY the originally verified namespace init. The kernel retires
// every descendant regardless of its cgroup; pidfd readiness is the barrier.
// A missing or changed original identity cannot mint positive retirement proof.
func (id Identity) Retire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id.Check() != nil {
		return ErrBoundary
	}
	pidfd, err := unix.PidfdOpen(id.PID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pidfd)
	if id.Check() != nil {
		return ErrBoundary
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Do not depend on a responsive userspace request loop to retire a busy
	// original namespace. This pidfd is rechecked against its durable owner;
	// it cannot address an unknown worker or a reused numeric PID.
	if err = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
		return err
	}
	for {
		polls := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		n, e := unix.Poll(polls, 50)
		if e != nil && e != unix.EINTR {
			return e
		}
		if n == 1 && polls[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// CheckRetired is read-only. A durably verified PID-namespace init exiting is
// a kernel guarantee about all namespace descendants, unlike an arbitrary
// missing shim PID or an empty cgroup. Boot/identity uncertainty still fails
// closed. The enclosing broker record must authenticate the original Identity.
func (id Identity) CheckRetired() error {
	if !id.verified {
		return ErrBoundary
	}
	boot, err := bootID()
	if err != nil || boot != id.Boot || id.PID < 2 || id.Start == "" || id.PIDNamespaceInode == 0 || id.MountNamespaceInode == 0 {
		return ErrBoundary
	}
	start, err := processStart(id.PID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrBoundary
	}
	if start != id.Start {
		return nil
	} // Original namespace init exited, PID reused.
	fd, err := unix.PidfdOpen(id.PID, 0)
	if err != nil {
		return ErrBoundary
	}
	defer unix.Close(fd)
	// Recheck after pidfd_open: a reused PID must never be signaled or adopted.
	after, e := processStart(id.PID)
	if e != nil || after != start {
		return ErrBoundary
	}
	polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, e := unix.Poll(polls, 0)
	if e != nil || n != 1 || polls[0].Revents&unix.POLLIN == 0 {
		return ErrBoundary
	}
	return nil
}
