//go:build linux

package dockerengine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Socket-activated listeners identify PID 1 through SO_PEERCRED. Authenticate
// the actual dockerd sender with kernel SCM_CREDENTIALS on a read-only ping on
// this very connection, before returning it to any mutating HTTP transport.
// The endpoint identity remains boot ID + dockerd PID + process start time.
func peerIdentity(ctx context.Context, path string) (string, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return "", diagnostic(err)
	}
	defer conn.Close()
	_, peer, err := authenticatedConnection(ctx, conn)
	return peer, err
}

func socketCredentials(conn *net.UnixConn, pass bool) (*syscall.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, ErrUnsupported
	}
	var cred *syscall.Ucred
	var callErr error
	err = raw.Control(func(fd uintptr) {
		if pass {
			callErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
			if callErr != nil {
				return
			}
		}
		cred, callErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || callErr != nil || cred == nil || cred.Uid != 0 {
		return nil, ErrUnsupported
	}
	return cred, nil
}

func processIdentity(cred *syscall.Ucred) (string, error) {
	if cred == nil || cred.Uid != 0 || cred.Pid <= 1 {
		return "", ErrUnsupported
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/stat")
	if err != nil {
		return "", ErrContinuity
	}
	start := strings.IndexByte(string(stat), '(')
	end := strings.LastIndexByte(string(stat), ')')
	if start < 0 || end <= start || string(stat[start+1:end]) != "dockerd" {
		return "", ErrUnsupported
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return "", ErrUnsupported
	}
	if _, err = strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", ErrUnsupported
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", ErrContinuity
	}
	return strings.TrimSpace(string(boot)) + ":" + strconv.Itoa(int(cred.Pid)) + ":" + fields[19], nil
}

// Remains available for direct-peer tests. PID 1 alone is never dockerd identity.
func peerIdentityConnection(conn net.Conn) (string, error) {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return "", ErrUnsupported
	}
	cred, err := socketCredentials(u, false)
	if err != nil {
		return "", err
	}
	return processIdentity(cred)
}

func authenticatedConnection(ctx context.Context, conn net.Conn) (net.Conn, string, error) {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return conn, "", ErrUnsupported
	}
	cred, err := socketCredentials(u, true)
	if err != nil {
		return conn, "", err
	}
	if cred.Pid == 1 {
		name, err := os.ReadFile("/proc/1/comm")
		if err != nil || strings.TrimSpace(string(name)) != "systemd" {
			return conn, "", ErrUnsupported
		}
		return authenticateActivatedConnection(ctx, u)
	}
	peer, err := processIdentity(cred)
	if err != nil {
		return conn, "", err
	}
	return &credentialConnection{conn: u, peer: peer, cred: *cred}, peer, nil
}

type credentialConnection struct {
	conn *net.UnixConn
	peer string
	cred syscall.Ucred
	// Only used during the unbound, read-only handshake; cleared before publication.
	handshakeRemaining int
}

func (c *credentialConnection) Close() error                       { return c.conn.Close() }
func (c *credentialConnection) CloseWrite() error                  { return c.conn.CloseWrite() }
func (c *credentialConnection) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *credentialConnection) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *credentialConnection) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *credentialConnection) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *credentialConnection) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *credentialConnection) reject(cause error) error {
	_ = c.conn.Close()
	return diagnostic(cause)
}

func (c *credentialConnection) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if c.handshakeRemaining > 0 && len(data) > c.handshakeRemaining {
		data = data[:c.handshakeRemaining]
	}
	// Go's Linux ReadMsgUnix uses MSG_CMSG_CLOEXEC. Any received rights are closed
	// and rejected, including on truncated-control errors; none reach an exec child.
	oob := make([]byte, syscall.CmsgSpace(syscall.SizeofUcred)+syscall.CmsgSpace(16*4))
	n, oobn, flags, _, err := c.conn.ReadMsgUnix(data, oob)
	if n == 0 && oobn == 0 {
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}
	messages, parseErr := syscall.ParseSocketControlMessage(oob[:oobn])
	var sender *syscall.Ucred
	invalid := parseErr != nil || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0
	for _, m := range messages {
		switch {
		case m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_RIGHTS:
			fds, e := syscall.ParseUnixRights(&m)
			if e == nil {
				for _, fd := range fds {
					_ = syscall.Close(fd)
				}
			}
			invalid = true
		case m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_CREDENTIALS:
			if sender != nil {
				invalid = true
				continue
			}
			sender, parseErr = syscall.ParseUnixCredentials(&m)
			if parseErr != nil {
				invalid = true
			}
		default:
			invalid = true
		}
	}
	if invalid || sender == nil {
		return 0, c.reject(ErrUnsupported)
	}
	peer, e := processIdentity(sender)
	if e != nil {
		return 0, c.reject(e)
	}
	if c.peer == "" {
		c.peer = peer
		c.cred = *sender
	} else if c.peer != peer || c.cred.Pid != sender.Pid || c.cred.Uid != sender.Uid {
		return 0, c.reject(ErrContinuity)
	}
	if c.handshakeRemaining > 0 {
		c.handshakeRemaining -= n
		if c.handshakeRemaining == 0 {
			return 0, c.reject(ErrUnsupported)
		}
	}
	return n, err
}

func (c *credentialConnection) Write(data []byte) (int, error) {
	// Never send even the first byte of a mutation through a stale binding. During
	// the handshake only the fixed HEAD /_ping below can use the raw Unix socket.
	if c.peer == "" {
		return 0, c.reject(ErrUnsupported)
	}
	current, err := processIdentity(&c.cred)
	if err != nil || current != c.peer {
		return 0, c.reject(ErrContinuity)
	}
	return c.conn.Write(data)
}

func authenticateActivatedConnection(ctx context.Context, conn *net.UnixConn) (net.Conn, string, error) {
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return conn, "", ErrDaemonUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c := &credentialConnection{conn: conn, handshakeRemaining: 64 << 10}
	// No token, labels, resource name, authorization or mutating operation is sent.
	if _, err := io.WriteString(conn, "HEAD /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		return conn, "", ErrDaemonUnavailable
	}
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodHead})
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return conn, "", err
		}
		return conn, "", ErrDaemonUnavailable
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if response.StatusCode != http.StatusOK || response.Close || response.ProtoMajor != 1 || response.ProtoMinor != 1 || reader.Buffered() != 0 || c.peer == "" {
		return conn, "", ErrUnsupported
	}
	if ctx.Err() != nil {
		return conn, "", ErrDaemonUnavailable
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return conn, "", ErrDaemonUnavailable
	}
	c.handshakeRemaining = 0
	return c, c.peer, nil
}
