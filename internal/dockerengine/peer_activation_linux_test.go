//go:build linux

package dockerengine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func activatedFixture(t *testing.T, name, mode string) (*net.UnixConn, *exec.Cmd) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root inherited-listener fixture; run on disposable VM")
	}
	dir := t.TempDir()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "inherited.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, name)
	if err = os.Symlink(binary, helper); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helper, "-test.run=^TestActivatedPeerHelper$")
	cmd.Env = append(os.Environ(), "NRD_ACTIVATED_HELPER="+mode)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	raw, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err = socketCredentials(raw, true); err != nil {
		t.Fatal(err)
	}
	return raw, cmd
}

func TestActivatedSocketAuthenticatesActualDockerdSender(t *testing.T) {
	conn, child := activatedFixture(t, "dockerd", "normal")
	creator, err := socketCredentials(conn, false)
	if err != nil || int(creator.Pid) != os.Getpid() {
		t.Fatal("fixture did not inherit listener", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authenticated, peer, err := authenticateActivatedConnection(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(peer, ":"+strconv.Itoa(child.Process.Pid)+":") {
		t.Fatal("trusted listener creator instead of replying daemon")
	}
	if _, ok := authenticated.(io.ReaderFrom); ok {
		t.Fatal("socket fast path bypasses verified Write")
	}
	if _, ok := authenticated.(syscall.Conn); ok {
		t.Fatal("raw socket exposed outside authenticated transport")
	}
	if _, ok := authenticated.(interface{ CloseWrite() error }); !ok {
		t.Fatal("bootstrap half-close support lost")
	}
	if _, err = io.WriteString(authenticated, "GET /info HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(authenticated), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(data) != "verified" {
		t.Fatal("authenticated response failed", err)
	}
}

func TestActivatedSocketRejectsUnverifiedOrAncillaryReplies(t *testing.T) {
	for _, fixture := range []struct{ name, mode string }{{"other-daemon", "normal"}, {"dockerd", "rights"}, {"dockerd", "oversized"}} {
		t.Run(fixture.name+"-"+fixture.mode, func(t *testing.T) {
			conn, _ := activatedFixture(t, fixture.name, fixture.mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := authenticateActivatedConnection(ctx, conn); err == nil {
				t.Fatal("unverified reply accepted")
			}
		})
	}
}

func TestActivatedPeerDeathFencesWritesBeforeSendingBytes(t *testing.T) {
	conn, child := activatedFixture(t, "dockerd", "normal")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authenticated, _, err := authenticateActivatedConnection(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	n, err := authenticated.Write([]byte("POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"))
	if n != 0 || !errors.Is(err, ErrContinuity) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("dead daemon received mutation bytes", n, err)
	}
}

func TestDockerDiagnosticCategoriesPreserveFailClosedContract(t *testing.T) {
	for _, cause := range []error{ErrPermission, ErrSocketInaccessible, ErrDaemonUnavailable, ErrUnsupported, ErrContinuity} {
		if err := diagnostic(cause); !errors.Is(err, cause) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("lost typed diagnostic", err)
		}
	}
	if _, err := processIdentity(&syscall.Ucred{Pid: 1, Uid: 0}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("PID 1 treated as daemon")
	}
	if _, err := processIdentity(&syscall.Ucred{Pid: int32(os.Getpid()), Uid: 1000}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("nonroot daemon trusted")
	}
}

func TestActivatedPeerHelper(t *testing.T) {
	mode := os.Getenv("NRD_ACTIVATED_HELPER")
	if mode == "" {
		t.Skip("subprocess fixture only")
	}
	listener, err := net.FileListener(os.NewFile(3, "inherited-listener"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead && r.Method != http.MethodGet {
			t.Error("authentication sent mutating request")
		}
		if mode == "rights" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			file, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			_, _, err = conn.(*net.UnixConn).WriteMsgUnix([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), syscall.UnixRights(int(file.Fd())), nil)
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if mode == "oversized" {
			w.Header().Set("X-Long", strings.Repeat("x", 70<<10))
		}
		if r.URL.Path == "/_ping" {
			w.Header().Set("Api-Version", "1.56")
			w.WriteHeader(200)
			return
		}
		_, _ = fmt.Fprint(w, "verified")
	})}
	_ = server.Serve(listener)
}
