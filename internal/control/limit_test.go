package control

import (
	"net"
	"sync"
	"testing"
	"time"
)

type testListener struct {
	calls int
	mu    sync.Mutex
	peers []net.Conn
}

func (l *testListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, b := net.Pipe()
	l.peers = append(l.peers, b)
	l.calls++
	return a, nil
}
func (l *testListener) Close() error   { return nil }
func (l *testListener) Addr() net.Addr { return &net.UnixAddr{Net: "unix"} }
func TestControlConnectionLimitAndCancellation(t *testing.T) {
	raw := &testListener{}
	limited := newLimitListener(raw, 2)
	defer func() {
		for _, peer := range raw.peers {
			_ = peer.Close()
		}
	}()
	a, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	waiting := make(chan error, 1)
	go func() {
		c, err := limited.Accept()
		if c != nil {
			c.Close()
		}
		waiting <- err
	}()
	_ = limited.Close()
	select {
	case err := <-waiting:
		if err == nil {
			t.Fatal("connection cap bypassed")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock accept")
	}
	raw.mu.Lock()
	calls := raw.calls
	raw.mu.Unlock()
	if calls != 2 {
		t.Fatal("underlying connection cap exceeded")
	}
}
