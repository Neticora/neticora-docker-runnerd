package control

import (
	"net"
	"sync"
)

// limitListener caps live local-control handlers and unblocks on shutdown.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newLimitListener(listener net.Listener, max int) *limitListener {
	return &limitListener{Listener: listener, slots: make(chan struct{}, max), done: make(chan struct{})}
}
func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case l.slots <- struct{}{}:
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: connection, release: func() { <-l.slots }}, nil
}
func (l *limitListener) Close() error { l.once.Do(func() { close(l.done) }); return l.Listener.Close() }

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
