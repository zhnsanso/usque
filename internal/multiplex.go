package internal

import (
	"bufio"
	"net"
)

// PeekedConn is a net.Conn wrapper that reads from a bufio.Reader.
// This allows peeking at the first few bytes of a connection to determine the protocol
// without losing the data when passing the connection to a handler.
type PeekedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *PeekedConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

// VirtualListener is a net.Listener implementation that accepts connections from a channel.
// It is used to feed connections to an http.Server or other listeners that require a net.Listener.
type VirtualListener struct {
	AddrVal net.Addr
	Ch      chan net.Conn
	Closed  chan struct{}
}

func NewVirtualListener(addr net.Addr) *VirtualListener {
	return &VirtualListener{
		AddrVal: addr,
		Ch:      make(chan net.Conn),
		Closed:  make(chan struct{}),
	}
}

func (l *VirtualListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.Ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.Closed:
		return nil, net.ErrClosed
	}
}

func (l *VirtualListener) Close() error {
	select {
	case <-l.Closed:
		return nil
	default:
		close(l.Closed)
		return nil
	}
}

func (l *VirtualListener) Addr() net.Addr {
	return l.AddrVal
}
