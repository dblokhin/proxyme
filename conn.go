package proxyme

import (
	"io"
	"net"
	"time"
)

type tcpConnWithTimeout struct {
	*net.TCPConn
	timeout time.Duration
}

func (t tcpConnWithTimeout) ReadFrom(r io.Reader) (n int64, err error) {
	_ = t.TCPConn.SetDeadline(time.Now().Add(t.timeout)) // nolint
	return t.TCPConn.ReadFrom(r)
}

func (t tcpConnWithTimeout) WriteTo(w io.Writer) (n int64, err error) {
	_ = t.TCPConn.SetDeadline(time.Now().Add(t.timeout)) // nolint
	return t.TCPConn.WriteTo(w)
}

func (t tcpConnWithTimeout) Write(p []byte) (n int, err error) {
	_ = t.TCPConn.SetDeadline(time.Now().Add(t.timeout)) // nolint
	return t.TCPConn.Write(p)
}

func (t tcpConnWithTimeout) Read(p []byte) (n int, err error) {
	_ = t.TCPConn.SetDeadline(time.Now().Add(t.timeout)) // nolint
	return t.TCPConn.Read(p)
}
