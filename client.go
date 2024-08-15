package proxyme

import (
	"bufio"
	"io"
	"net"
)

const (
	bufferSize = 1024
)

type client struct {
	conn io.ReadWriteCloser
	rdr  *bufio.Reader
	wrt  *bufio.Writer
}

// writeMessage writes payload through buffer writer.
func (c *client) writeMessage(msg io.WriterTo) error {
	if _, err := msg.WriteTo(c.wrt); err != nil {
		return err
	}

	if err := c.wrt.Flush(); err != nil {
		return err
	}

	return nil
}

// upgrade hijacks client conn (reason: protocol flow might consider encapsulation)
// For example GSSAPI encapsulates the traffic intro gssapi protocol messages.
// Package user can encapsulate traffic into whatever he wants using Connect method.
func (c *client) upgrade(conn io.ReadWriteCloser) {
	c.conn = conn
	c.rdr = bufio.NewReaderSize(conn, bufferSize)
	c.wrt = bufio.NewWriterSize(conn, bufferSize)
}

func (c *client) close() error {
	return c.conn.Close()
}

func newClient(conn net.Conn) *client {
	rdr := bufio.NewReaderSize(conn, bufferSize)
	wrt := bufio.NewWriterSize(conn, bufferSize)

	return &client{
		conn: conn,
		rdr:  rdr,
		wrt:  wrt,
	}
}
