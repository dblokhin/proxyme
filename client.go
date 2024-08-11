package proxyme

import (
	"bufio"
	"io"
	"net"
)

const (
	readBuffer  = 32 * 1024
	writeBuffer = 4 * 1024
)

type Client struct {
	conn io.ReadWriteCloser
	rdr  *bufio.Reader
	wrt  *bufio.Writer

	err error // last error during connection
}

func (c *Client) LastError() error {
	return c.err
}

func (c *Client) WriteMessage(msg io.WriterTo) error {
	if _, err := msg.WriteTo(c.wrt); err != nil {
		return err
	}

	if err := c.wrt.Flush(); err != nil {
		return err
	}

	return nil
}

func (c *Client) Upgrade(conn io.ReadWriteCloser) {
	c.conn = conn
	c.rdr = bufio.NewReaderSize(conn, readBuffer)
	c.wrt = bufio.NewWriterSize(conn, writeBuffer)
}

func NewClient(conn net.Conn) *Client {
	rdr := bufio.NewReaderSize(conn, readBuffer)
	wrt := bufio.NewWriterSize(conn, writeBuffer)

	return &Client{
		conn: conn,
		rdr:  rdr,
		wrt:  wrt,
	}
}
