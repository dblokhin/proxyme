package protocol

import (
	"bufio"
	"net"
)

type Peer struct {
	conn net.Conn
	rdr  *bufio.Reader
	wrt  *bufio.Writer

	err error // last error during connection
}

func (p Peer) LastError() error {
	return p.err
}

func NewPeer(conn net.Conn) *Peer {
	const (
		readBuffer  = 32 * 1024
		writeBuffer = 4 * 1024
	)

	rdr := bufio.NewReaderSize(conn, readBuffer)
	wrt := bufio.NewWriterSize(conn, writeBuffer)

	return &Peer{
		conn: conn,
		rdr:  rdr,
		wrt:  wrt,
	}
}
