package proxyme

import (
	"bufio"
	"net"
)

type peer struct {
	conn net.Conn
	rdr  *bufio.Reader
	wrt  *bufio.Writer

	err error // last error during connection
}
