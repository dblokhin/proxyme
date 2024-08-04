package proxyme

import (
	"bufio"
)

type peer struct {
	rdr *bufio.Reader
	wrt *bufio.Writer

	err error // last error during connection
}
