// 13.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"net"
	"errors"
)

const (
	// identical methods
	IdentNoAuth uint8 = 0
	IdentGSSAPI uint8 = 1
	IdentLogin  uint8 = 2
	IdentError  uint8 = 0xff
)

var errAccessDenied = errors.New("access denied")

// Identifier is possible method identify
type Identifier interface {
	// ID is identical method id
	ID() uint8

	// Identify client, returns nonerror if identifier successful
	Identify(conn net.Conn) error
}
