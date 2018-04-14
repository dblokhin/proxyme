// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package ident

import (
	"net"
	"errors"
)

const (
	// identical method ids
	SOCK5NoAuth     uint8 = 0
	SOCK5GSSAPI     uint8 = 1
	SOCK5Login      uint8 = 2
	SOCK5IdentError uint8 = 0xff
)

var errAccessDenied = errors.New("access denied")

// Identifier is possible method identify
type Identifier interface {
	// ID is identical method id
	ID() uint8

	// Identify client, returns nonerror if identity successful
	Identify(conn net.Conn) error
}
