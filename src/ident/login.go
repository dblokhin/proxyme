// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package ident

import (
	"net"
)

// Login ident method with username/pass auth
type Login struct {}


// ID is identical method id
func (a Login) ID() uint8 {
	return SOCK5Login
}

// Identify authorization proc
func (a Login) Identify(conn net.Conn) error {
	// TODO: impl it
	return errAccessDenied
}