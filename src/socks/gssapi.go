// 25.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

import "net"

// GSSAPI ident method with GSSAPI
type GSSAPI struct{}

// ID is identical method id
func (a GSSAPI) ID() uint8 {
	return IdentGSSAPI
}

// Identify authorization proc
func (a GSSAPI) Identify(conn net.Conn) error {
	// get sec context
	// set sec context
	//
	return nil
}