// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package socks

import "net"

// NoAuth ident method without auth
type NoAuth struct{}

// ID is identical method id
func (a NoAuth) ID() uint8 {
	return IdentNoAuth
}

// Identify authorization proc
func (a NoAuth) Identify(conn net.Conn) error {
	return nil
}
