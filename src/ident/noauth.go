// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package ident

// NoAuth ident method without auth
type NoAuth struct {}

// ID is identical method id
func (a NoAuth) ID() int8 {
	return SOCK5NoAuth
}

// Auth authorization proc
func (a NoAuth) Auth() bool {
	return true
}