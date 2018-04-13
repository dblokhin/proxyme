// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package ident

// Login ident method with username/pass auth
type Login struct {}

// ID is identical method id
func (a Login) ID() int8 {
	return SOCK5Login
}

// Auth authorization proc
func (a Login) Auth() bool {
	// TODO: impl it
	return false
}