// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package ident

const (
	// identical method ids
	SOCK5NoAuth int8 = 0
	SOCK5GSSAPI      = 1
	SOCK5Login       = 2
)

// Identifier is possible method identify
type Identifier interface {
	// ID is identical method id
	ID() int8
	Auth() bool
}
