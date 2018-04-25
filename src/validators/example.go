// 25.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

// Package validators provides validators for login identity
// You can create your own validator (authenticator) database based, config data based, OS users based and others
package validators

// HardcodeValidator is just simple example validator of login identity.
// Validator implements LoginValidator interface (see src/socks/login.go)
type HardcodeValidator struct {}

// PasswordByLogin the main goal of validator: returns pwd of given login
func (hc HardcodeValidator) Authorize(login, pass string) bool {
	// zero-length login or pass is invalid
	if len(login) == 0 || len(pass) == 0 {
		return false
	}

	return login == "guest" && pass == "guest"
}