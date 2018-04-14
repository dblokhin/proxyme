// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"server"
	"sock"
	"os"
)

func init() {
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

// Staring main program here.
// proxyme is so easy!

func main() {
	log.Println("Starting golang proxyme")

	// setting up listen addr
	// TODO: from env. vars
	listenAddr := "localhost:8080"

	// init ident methods (see sock5, http://www.ietf.org/rfc/rfc1928.txt)
	idents := make([]sock.Identifier, 0)
	idents = append(idents, sock.Login{
		HardcodeValidator{},
	})

	// init server structure
	proxyme := server.ProxymeServer{
		ListenAddr: listenAddr,
		Idents:     idents,
	}

	// run proxy
	if err := proxyme.Start(); err != nil {
		log.Fatal(err)
	}
}

// HardcodeValidator is just simple example validator of username/pass identity.
// Validator should impl LoginValidator interface (see login.go)
type HardcodeValidator struct {}

// PasswordByLogin the main goal of validator: returns pwd of given login
func (hc HardcodeValidator) PasswordByLogin(login string) string {
	if login == "guest" {
		return "guest"
	}

	// the zero-lenght pass is invalid pass (see login.go)
	return ""
}