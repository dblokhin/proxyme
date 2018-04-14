// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"server"
	"ident"
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
	// setting up listen addr
	// TODO: from env. vars
	listenAddr := "0:8080"

	// init ident methods (see sock5, http://www.ietf.org/rfc/rfc1928.txt)
	idents := make([]ident.Identifier, 0)
	idents = append(idents, ident.NoAuth{})

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
