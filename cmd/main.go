// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"proxyme"
)

// Staring main program here.
// proxyme is so easy!
func main() {
	// it's just http profiler
	go http.ListenAndServe("0.0.0.0:8081", nil)

	// init server structure
	srv, err := proxyme.NewServer("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	srv.EnableNoAuth()

	// start proxy
	log.Println("starting")
	if err := srv.Run(":1080"); err != nil {
		log.Println(err)
	}
}
