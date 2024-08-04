// 13.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"proxyme"
	"runtime"
)

// Staring main program here.
// proxyme is so easy!
func main() {
	runtime.GOMAXPROCS(8)

	// it's just http profiler
	go http.ListenAndServe("0.0.0.0:8081", nil)

	// init server structure
	srv, err := proxyme.NewServer("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	// start proxy
	log.Println("starting")
	if err := srv.Run(":1080"); err != nil {
		log.Println(err)
	}
}
