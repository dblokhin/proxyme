// 13.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"socks"
	"os"
	_ "net/http/pprof"
	"net/http"
	"runtime"
	"validators"
	"github.com/dblokhin/config"
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
	runtime.GOMAXPROCS(8)
	log.Println("Starting golang proxyme")

	// it's just http profiler
	go http.ListenAndServe("0.0.0.0:8081", nil)

	// load config
	conf, err := config.New("config.json")
	if err != nil {
		log.Fatal(err)
	}

	// setting up listen addr
	listenAddr := conf.GetString("listen")

	// init ident methods (see sock5, http://www.ietf.org/rfc/rfc1928.txt)
	idents := make([]socks.Identifier, 0)

	// adding username/pass identity
	idents = append(idents, socks.Login{
		Validator: validators.HardcodeValidator{},
	})

	// adding noauth identity
	idents = append(idents, socks.NoAuth{})

	// init server structure
	proxyme := socks.NewServer(listenAddr, idents)

	// start proxy
	if err := proxyme.Start(); err != nil {
		log.Println(err)
	}
}