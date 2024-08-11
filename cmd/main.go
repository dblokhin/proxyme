// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"log"
	"proxyme"
)

func main() {
	opts := proxyme.Options{
		AllowNoAuth: true,
	}

	srv, err := proxyme.New(opts)
	if err != nil {
		log.Fatal(err)
	}

	// start socks5 proxy
	if err := srv.ListenAndServe("tcp4", ":1080"); err != nil {
		log.Println(err)
	}
}
