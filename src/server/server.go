// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package server

import (
	"ident"
	"net"
	"protocols"
)

type ProxymeServer struct {
	ListenAddr string
	Idents []ident.Identifier
}

func (s *ProxymeServer) Start() error {
	// TODO: listener from ENV. VARIABLES
	listener, err := net.Listen("tcp4", "localhost:8080")
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		// processes new client
		go protocols.NewClient(conn, s.Idents)
	}
}