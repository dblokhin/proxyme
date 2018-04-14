// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package server

import (
	"net"
	"sock"
)

type ProxymeServer struct {
	ListenAddr string
	Idents []sock.Identifier
}

func (s *ProxymeServer) Start() error {
	// TODO: listener from ENV. VARIABLES
	listener, err := net.Listen("tcp4", s.ListenAddr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		// processes new client
		go sock.NewClient(conn, s.Idents)
	}
}