// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package protocols

import (
	"net"
	"encoding/binary"
	"log"
	"ident"
)

const (
	// identical method ids
	SOCK4Version uint8 = 4
	SOCK5Version uint8 = 5
)

// Client structure represents each connected client
type Client struct {
	Conn          net.Conn
	SocketVersion uint8
	IdentMethod   ident.Identifier
}

// NewClient processes new incoming connection
func NewClient(conn net.Conn, idents []ident.Identifier) {
	cli := Client{
		Conn: conn,
	}

	// read the sock version first
	if err := binary.Read(cli.Conn, binary.BigEndian, &cli.SocketVersion); err != nil {
		log.Println(err)
		return
	}

	switch cli.SocketVersion {
	case SOCK4Version: // TODO: impl
		log.Println("not supported yet")
		conn.Close()
		break

	case SOCK5Version:
		// get identity method first
		if err := sock5IdentityMethod(&cli, idents); err != nil {
			log.Println(err)
			conn.Close()
		}

		// identity client
		if err := cli.IdentMethod.Identify(cli.Conn); err != nil {
			log.Println(err)
			conn.Close()
		}

		// getting CONNECT or BIND

	default:
		conn.Close()
		return
	}
}
