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

// Client structure represents each connected client
type Client struct {
	Conn net.Conn
	SocketVersion int8

}



// NewClient processes new incoming connection
func NewClient(conn net.Conn, idents []ident.Identifier) {
	cli := Client{
		Conn: conn,
	}

	// read the sock version first
	if err := binary.Read(cli.Conn, binary.BigEndian,  &cli.SocketVersion); err != nil {
		log.Println(err)
		return
	}

	switch cli.SocketVersion {
	case 4:	// TODO: impl
		break
	case 5:
		// identity first
		if err := sock5Identity(cli, idents); err != nil {
			log.Println(err)
			conn.Close()
		}

		//

	default:
		conn.Close()
		return
	}
}