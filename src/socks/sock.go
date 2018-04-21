// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"net"
	"encoding/binary"
	"log"
	"errors"
	"sync"
)

const (
	// identical method ids
	SOCK4Version uint8 = 4
	SOCK5Version uint8 = 5

	CMDConnect  uint8 = 1
	CMDBind     uint8 = 2
	CMDSOCK5UDP uint8 = 3

	SOCK5StatusSucceeded           uint8 = 0
	SOCK5StatusSockFailure         uint8 = 1 // general SOCKS server failure
	SOCK5StatusNowAllowed          uint8 = 2 // connection not allowed by ruleset
	SOCK5StatusNetworkUnreachable  uint8 = 3 // Network unreachable
	SOCK5StatusHostUnreachable     uint8 = 4 // Host unreachable
	SOCK5StatusRefused             uint8 = 5 // Connection refused
	SOCK5StatusTTLExpired          uint8 = 6 // TTL expired
	SOCK5StatusNotSupported        uint8 = 7 // Command not supported
	SOCK5StatusAddressNotSupported uint8 = 8 // Address type not supported
)

var errSOCKVersion = errors.New("error sock version")
var errUnsupportedATYP = errors.New("unsupported ATYP")
var errResolvingDomain = errors.New("resolving domain error")

// Client structure represents each connected client
type Client struct {
	Conn          net.Conn
	RemoteConn    net.Conn
	SocketVersion uint8
	IdentMethod   Identifier
}

// NewClient processes new incoming connection
func NewClient(conn net.Conn, idents []Identifier) {
	cli := Client{
		Conn: conn,
	}
	defer conn.Close()

	// read the sock version first
	if err := binary.Read(cli.Conn, binary.BigEndian, &cli.SocketVersion); err != nil {
		log.Println(err)
		return
	}

	// proxyme is only SOCKS5 server
	if cli.SocketVersion != SOCK5Version {
		return
	}

	// get identity method first
	if err := sock5IdentityMethod(&cli, idents); err != nil {
		log.Println(err)
		return
	}

	// identity client
	if err := cli.IdentMethod.Identify(cli.Conn); err != nil {
		log.Println(err)
		return
	}

	// getting request (CONNECT, BIND, UDP assoc)
	var req RequestSOCK5
	if err := req.Read(cli.Conn); err != nil {
		log.Println(err)
		return
	}

	var reply ReplySOCK5

	// processing client request
	switch req.CMD {
	case CMDConnect:
		// connect to remote
		conn, err := net.Dial("tcp", req.Addr.String())
		if err != nil {
			reply.REP = SOCK5StatusSockFailure
			reply.Addr = cli.Conn.LocalAddr().(*net.TCPAddr)

			if nerr, ok := err.(net.Error); ok {
				if nerr.Timeout() {
					reply.REP = SOCK5StatusHostUnreachable
				}
			}

			return
		}
		defer conn.Close()

		// fill bnd addr
		reply.Addr = conn.LocalAddr().(*net.TCPAddr)
		reply.Send(cli.Conn)

		// Start proxy streams with efficient splice kernel method
		spliceStreams(cli.Conn, conn)

	default:
		reply.REP = SOCK5StatusNotSupported
		reply.Send(cli.Conn)
		return
	}
}

// spliceStreams efficient kernel method to transfer data without context switching
// and additional buffering
func spliceStreams(dst net.Conn, src net.Conn) error {

	// getting FD handles
	dstFile, err := dst.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer dstFile.Close()

	srcFile, err := src.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcFD := int(srcFile.Fd())
	dstFD := int(dstFile.Fd())

	var (
		err1, err2         error
		wg sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		err1 = Splice(dstFD, srcFD)
		wg.Done()
	}()
	go func() {
		err2 = Splice(srcFD, dstFD)
		wg.Done()
	}()

	wg.Wait()

	if err1 != nil {
		return err1
	}

	return err2
}
