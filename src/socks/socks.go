// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

// package socks implements SOCKS5 protocol based on RFC: http://www.ietf.org/rfc/rfc1928.txt
package socks

import (
	"net"
	"encoding/binary"
	"log"
	"errors"
	"io"
)

const (
	// Protocol versions. Supported only SOCKS5
	SOCK4Version uint8 = 4
	SOCK5Version uint8 = 5

	// Clients CMD
	CMDConnect  uint8 = 1
	CMDBind     uint8 = 2
	CMDUDPAssoc uint8 = 3

	// Reply status based on RFC
	StatusSucceeded           uint8 = 0
	StatusSockFailure         uint8 = 1 // general SOCKS server failure
	StatusNowAllowed          uint8 = 2 // connection not allowed by ruleset
	StatusNetworkUnreachable  uint8 = 3 // Network unreachable
	StatusHostUnreachable     uint8 = 4 // Host unreachable
	StatusRefused             uint8 = 5 // Connection refused
	StatusTTLExpired          uint8 = 6 // TTL expired
	StatusNotSupported        uint8 = 7 // Command not supported
	StatusAddressNotSupported uint8 = 8 // Address type not supported

	// address types based on RFC
	ATYPIpv4       uint8 = 1
	ATYPDomainName uint8 = 3
	ATYPIpv6       uint8 = 4
)

var (
	errSOCKVersion = errors.New("error sock version")
	errUnsupportedATYP = errors.New("unsupported ATYP")
	errResolvingDomain = errors.New("resolving domain error")
)

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
			reply.REP = StatusSockFailure
			reply.Addr = cli.Conn.LocalAddr().(*net.TCPAddr)

			if nerr, ok := err.(net.Error); ok {
				if nerr.Timeout() {
					reply.REP = StatusHostUnreachable
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
		reply.REP = StatusNotSupported
		reply.Send(cli.Conn)
		return
	}
}

// sock5IdentityMethod gets client ident methods & select one
func sock5IdentityMethod(client *Client, approved []Identifier) error {

	// read the first message
	var request identRequest
	if err := request.Read(client.Conn); err != nil {
		return err
	}

	// determine ident method
	var determined bool
check:
	for _, methodID := range request.Methods {
		for _, identMethod := range approved {

			if identMethod.ID() == methodID {
				client.IdentMethod = identMethod
				determined = true
				break check
			}
		}
	}

	var resp identResp
	if !determined {
		// send error no ident to client
		resp.ID = IdentError
		return errors.New("no selected ident method")
	}

	// send selected method
	resp.ID = client.IdentMethod.ID()
	return resp.Send(client.Conn)
}

// identRequest is the first message from sock5 client
// represents identifier/method selection message
type identRequest struct {
	NMethods uint8
	Methods  []uint8
}

// Read sock5 identifier/method selection message
func (h *identRequest) Read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &h.NMethods); err != nil {
		return err
	}

	h.Methods = make([]uint8, h.NMethods)
	for i := 0; i < int(h.NMethods); i++ {
		if err := binary.Read(r, binary.BigEndian, &h.Methods[i]); err != nil {
			return err
		}
	}

	return nil
}

// identResp responce structure on requesting iden method
type identResp struct {
	ID uint8
}

// Send response to client
func (m *identResp) Send(w io.Writer) error {
	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, SOCK5Version); err != nil {
		return err
	}

	// write method ID
	if err := binary.Write(w, binary.BigEndian, m.ID); err != nil {
		return err
	}

	return nil
}

// Request SOCK5 request as described in rfc1928
type RequestSOCK5 struct {
	// Ver protocol version
	Ver  uint8 // MUST BE 5
	CMD  uint8
	RSV  uint8 // MUST BE 0
	ATYP uint8
	// Addr dest address (ipv4, v6 or domain name)
	Addr *net.TCPAddr
}

// Read the client request
func (req *RequestSOCK5) Read(r io.Reader) error {
	var err error

	if err = binary.Read(r, binary.BigEndian, &req.Ver); err != nil {
		return err
	}

	// check MUST BE
	if req.Ver != SOCK5Version {
		return errSOCKVersion
	}

	// Read CMD and others
	if err = binary.Read(r, binary.BigEndian, &req.CMD); err != nil {
		return err
	}

	if err = binary.Read(r, binary.BigEndian, &req.RSV); err != nil {
		return err
	}

	if err = binary.Read(r, binary.BigEndian, &req.ATYP); err != nil {
		return err
	}

	// read DST ADDR
	req.Addr, err = readAddr(r, req.ATYP)
	return err
}

func readAddr(r io.Reader, ATYP uint8) (*net.TCPAddr, error) {
	var IPAddr []byte
	var port uint16

	switch ATYP {
	case ATYPIpv4, ATYPIpv6:

		IPlen := net.IPv4len
		if ATYP == ATYPIpv6 {
			IPlen = net.IPv6len
		}

		IPAddr = make([]byte, IPlen)
		if _, err := io.ReadFull(r, IPAddr); err != nil {
			return nil, err
		}

	case ATYPDomainName:
		// Read the domain
		var domainLen uint8
		if err := binary.Read(r, binary.BigEndian, &domainLen); err != nil {
			return nil, err
		}

		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, err
		}

		// resolving domain
		IPs, err := net.LookupIP(string(domain))
		if err != nil {
			return nil, err
		}

		if len(IPs) < 1 {
			return nil, errResolvingDomain
		}

		IPAddr = IPs[0]

	default:
		return nil, errUnsupportedATYP
	}

	// read port
	if err := binary.Read(r, binary.BigEndian, &port); err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   IPAddr,
		Port: int(port),
	}, nil
}

type ReplySOCK5 struct {
	// Ver protocol version
	REP  uint8
	RSV  uint8 // MUST BE 0
	ATYP uint8

	//	server bound address (server ip & port in connection with remote host)
	Addr *net.TCPAddr
}

func (r ReplySOCK5) Send(w io.Writer) error {

	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, SOCK5Version); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, r.REP); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, r.RSV); err != nil {
		return err
	}

	if isIPv4(r.Addr.IP) {
		r.ATYP = ATYPIpv4
	} else {
		r.ATYP = ATYPIpv6
	}

	if err := binary.Write(w, binary.BigEndian, r.ATYP); err != nil {
		return err
	}

	if isIPv4(r.Addr.IP) {
		if _, err := w.Write(r.Addr.IP.To4()); err != nil {
			return err
		}
	} else {
		if _, err := w.Write(r.Addr.IP.To16()); err != nil {
			return err
		}
	}

	if err := binary.Write(w, binary.BigEndian, uint16(r.Addr.Port)); err != nil {
		return err
	}

	return nil
}

// isIPv4 returns true if ip is ipv4
func isIPv4(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil
}
