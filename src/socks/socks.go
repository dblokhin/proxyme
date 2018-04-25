// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

// package socks implements SOCKS5 protocol based on RFC: http://www.ietf.org/rfc/rfc1928.txt
package socks

import (
	"net"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// Protocol versions. Supported only SOCKS5
	SOCKS4Version  uint8 = 4
	SOCKS5Version uint8 = 5

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
	errSOCKSVersion    = errors.New("invalid socks version")
	errNoIdentity = errors.New("unsupported client idents")
	errUnsupportedATYP = errors.New("unsupported ATYP")
	errResolvingDomain = errors.New("resolving domain error")
)

// Client structure represents each connected client
type Client struct {
	Conn       net.Conn
	RemoteConn net.Conn

	// Socks version
	version         uint8
	supportedIdents []uint8
	identifier      Identifier
}

// NewClient creates new socks5 identified client for creating proxy window
func NewClient(conn net.Conn, serverIdents []Identifier) (*Client, error) {
	client := &Client{
		Conn: conn,
	}

	// init state
	if err := client.Init(); err != nil {
		return nil, err
	}

	// Identify procedure
	if err := client.GetIdentities(); err != nil {
		return nil, err
	}

	if err := client.SelectIdentity(serverIdents); err != nil {
		return nil, err
	}

	// Identify client
	if err := client.Identify(); err != nil {
		return nil, err
	}

	return client, nil
}

// Init checks client conn
func (cli *Client) Init() error {
	// read the socks version first
	if err := binary.Read(cli.Conn, binary.BigEndian, &cli.version); err != nil {
		return err
	}

	// Check version. Proxyme is only SOCKS5 server
	if cli.version != SOCKS5Version {
		return errSOCKSVersion
	}

	return nil
}

// GetIdentities gets client ident methods & select one
func (cli *Client) GetIdentities() error {
	var (
		count uint8
	)

	// read count of methods
	if err := binary.Read(cli.Conn, binary.BigEndian, &count); err != nil {
		return err
	}

	// read methods
	methods := make([]uint8, count)
	for i := 0; i < int(count); i++ {
		if err := binary.Read(cli.Conn, binary.BigEndian, &methods[i]); err != nil {
			return err
		}
	}

	cli.supportedIdents = methods
	return nil
}

// SelectIdentity selects common identity method
func (cli *Client) SelectIdentity(serverIdents []Identifier) error {
	var determined bool

	// determine identifier method

check:
	for _, clientMethodID := range cli.supportedIdents {
		for _, srvMethod := range serverIdents {

			if srvMethod.ID() == clientMethodID {
				cli.identifier = srvMethod
				determined = true
				break check
			}
		}
	}

	// prepare response
	var resp identResp
	if !determined {
		resp.ID = IdentError

	} else {
		resp.ID = cli.identifier.ID()
	}

	if err := resp.Send(cli.Conn); err != nil {
		return err
	}

	if !determined {
		return errNoIdentity
	}

	return nil
}

// Identify identifies client with chosen method
func (cli *Client) Identify() error {
	return cli.identifier.Identify(cli.Conn)
}

// RunCMD reads client cmd & runs it
func (cli *Client) RunCMD() error {
	defer cli.Conn.Close()

	// read request (CONNECT, BIND, UDP assoc)
	var req requestCMD
	if err := req.Read(cli.Conn); err != nil {
		return err
	}

	// prepare reply
	var reply replyCMD

	// processing client request
	switch req.CMD {
	case CMDConnect:
		// connect to remote
		RemoteConn, err := net.Dial("tcp", req.Addr.String())
		if err != nil {
			reply.REP = StatusSockFailure
			reply.Addr = cli.Conn.LocalAddr().(*net.TCPAddr)

			if nerr, ok := err.(net.Error); ok {
				if nerr.Timeout() {
					reply.REP = StatusHostUnreachable
				}
			}

			// send error code to client
			if err := reply.Send(cli.Conn); err != nil {
				return err
			}

			return err
		}
		defer RemoteConn.Close()
		cli.RemoteConn = RemoteConn

		// fill bnd addr
		reply.Addr = RemoteConn.LocalAddr().(*net.TCPAddr)
		if err := reply.Send(cli.Conn); err != nil {
			return err
		}

		// Start proxy streams with efficient splice kernel method
		return spliceStreams(cli.Conn, RemoteConn)

	default:
		reply.REP = StatusNotSupported
		reply.Send(cli.Conn)
		return nil
	}

	// never rich
	return nil
}

// Close destroys client, connections and other active resources
func (cli *Client) Close() {
	cli.Conn.Close()
	if cli.RemoteConn != nil {
		cli.RemoteConn.Close()
	}
}

// identResp response structure on requesting identity method
type identResp struct {
	ID uint8
}

// Send response to client
func (m *identResp) Send(w io.Writer) error {
	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, SOCKS5Version); err != nil {
		return err
	}

	// write method ID
	if err := binary.Write(w, binary.BigEndian, m.ID); err != nil {
		return err
	}

	return nil
}

// requestCMD SOCKS5 request as described in rfc1928
type requestCMD struct {
	// Ver protocol version
	Ver  uint8 // MUST BE 5
	CMD  uint8
	RSV  uint8 // MUST BE 0
	ATYP uint8

	// Addr dest address (ipv4, v6 or domain name)
	Addr *net.TCPAddr
}

// Read the client request
func (req *requestCMD) Read(r io.Reader) error {
	var err error

	if err = binary.Read(r, binary.BigEndian, &req.Ver); err != nil {
		return err
	}

	// check MUST BE
	if req.Ver != SOCKS5Version {
		return errSOCKSVersion
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

type replyCMD struct {
	// Ver protocol version
	REP  uint8
	RSV  uint8 // MUST BE 0
	ATYP uint8

	//	server bound address (server ip & port in connection with remote host)
	Addr *net.TCPAddr
}

func (r replyCMD) Send(w io.Writer) error {

	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, SOCKS5Version); err != nil {
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
