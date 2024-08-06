package protocol

import (
	"fmt"
	"net"
)

// as defined http://www.ietf.org/rfc/rfc1928.txt

const (
	protoVersion          uint8 = 5
	subnegotiationVersion uint8 = 1
)

// address types based on RFC
const (
	atypIpv4       uint8 = 1
	atypDomainName uint8 = 3
	atypIpv6       uint8 = 4
)

// protocol commands
const (
	cmdConnect  uint8 = 1
	cmdBind     uint8 = 2
	cmdUDPAssoc uint8 = 3
)

const (
	commandStatusSucceeded           uint8 = 0
	commandStatusSockFailure         uint8 = 1 // general SOCKS server failure
	commandStatusNowAllowed          uint8 = 2 // connection not allowed by ruleset
	commandStatusNetworkUnreachable  uint8 = 3 // Network unreachable
	commandStatusHostUnreachable     uint8 = 4 // Host unreachable
	commandStatusRefused             uint8 = 5 // Connection refused
	commandStatusTTLExpired          uint8 = 6 // TTL expired
	commandStatusNotSupported        uint8 = 7 // Command not supported
	commandStatusAddressNotSupported uint8 = 8 // Address type not supported
)

type State func(*Client) State

// Sock5 implements Sock5 protocol
type Sock5 struct {
	authMethods map[uint8]authHandler
	ExternalIP  net.IP // external address for clients to connect
}

func New(externalIP net.IP) Sock5 {
	return Sock5{
		authMethods: make(map[uint8]authHandler),
		ExternalIP:  externalIP,
	}
}

func (s Sock5) EnableNoAuth() {
	s.authMethods[authTypeNoAuth] = noAuth{}
}

func (s Sock5) EnableUsernameAuth(fn func([]byte, []byte) error) {
	s.authMethods[authTypeLogin] = usernameAuth{fn}
}

func (s Sock5) EnableGSSAPIAuth() {
	s.authMethods[authTypeGSSAPI] = gssapiAuth{}
}

// InitState starts protocol negotiation
func (s Sock5) InitState(c *Client) State {
	var msg AuthRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		c.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	// check version: is only SOCKS5 server
	if err := validateProtocolVersion(msg.Version); err != nil {
		c.err = err
		return nil
	}

	return s.chooseAuthState(msg)
}

func (s Sock5) chooseAuthState(msg AuthRequest) State {
	return func(c *Client) State {
		for _, code := range msg.Methods {
			if method, ok := s.authMethods[code]; ok {
				return s.authState(method)
			}
		}

		return s.errAuthState(msg)
	}
}

func (s Sock5) errAuthState(msg AuthRequest) State {
	return func(c *Client) State {
		reply := AuthReply{Method: authTypeError}

		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		c.err = fmt.Errorf("client sent unsupported auth methods: %v", msg.Methods)

		return nil // stop
	}
}

func (s Sock5) authState(method authHandler) State {
	return func(c *Client) State {
		// send chosen auth method
		reply := AuthReply{Method: method.methodID()}

		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		// do authentication
		conn, err := method.auth(c.conn)
		if err != nil {
			c.err = fmt.Errorf("auth: %w", err)
			return nil
		}

		c.Upgrade(conn)

		return s.newCommandState
	}
}

func (s Sock5) newCommandState(c *Client) State {
	var msg CommandRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		c.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	// validate fields
	if err := validateProtocolVersion(msg.Version); err != nil {
		c.err = err
		return nil
	}

	switch msg.Cmd {
	case cmdConnect:
		return s.connectState(msg)
	case cmdBind:
		return s.bindState(msg)
	case cmdUDPAssoc:
		return s.commandErrorState(msg, commandStatusNotSupported)

	default:
		c.err = fmt.Errorf("client sent unsupported commandMessage: %d", msg.Cmd)
		return s.commandErrorState(msg, commandStatusNotSupported)
	}
}

func (s Sock5) connectState(msg CommandRequest) State {
	return func(c *Client) State {
		conn, err := net.Dial("tcp", msg.CanonicalAddr())
		if err != nil {
			c.err = fmt.Errorf("dial: %w", err)
			return s.commandErrorState(msg, commandStatusHostUnreachable)
		}

		reply := CommandReply{
			Rep:  commandStatusSucceeded,
			Rsv:  0,
			Atyp: msg.Atyp,
			Addr: msg.Addr,
			Port: msg.Port,
		}

		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		bind(conn, c.conn.(net.Conn))

		return nil
	}
}

func (s Sock5) commandErrorState(msg CommandRequest, status uint8) State {
	reply := CommandReply{
		Rep:  status,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(c *Client) State {
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s Sock5) bindState(msg CommandRequest) State {
	return func(c *Client) State {
		ls, err := net.Listen("tcp", fmt.Sprintf("%s:0", s.ExternalIP))
		if err != nil {
			c.err = fmt.Errorf("bind listen: %w", err)
			return s.commandErrorState(msg, commandStatusSockFailure)
		}

		port := uint16(ls.Addr().(*net.TCPAddr).Port)
		ip := ls.Addr().(*net.TCPAddr).IP

		atyp := atypIpv4
		if len(ip) != 4 {
			atyp = atypIpv6
		}

		reply := CommandReply{
			Rep:  commandStatusSucceeded,
			Rsv:  0,
			Atyp: atyp,
			Addr: s.ExternalIP,
			Port: port,
		}

		// send first reply
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		conn, err := ls.Accept()
		if err != nil {
			c.err = fmt.Errorf("bind accept: %w", err)
			return s.commandErrorState(msg, commandStatusSockFailure)
		}

		// send first reply (on connect)
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		bind(conn, c.conn.(net.Conn))

		return nil
	}
}

func validateProtocolVersion(version uint8) error {
	if version != protoVersion {
		return fmt.Errorf("client sent unsupported version: %d", version)
	}

	return nil
}
