package protocol

import (
	"fmt"
	"net"
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
	s.authMethods[identNoAuth] = noAuth{}
}

func (s Sock5) EnableUsernameAuth(fn func(string, string) error) {
	s.authMethods[identLogin] = usernameAuth{fn}
}

func (s Sock5) EnableGSSAPIAuth() {
	s.authMethods[identGSSAPI] = gssapiAuth{}
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
		reply := AuthReply{Method: identError}

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

		// make authenticity
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
		return s.commandErrorState(msg, replyStatusNotSupported)

	default:
		c.err = fmt.Errorf("client sent unsupported commandMessage: %d", msg.Cmd)
		return s.commandErrorState(msg, replyStatusNotSupported)
	}
}

func (s Sock5) connectState(msg CommandRequest) State {
	return func(c *Client) State {
		conn, err := net.Dial("tcp", msg.CanonicalAddr())
		if err != nil {
			c.err = fmt.Errorf("dial: %w", err)
			return s.commandErrorState(msg, replyStatusHostUnreachable)
		}

		reply := CommandReply{
			Rep:  replyStatusSucceeded,
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
			return s.commandErrorState(msg, replyStatusSockFailure)
		}

		port := uint16(ls.Addr().(*net.TCPAddr).Port)
		ip := ls.Addr().(*net.TCPAddr).IP

		atyp := atypIpv4
		if len(ip) != 4 {
			atyp = atypIpv6
		}

		reply := CommandReply{
			Rep:  replyStatusSucceeded,
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
			return s.commandErrorState(msg, replyStatusSockFailure)
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
