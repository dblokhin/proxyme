package proxyme

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// as defined http://www.ietf.org/rfc/rfc1928.txt

const (
	protoVersion uint8 = 5
	subnVersion  uint8 = 1
)

// authentication methods
type authMethod uint8

const (
	typeNoAuth authMethod = 0
	typeGSSAPI authMethod = 1
	typeLogin  authMethod = 2
	typeError  authMethod = 0xff
)

// address types based on RFC (atyp)
type addressType uint8

const (
	ipv4       addressType = 1
	domainName addressType = 3
	ipv6       addressType = 4
)

// protocol commands
type commandType uint8

const (
	connect  commandType = 1
	bind     commandType = 2
	udpAssoc commandType = 3
)

type commandStatus uint8

const (
	succeeded           commandStatus = 0
	sockFailure         commandStatus = 1 // general SOCKS server failure
	nowAllowed          commandStatus = 2 // connection not allowed by ruleset
	networkUnreachable  commandStatus = 3 // Network unreachable
	hostUnreachable     commandStatus = 4 // Host unreachable
	refused             commandStatus = 5 // Connection refused
	ttlExpired          commandStatus = 6 // TTL expired
	notSupported        commandStatus = 7 // Command not supported
	addressNotSupported commandStatus = 8 // Address type not supported
)

type State func(*Client) State

// socks5 implements socks5 protocol
type socks5 struct {
	authMethods map[authMethod]authHandler
	bindIP      net.IP // external address for clients to connect
}

func (s socks5) EnableNoAuth() {
	s.authMethods[typeNoAuth] = noAuth{}
}

func (s socks5) EnableUsernameAuth(fn func([]byte, []byte) error) {
	s.authMethods[typeLogin] = usernameAuth{fn}
}

func (s socks5) EnableGSSAPIAuth() {
	s.authMethods[typeGSSAPI] = gssapiAuth{}
}

// InitState starts protocol negotiation
func (s socks5) InitState(c *Client) State {
	var msg authRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		c.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	if err := msg.validate(); err != nil {
		c.err = err
		return nil
	}

	return s.chooseAuthState(msg)
}

func (s socks5) chooseAuthState(msg authRequest) State {
	return func(c *Client) State {
		for _, code := range msg.methods {
			if method, ok := s.authMethods[code]; ok {
				return s.authState(method)
			}
		}

		return s.errAuthState(msg)
	}
}

func (s socks5) errAuthState(msg authRequest) State {
	return func(c *Client) State {
		reply := authReply{method: typeError}

		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		c.err = fmt.Errorf("unsupported auth methods: %v", msg.methods)

		return nil // stop
	}
}

func (s socks5) authState(method authHandler) State {
	return func(c *Client) State {
		// send chosen auth method
		reply := authReply{method: method.method()}

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

func (s socks5) newCommandState(c *Client) State {
	var msg commandRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		c.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	// validate fields
	if err := msg.validate(); err != nil {
		c.err = err
		return nil
	}

	switch msg.commandType {
	case connect:
		return s.connectState(msg)
	case bind:
		return s.bindState(msg)
	case udpAssoc:
		return s.commandErrorState(msg, notSupported)

	default:
		c.err = fmt.Errorf("unsupported commandMessage: %d", msg.commandType)
		return s.commandErrorState(msg, notSupported)
	}
}

func (s socks5) connectState(msg commandRequest) State {
	return func(c *Client) State {
		conn, err := net.Dial("tcp", msg.canonicalAddr())
		if err != nil {
			c.err = fmt.Errorf("dial: %w", err)
			return s.commandErrorState(msg, hostUnreachable)
		}

		reply := commandReply{
			rep:         succeeded,
			rsv:         0,
			addressType: msg.addressType,
			addr:        msg.addr,
			port:        msg.port,
		}

		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		link(conn, c.conn.(net.Conn))

		return nil
	}
}

func (s socks5) commandErrorState(msg commandRequest, status commandStatus) State {
	reply := commandReply{
		rep:         status,
		rsv:         0,
		addressType: msg.addressType,
		addr:        msg.addr,
		port:        msg.port,
	}

	return func(c *Client) State {
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s socks5) bindState(msg commandRequest) State {
	return func(c *Client) State {
		ls, err := net.Listen("tcp", fmt.Sprintf("%s:0", s.bindIP))
		if err != nil {
			c.err = fmt.Errorf("link listen: %w", err)
			return s.commandErrorState(msg, sockFailure)
		}

		port := uint16(ls.Addr().(*net.TCPAddr).Port)
		ip := ls.Addr().(*net.TCPAddr).IP

		_atyp := ipv4
		if len(ip) != 4 {
			_atyp = ipv6
		}

		reply := commandReply{
			rep:         succeeded,
			rsv:         0,
			addressType: _atyp,
			addr:        s.bindIP,
			port:        port,
		}

		// send first reply
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		conn, err := ls.Accept()
		if err != nil {
			c.err = fmt.Errorf("link accept: %w", err)
			return s.commandErrorState(msg, sockFailure)
		}

		// send first reply (on connect)
		if err := c.WriteMessage(reply); err != nil {
			c.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		link(conn, c.conn.(net.Conn))

		return nil
	}
}

// nolint
func link(dst, src io.ReadWriteCloser) {
	var once sync.Once

	stop := func() {
		once.Do(func() {
			src.Close()
			dst.Close()
		})
	}

	defer stop()

	go func() {
		io.Copy(dst, src)
	}()

	io.Copy(src, dst)
}
