package proxyme

import (
	"fmt"
	"io"
	"log/slog"
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
	notAllowed          commandStatus = 2 // connection not allowed by ruleset
	networkUnreachable  commandStatus = 3 // Network unreachable
	hostUnreachable     commandStatus = 4 // Host unreachable
	refused             commandStatus = 5 // Connection refused
	ttlExpired          commandStatus = 6 // TTL expired
	notSupported        commandStatus = 7 // Command not supported
	addressNotSupported commandStatus = 8 // Address type not supported
)

type state func(*client) (state, error)

// socks5 implements socks5 protocol
type socks5 struct {
	authMethods map[authMethod]authHandler
	bindIP      net.IP // external address for BIND command
	connect     func(addr string) (io.ReadWriteCloser, error)
	log         *slog.Logger
}

// initState starts protocol negotiation
func (s socks5) initState(c *client) (state, error) {
	var msg authRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		return nil, fmt.Errorf("sock read: %w", err)
	}

	if err := msg.validate(); err != nil {
		return nil, err
	}

	return s.chooseAuthState(msg), nil
}

func (s socks5) chooseAuthState(msg authRequest) state {
	return func(c *client) (state, error) {
		for _, code := range msg.methods {
			if method, ok := s.authMethods[code]; ok {
				return s.authState(method), nil
			}
		}

		return s.errAuthState(msg), nil
	}
}

func (s socks5) errAuthState(msg authRequest) state {
	return func(c *client) (state, error) {
		reply := authReply{method: typeError}

		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		// stop
		return nil, fmt.Errorf("unsupported auth methods: %v", msg.methods)
	}
}

func (s socks5) authState(method authHandler) state {
	return func(c *client) (state, error) {
		// send chosen auth method
		reply := authReply{method: method.method()}

		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		// do authentication
		conn, err := method.auth(c.conn)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}

		c.upgrade(conn)

		return s.newCommandState, nil
	}
}

func (s socks5) newCommandState(c *client) (state, error) {
	var msg commandRequest

	if _, err := msg.ReadFrom(c.rdr); err != nil {
		return nil, fmt.Errorf("sock read: %w", err)
	}

	// validate fields
	if err := msg.validate(); err != nil {
		return nil, err
	}

	switch msg.commandType {
	case connect:
		return s.connectState(msg), nil
	case bind:
		if len(s.bindIP) == 0 {
			return s.commandErrorState(msg, notAllowed), nil
		}
		return s.bindState(msg), nil
	case udpAssoc:
		return s.commandErrorState(msg, notSupported), nil

	default:
		return s.commandErrorState(msg, notSupported), fmt.Errorf("unsupported commandMessage: %d", msg.commandType)
	}
}

func (s socks5) connectState(msg commandRequest) state {
	return func(c *client) (state, error) {
		conn, err := s.connect(msg.canonicalAddr())
		if err != nil {
			return s.commandErrorState(msg, hostUnreachable), fmt.Errorf("dial: %w", err)
		}

		reply := commandReply{
			rep:         succeeded,
			rsv:         0,
			addressType: msg.addressType,
			addr:        msg.addr,
			port:        msg.port,
		}

		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		link(conn, c.conn)

		return nil, nil
	}
}

func (s socks5) commandErrorState(msg commandRequest, status commandStatus) state {
	reply := commandReply{
		rep:         status,
		rsv:         0,
		addressType: msg.addressType,
		addr:        msg.addr,
		port:        msg.port,
	}

	return func(c *client) (state, error) {
		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		return s.newCommandState, nil
	}
}

func (s socks5) bindState(msg commandRequest) state {
	return func(c *client) (state, error) {
		ls, err := net.Listen("tcp", fmt.Sprintf("%s:0", s.bindIP))
		if err != nil {
			return s.commandErrorState(msg, sockFailure), fmt.Errorf("bind: %w", err)
		}

		port := uint16(ls.Addr().(*net.TCPAddr).Port)
		ip := ls.Addr().(*net.TCPAddr).IP

		addrType := ipv4
		if len(ip) != 4 {
			addrType = ipv6
		}

		reply := commandReply{
			rep:         succeeded,
			rsv:         0,
			addressType: addrType,
			addr:        s.bindIP,
			port:        port,
		}

		// send first reply
		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		conn, err := ls.Accept()
		if err != nil {
			return s.commandErrorState(msg, sockFailure), fmt.Errorf("link accept: %w", err)
		}

		// send first reply (on connect)
		if err := c.writeMessage(reply); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		link(conn, c.conn.(net.Conn))

		return nil, nil
	}
}

func defaultConnect(addr string) (io.ReadWriteCloser, error) {
	return net.Dial("tcp", addr)
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

	go func() {
		defer stop()
		io.Copy(dst, src)
	}()

	defer stop()
	io.Copy(src, dst)
}
