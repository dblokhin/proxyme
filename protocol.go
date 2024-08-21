package proxyme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

var (
	ErrHostUnreachable    = errors.New("host unreachable")
	ErrNetworkUnreachable = errors.New("network unreachable")
	ErrConnectionRefused  = errors.New("connection refused")
	ErrTTLExpired         = errors.New("ttl expired")
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

type state func(*io.ReadWriteCloser) (state, error)

// socks5 implements socks5 protocol
type socks5 struct {
	authMethods   map[authMethod]authHandler
	bindIP        net.IP // external address for BIND command
	connect       func(ctx context.Context, addr string) (io.ReadWriteCloser, error)
	resolveDomain func(ctx context.Context, domain []byte) (net.IP, error)
	timeout       time.Duration
}

// initState starts protocol negotiation
func (s socks5) initState(c *io.ReadWriteCloser) (state, error) {
	var msg authRequest

	if _, err := msg.ReadFrom(*c); err != nil {
		return nil, fmt.Errorf("sock read: %w", err)
	}

	if err := msg.validate(); err != nil {
		return nil, err
	}

	return s.chooseAuthState(msg), nil
}

func (s socks5) chooseAuthState(msg authRequest) state {
	return func(c *io.ReadWriteCloser) (state, error) {
		for _, code := range msg.methods {
			if method, ok := s.authMethods[code]; ok {
				return s.authState(method), nil
			}
		}

		return s.errAuthState(msg), nil
	}
}

func (s socks5) errAuthState(msg authRequest) state {
	return func(c *io.ReadWriteCloser) (state, error) {
		reply := authReply{method: typeError}

		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		// stop
		return nil, fmt.Errorf("unsupported auth methods: %v", msg.methods)
	}
}

func (s socks5) authState(method authHandler) state {
	return func(c *io.ReadWriteCloser) (state, error) {
		// send chosen auth method
		reply := authReply{method: method.method()}

		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		// do authentication
		conn, err := method.auth(*c)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}

		// Hijacks client conn (reason: protocol flow might consider encapsulation).
		// For example GSSAPI encapsulates the traffic intro gssapi protocol messages.
		// Package user can encapsulate traffic into whatever he wants using Connect method.
		*c = conn

		return s.newCommandState, nil
	}
}

func (s socks5) newCommandState(c *io.ReadWriteCloser) (state, error) {
	var msg commandRequest

	if _, err := msg.ReadFrom(*c); err != nil {
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
	return func(c *io.ReadWriteCloser) (state, error) {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()

		// make connect addr
		addr, err := s.parseAddr(ctx, msg)
		if err != nil {
			var addrErr *net.AddrError
			if errors.As(err, &addrErr) {
				return s.commandErrorState(msg, addressNotSupported), err
			}
			return s.commandErrorState(msg, hostUnreachable), err
		}

		// connect
		conn, err := s.connect(ctx, addr)
		if err != nil {
			var status commandStatus
			switch {
			case errors.Is(err, ErrHostUnreachable):
				status = hostUnreachable
			case errors.Is(err, ErrConnectionRefused):
				status = refused
			case errors.Is(err, ErrNetworkUnreachable):
				status = networkUnreachable
			case errors.Is(err, ErrTTLExpired):
				status = ttlExpired
			default:
				status = hostUnreachable
			}

			return s.commandErrorState(msg, status), err
		}

		// limited timeouts
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			conn = &tcpConnWithTimeout{
				TCPConn: tcpConn,
				timeout: s.timeout,
			}
		}

		reply := commandReply{
			rep:         succeeded,
			rsv:         0,
			addressType: msg.addressType,
			addr:        msg.addr,
			port:        msg.port,
		}

		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		link(conn, *c)

		return nil, nil
	}
}

// parseAddr parses command request and returns connection string in "host:port" format
func (s socks5) parseAddr(ctx context.Context, msg commandRequest) (string, error) {
	if msg.addressType != domainName {
		return fmt.Sprintf("%s:%d", net.IP(msg.addr), msg.port), nil
	}

	// domain name: dns resolve
	ip, err := s.resolveDomain(ctx, msg.addr)
	if err != nil {
		return "", fmt.Errorf("resolve domain: %w", err)
	}

	return fmt.Sprintf("%s:%d", ip, msg.port), nil
}

func (s socks5) commandErrorState(msg commandRequest, status commandStatus) state {
	reply := commandReply{
		rep:         status,
		rsv:         0,
		addressType: msg.addressType,
		addr:        msg.addr,
		port:        msg.port,
	}

	return func(c *io.ReadWriteCloser) (state, error) {
		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		return s.newCommandState, nil
	}
}

func (s socks5) bindState(msg commandRequest) state {
	return func(c *io.ReadWriteCloser) (state, error) {
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
		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		conn, err := ls.Accept()
		if err != nil {
			return s.commandErrorState(msg, sockFailure), fmt.Errorf("link accept: %w", err)
		}

		// send first reply (on connect)
		if _, err := reply.WriteTo(*c); err != nil {
			return nil, fmt.Errorf("sock write: %w", err)
		}

		link(conn, *c)

		return nil, nil
	}
}

func defaultConnect(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	d := net.Dialer{KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.EHOSTUNREACH) {
			return conn, ErrHostUnreachable
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return conn, ErrConnectionRefused
		}
		if errors.Is(err, syscall.ENETUNREACH) {
			return conn, ErrNetworkUnreachable
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return conn, ErrTTLExpired
		}
		return conn, err
	}

	_ = conn.(*net.TCPConn).SetKeepAlive(false) // nolint
	_ = conn.(*net.TCPConn).SetLinger(0)        // nolint

	return conn, nil
}

func defaultDomainResolver(ctx context.Context, domain []byte) (net.IP, error) {
	ips, err := defaultResolver.LookupIP(ctx, "ip", string(domain))
	if err != nil {
		return net.IP{}, err
	}

	return ips[0], nil
}

// nolint
func link(dst, src io.ReadWriteCloser) {
	var once sync.Once

	stop := func() {
		once.Do(func() {
			_ = src.Close() // nolint
			_ = dst.Close() // nolint
		})
	}

	go func() {
		defer stop()
		_, _ = io.Copy(dst, src) // nolint
	}()

	defer stop()
	_, _ = io.Copy(src, dst) // nolint
}
