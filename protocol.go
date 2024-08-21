package proxyme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
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

// socks5 implements socks5 protocol.
type socks5 struct {
	authMethods   map[authMethod]authHandler
	bindIP        net.IP // external address for BIND command
	connect       func(ctx context.Context, addr string) (io.ReadWriteCloser, error)
	resolveDomain func(ctx context.Context, domain []byte) (net.IP, error)
	timeout       time.Duration
}

// resolveHost parses command request and returns host IP (resolves IP if needed).
func (s socks5) resolveHost(ctx context.Context, msg commandRequest) (net.IP, error) {
	if msg.addressType != domainName {
		return msg.addr, nil
	}

	// domain name: dns resolve
	ip, err := s.resolveDomain(ctx, msg.addr)
	if err != nil {
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	return ip, nil
}

// state is state through the SOCKS5 protocol negotiations.
type state struct {
	opts socks5 // protocol options

	conn    io.ReadWriteCloser // client connection
	methods []authMethod       // proposed authenticate methods by client
	method  authHandler        // accepted authenticate method (handler)
	command commandRequest     // clients command to socks5 server
	status  commandStatus      // server reply/result on command
}

type transition func(*state) (transition, error)

// initial starts protocol negotiation
func initial(state *state) (transition, error) {
	var msg authRequest

	if _, err := msg.ReadFrom(state.conn); err != nil {
		return nil, fmt.Errorf("sock read: %w", err)
	}
	if err := msg.validate(); err != nil {
		return nil, err
	}

	state.methods = msg.methods

	// choose auth method
	for _, code := range state.methods {
		if method, ok := state.opts.authMethods[code]; ok {
			state.method = method
			return authenticate, nil
		}
	}

	return failAuth, nil
}

func failAuth(state *state) (transition, error) {
	// If the selected METHOD is X'FF', none of the methods listed by the
	// client are acceptable, and the client MUST close the connection.
	reply := authReply{method: typeError}

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	// stop
	return nil, fmt.Errorf("unsupported authenticate methods: %v", state.methods)
}

func authenticate(state *state) (transition, error) {
	// send chosen authenticate method
	reply := authReply{method: state.method.method()}

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	// do authentication
	conn, err := state.method.auth(state.conn)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	// Hijacks client conn (reason: protocol flow might consider encapsulation).
	// For example GSSAPI encapsulates the traffic intro gssapi protocol messagestate.opts.
	// Package user can encapsulate traffic into whatever he wants using Connect method.
	state.conn = conn

	return getCommand, nil
}

func getCommand(state *state) (transition, error) {
	var msg commandRequest

	if _, err := msg.ReadFrom(state.conn); err != nil {
		return nil, fmt.Errorf("sock read: %w", err)
	}
	if err := msg.validate(); err != nil {
		return nil, err
	}

	state.command = msg

	switch msg.commandType {
	case connect:
		return runConnect, nil
	case bind:
		if len(state.opts.bindIP) == 0 {
			state.status = notAllowed
			return failCommand, nil
		}
		return runBind, nil
	case udpAssoc:
		state.status = notSupported
		return failCommand, nil

	default:
		state.status = notSupported
		return failCommand, fmt.Errorf("unsupported command: %d", msg.commandType)
	}
}

func runConnect(state *state) (transition, error) {
	ctx, cancel := context.WithTimeout(context.Background(), state.opts.timeout)
	defer cancel()

	// make connect addr
	ip, err := state.opts.resolveHost(ctx, state.command)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) {
			state.status = addressNotSupported
			return failCommand, err
		}
		state.status = hostUnreachable
		return failCommand, err
	}

	// connect
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(state.command.port)))
	conn, err := state.opts.connect(ctx, addr)
	if err != nil {
		switch {
		case errors.Is(err, ErrHostUnreachable):
			state.status = hostUnreachable
		case errors.Is(err, ErrConnectionRefused):
			state.status = refused
		case errors.Is(err, ErrNetworkUnreachable):
			state.status = networkUnreachable
		case errors.Is(err, ErrTTLExpired):
			state.status = ttlExpired
		default:
			state.status = hostUnreachable
		}

		return failCommand, err
	}

	// limited timeouts
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		conn = &tcpConnWithTimeout{
			TCPConn: tcpConn,
			timeout: state.opts.timeout,
		}
	}

	reply := commandReply{
		rep:         succeeded,
		rsv:         0,
		addressType: state.command.addressType,
		addr:        state.command.addr,
		port:        state.command.port,
	}

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	link(conn, state.conn)

	return nil, nil
}

func failCommand(state *state) (transition, error) {
	reply := commandReply{
		rep:         state.status,
		rsv:         0,
		addressType: state.command.addressType,
		addr:        state.command.addr,
		port:        state.command.port,
	}

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	return getCommand, nil
}

func runBind(state *state) (transition, error) {
	// todo move it to hook like connect, elimination bindIP
	ls, err := net.Listen("tcp", fmt.Sprintf("%s:0", state.opts.bindIP))
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("bind: %w", err)
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
		addr:        state.opts.bindIP,
		port:        port,
	}

	// send first reply
	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	conn, err := ls.Accept()
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("link accept: %w", err)
	}

	// send first reply (on connect)
	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	link(conn, state.conn)

	return nil, nil
}

func defaultConnect(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("invalid addr: %q", addr)
	}

	d := net.Dialer{KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.EHOSTUNREACH) {
			return conn, fmt.Errorf("%w: %v", ErrHostUnreachable, err)
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return conn, fmt.Errorf("%w: %v", ErrConnectionRefused, err)
		}
		if errors.Is(err, syscall.ENETUNREACH) {
			return conn, fmt.Errorf("%w: %v", ErrNetworkUnreachable, err)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return conn, fmt.Errorf("%w: %v", ErrTTLExpired, err)
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
		return nil, err
	}

	// ipv4 priority
	for _, ip := range ips {
		if len(ip) == net.IPv4len {
			return ip, nil
		}
	}

	return ips[rand.Intn(len(ips))], nil
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
