package proxyme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

var (
	ErrHostUnreachable    = errors.New("host unreachable")
	ErrNetworkUnreachable = errors.New("network unreachable")
	ErrNotAllowed         = errors.New("not allowed by ruleset")
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
	authMethods map[authMethod]authHandler
	bind        func() (net.Listener, error) // bind for BIND command
	connect     func(ctx context.Context, addressType int, addr []byte, port string) (io.ReadWriteCloser, error)
	timeout     time.Duration
}

// state is state through the SOCKS5 protocol negotiations.
type state struct {
	opts socks5 // protocol options

	conn    io.ReadWriteCloser // client connection
	methods []authMethod       // proposed authenticate methods by client
	method  authHandler        // chosen authenticate method (handler)
	command commandRequest     // clients validated command to socks5 server
	status  commandStatus      // server reply/result on command
}

type transition func(*state) (transition, error)

// TODO: check all behind protocol behaves just close connection
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
	// For example GSSAPI encapsulates the traffic intro gssapi protocol messages.
	// Package user can encapsulate traffic into whatever he wants using Connect method.
	state.conn = conn

	return getCommand, nil
}

func getCommand(state *state) (transition, error) {
	var msg commandRequest

	if _, err := msg.ReadFrom(state.conn); err != nil {
		// ReadFrom can return errInvalidAddrType:
		// we stop reading tcp input stream when encounter invalid address type,
		// because don't know how to parse payload.
		// that's why we need to close connection (return nil transition).

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
		return runBind, nil
	case udpAssoc:
		return runUDPAssoc, nil

	default:
		state.status = notSupported
		return failCommand, fmt.Errorf("unsupported command: %d", msg.commandType)
	}
}

func runBind(state *state) (transition, error) {
	if state.opts.bind == nil {
		state.status = notAllowed
		return failCommand, nil
	}
	return defaultBind, nil
}

func runUDPAssoc(state *state) (transition, error) {
	state.status = notSupported
	return failCommand, nil
}

func runConnect(state *state) (transition, error) {
	ctx, cancel := context.WithTimeout(context.Background(), state.opts.timeout)
	defer cancel()

	// connect
	addrType := int(state.command.addressType) //nolint
	addr := state.command.addr
	port := strconv.Itoa(int(state.command.port))

	conn, err := state.opts.connect(ctx, addrType, addr, port)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotAllowed):
			state.status = notAllowed
		case errors.Is(err, ErrHostUnreachable):
			state.status = hostUnreachable
		case errors.Is(err, ErrConnectionRefused):
			state.status = refused
		case errors.Is(err, ErrNetworkUnreachable):
			state.status = networkUnreachable
		case errors.Is(err, ErrTTLExpired):
			state.status = ttlExpired
		default:
			state.status = sockFailure
		}

		return failCommand, err
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

	// When a reply (REP value other than X'00') indicates a failure, the
	// SOCKS server MUST terminate the TCP connection shortly after sending
	// the reply.  This must be no more than 10 seconds after detecting the
	// condition that caused a failure.

	return nil, nil
}

func parseAddr(addr net.Addr) (net.IP, int, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid host %q", host)
	}

	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p >= 1<<16 {
		return nil, 0, fmt.Errorf("invalid port %q", port)
	}

	return ip, p, nil
}

func defaultBind(state *state) (transition, error) {
	ls, err := state.opts.bind()
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("bind bind: %w", err)
	}
	defer ls.Close() // nolint

	ip, port, err := parseAddr(ls.Addr())
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("bind addr: %w", err)
	}

	addrType := ipv4
	if len(ip) != net.IPv4len {
		addrType = ipv6
	}
	// send first reply
	reply := commandReply{
		rep:         succeeded,
		rsv:         0,
		addressType: addrType,
		addr:        ip,
		port:        uint16(port), // nolint
	}

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	// accept connection
	conn, err := ls.Accept()
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("bind accept: %w", err)
	}

	// parse remote addr
	ip, _, err = parseAddr(conn.RemoteAddr())
	if err != nil {
		state.status = sockFailure
		return failCommand, fmt.Errorf("bind remote addr: %w", err)
	}

	addrType = ipv4
	if len(ip) != net.IPv4len {
		addrType = ipv6
	}
	// send second reply (on connect)
	reply.addressType = addrType
	reply.addr = ip

	if _, err := reply.WriteTo(state.conn); err != nil {
		return nil, fmt.Errorf("sock write: %w", err)
	}

	link(conn, state.conn)

	return nil, nil
}

func defaultConnect(ctx context.Context, addressType int, addr []byte, port string) (io.ReadWriteCloser, error) {
	// make connection string for net.Dial
	address := buildDialAddress(addressType, addr, port)

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", address)
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

	_ = conn.(*net.TCPConn).SetLinger(0) // nolint

	return conn, nil
}

// buildDialAddress returns address in net.Dial format from socks5 details.
func buildDialAddress(addressType int, addr []byte, port string) string {
	var host string
	if addressType != int(domainName) {
		host = net.IP(addr).String()
	} else {
		host = string(addr)
	}

	return net.JoinHostPort(host, port)
}

// nolint
func link(dst, src io.ReadWriteCloser) {
	go func() {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
	}()

	_, _ = io.Copy(src, dst)
	_ = src.Close()
}
