package proxyme

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"testing"
)

type fakeRWCloser struct {
	fnWrite func(p []byte) (n int, err error)
	fnRead  func(p []byte) (n int, err error)
	fnClose func() error
}

func (f fakeRWCloser) Write(p []byte) (n int, err error) {
	return f.fnWrite(p)
}

func (f fakeRWCloser) Read(p []byte) (n int, err error) {
	return f.fnRead(p)
}

func (f fakeRWCloser) Close() error {
	return f.fnClose()
}

type fakeAuth struct {
	fnMethod func() authMethod
	fnAuth   func(conn io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

func (f fakeAuth) method() authMethod {
	return f.fnMethod()
}

func (f fakeAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	return f.fnAuth(conn)
}

func Test_failAuth(t *testing.T) {
	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(transition, error) error
	}{
		{
			name: "common, with no network error",
			args: args{state: &state{
				conn: &fakeRWCloser{
					fnWrite: func(p []byte) (n int, err error) {
						return len(p), nil
					},
				},
			}},
			check: func(fn transition, err error) error {
				if fn != nil {
					return fmt.Errorf("state must be nil")
				}
				return nil
			},
		},
		{
			name: "network error",
			args: args{state: &state{
				conn: &fakeRWCloser{
					fnWrite: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
				},
			}},
			check: func(fn transition, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected %v, but got %v", io.EOF, err)
				}
				if fn != nil {
					return fmt.Errorf("state must be nil")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := failAuth(tt.args.state)
			if err := tt.check(got, err); err != nil {
				t.Errorf("failAuth() = %v", err)
			}
		})
	}
}

func Test_initial(t *testing.T) {
	noAuthReq := []byte{0x05, 0x01, byte(typeNoAuth)}   // auth request with noauth method
	loginAuthReq := []byte{0x05, 0x01, byte(typeLogin)} // auth request with login method
	invalidAuthReq := []byte{0x05, 0x00}                // auth request with no methods

	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(*state, transition, error) error
	}{
		{
			name: "common auth method (noauth)",
			args: args{
				state: &state{
					opts: SOCKS5{
						auth: map[authMethod]authHandler{
							typeNoAuth: &noAuth{},
						},
					},
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							if len(noAuthReq) == 0 {
								return 0, io.EOF
							}

							n = min(len(p), len(noAuthReq))
							copy(p, noAuthReq[:n])
							noAuthReq = noAuthReq[n:]

							return n, nil
						},
					},
				},
			},
			check: func(state *state, transition transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if transition == nil {
					return fmt.Errorf("unexpected nil transition")
				}
				if !reflect.DeepEqual(state.methods, []authMethod{typeNoAuth}) {
					return fmt.Errorf("got %v, want = %v", state.methods, []authMethod{typeNoAuth})
				}
				if state.method == nil {
					return fmt.Errorf("got nil auth handler")
				}
				if state.method.method() != typeNoAuth {
					return fmt.Errorf("got method %v, want method = %v", state.method.method(), typeNoAuth)
				}

				return nil
			},
		},
		{
			name: "no common auth method",
			args: args{
				state: &state{
					opts: SOCKS5{
						auth: map[authMethod]authHandler{
							typeNoAuth: &noAuth{},
						},
					},
					conn: fakeRWCloser{
						fnWrite: nil,
						fnRead: func(p []byte) (n int, err error) {
							if len(loginAuthReq) == 0 {
								return 0, io.EOF
							}

							n = min(len(p), len(loginAuthReq))
							copy(p, loginAuthReq[:n])
							loginAuthReq = loginAuthReq[n:]

							return n, nil
						},
						fnClose: nil,
					},
				},
			},
			check: func(state *state, transition transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if transition == nil {
					return fmt.Errorf("unexpected nil transition")
				}
				if !reflect.DeepEqual(state.methods, []authMethod{typeLogin}) {
					return fmt.Errorf("got %v, want %v", state.methods, []authMethod{typeLogin})
				}
				if state.method != nil {
					return fmt.Errorf("expected nil auth handler")
				}

				return nil
			},
		},
		{
			name: "invalid auth request",
			args: args{
				state: &state{
					opts: SOCKS5{},
					conn: fakeRWCloser{
						fnWrite: nil,
						fnRead: func(p []byte) (n int, err error) {
							if len(invalidAuthReq) == 0 {
								return 0, io.EOF
							}

							n = min(len(p), len(invalidAuthReq))
							copy(p, invalidAuthReq[:n])
							invalidAuthReq = invalidAuthReq[n:]

							return n, nil
						},
						fnClose: nil,
					},
				},
			},
			check: func(state *state, transition transition, err error) error {
				if err == nil {
					return fmt.Errorf("expected error, but got nil")
				}
				if transition != nil {
					return fmt.Errorf("want nil transition")
				}
				return nil
			},
		},
		{
			name: "network error",
			args: args{
				state: &state{
					opts: SOCKS5{},
					conn: fakeRWCloser{
						fnWrite: nil,
						fnRead: func(p []byte) (n int, err error) {
							return 0, io.EOF
						},
						fnClose: nil,
					},
				},
			},
			check: func(state *state, transition transition, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected error, but got nil")
				}
				if transition != nil {
					return fmt.Errorf("want nil transition")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initial(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("initial() error = %v", err)
				return
			}
		})
	}
}

func Test_authenticate(t *testing.T) {
	hijacked := &fakeRWCloser{}

	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(*state, transition, error) error
	}{
		{
			name: "common noauth flow",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return len(p), nil
						},
					},
					method: fakeAuth{
						fnMethod: func() authMethod {
							return typeNoAuth
						},
						fnAuth: func(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
							return conn, nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %v", err)
				}
				if t == nil {
					return fmt.Errorf("got nil transition")
				}

				return nil
			},
		},
		{
			name: "check hijack connection",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return len(p), nil
						},
					},
					method: fakeAuth{
						fnMethod: func() authMethod {
							return typeNoAuth
						},
						fnAuth: func(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
							return hijacked, nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %v", err)
				}
				if t == nil {
					return fmt.Errorf("got nil transition")
				}
				if s.conn != hijacked {
					return fmt.Errorf("conn is not hijacked")
				}

				return nil
			},
		},
		{
			name: "auth error",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return len(p), nil
						},
					},
					method: fakeAuth{
						fnMethod: func() authMethod {
							return typeGSSAPI
						},
						fnAuth: func(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
							return conn, errors.ErrUnsupported
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, errors.ErrUnsupported) {
					return fmt.Errorf("got error %v, want %v", err, errors.ErrUnsupported)
				}
				if t != nil {
					return fmt.Errorf("expected nil transition")
				}
				return nil
			},
		},
		{
			name: "network error",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return 0, io.ErrUnexpectedEOF
						},
					},
					method: fakeAuth{
						fnMethod: func() authMethod {
							return typeNoAuth
						},
						fnAuth: func(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
							return conn, nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					return fmt.Errorf("got error %v, want %v", err, io.ErrUnexpectedEOF)
				}
				if t != nil {
					return fmt.Errorf("expected nil transition")
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authenticate(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("authenticate() error = %v", err)
				return
			}
		})
	}
}

func Test_getCommand(t *testing.T) {
	port := byte(0x77)
	ip4 := net.ParseIP("192.168.0.1").To4()
	validConnect := bytes.NewReader([]byte{protoVersion, byte(connect), 0x00, byte(ipv4), ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port})
	invalidAddrType := bytes.NewReader([]byte{protoVersion, byte(connect), 0x00, 0x22, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port})
	invalidConnect := bytes.NewReader([]byte{protoVersion + 100, byte(connect), 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port})
	unsupportedCommand := bytes.NewReader([]byte{protoVersion, byte(0x22), 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port})

	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(*state, transition, error) error
	}{
		{
			name: "common command",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return validConnect.Read(p)
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %v", err)
				}
				if t == nil {
					return fmt.Errorf("transition must be non nil")
				}
				if s.command.commandType != connect {
					return fmt.Errorf("got command type %d, want %d", s.command, connect)
				}
				return nil
			},
		},
		{
			name: "unsupported command type",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return unsupportedCommand.Read(p)
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err == nil {
					return fmt.Errorf("expected error but got nil")
				}
				if s.status != notSupported {
					return fmt.Errorf("got command status %d, want %d", s.status, notSupported)
				}
				if t == nil {
					return fmt.Errorf("transition must be non nil")
				}
				return nil
			},
		},
		{
			name: "unsupported address type",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return invalidAddrType.Read(p)
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, errInvalidAddrType) {
					return fmt.Errorf("got %v, want %v", err, errInvalidAddrType)
				}
				if t != nil {
					return fmt.Errorf("want nil transition")
				}
				return nil
			},
		},
		{
			name: "invalid command payload (invalid proto version)",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return invalidConnect.Read(p)
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err == nil {
					return fmt.Errorf("expected error but got nil")
				}
				if t != nil {
					return fmt.Errorf("expected nil transition")
				}
				return nil
			},
		},
		{
			name: "network error",
			args: args{
				state: &state{
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return 0, io.ErrUnexpectedEOF
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					return fmt.Errorf("got error %v, want %v", err, io.ErrUnexpectedEOF)
				}
				if t != nil {
					return fmt.Errorf("expected nil transition")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCommand(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("getCommand() error = %v", err)
				return
			}
		})
	}
}

func Test_failCommand(t *testing.T) {
	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(*state, transition, error) error
	}{
		{
			name: "common case",
			args: args{
				state: &state{
					command: commandRequest{
						version:     5,
						commandType: connect,
						rsv:         0,
						addressType: domainName, // <<- invalid address type
						addr:        []byte("google.com"),
						port:        80,
					},
					status: notAllowed,
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return len(p), nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %v", err)
				}

				if t != nil {
					return fmt.Errorf("want nil transition")
				}

				return nil
			},
		},
		{
			name: "invalid reply message",
			args: args{
				state: &state{
					command: commandRequest{
						version:     5,
						commandType: connect,
						rsv:         0,
						addressType: 18, // <<- invalid address type
						addr:        nil,
						port:        0,
					},
					status: addressNotSupported,
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return len(p), nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, errInvalidAddrType) {
					return fmt.Errorf("got %v, want %v", err, errInvalidAddrType)
				}

				if t != nil {
					return fmt.Errorf("want nil transition")
				}

				return nil
			},
		},
		{
			name: "network error",
			args: args{
				state: &state{
					status: notSupported,
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return 0, io.EOF
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("got %v, want %v", err, io.EOF)
				}

				if t != nil {
					return fmt.Errorf("want nil transition")
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := failCommand(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("failCommand() error = %v", err)
				return
			}
		})
	}
}

func Test_runBind(t *testing.T) {
	type args struct {
		state *state
	}
	tests := []struct {
		name    string
		args    args
		check   func(*state, transition, error) error
		wantErr bool
	}{
		{
			name: "no bind",
			args: args{
				state: &state{},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexcepted error: %w", err)
				}
				if t == nil {
					return fmt.Errorf("got nil transition")
				}
				if s.status != notAllowed {
					return fmt.Errorf("got status %d, want %d", s.status, notAllowed)
				}
				return nil
			},
		},
		{
			name: "yes bind",
			args: args{
				state: &state{
					opts: SOCKS5{
						bind: func() (net.Listener, error) {
							return nil, nil
						},
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexcepted error: %w", err)
				}
				if t == nil {
					return fmt.Errorf("got nil transition")
				}
				if s.status != succeeded {
					return fmt.Errorf("got status %d, want %d", s.status, succeeded)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runBind(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("runBind() error = %v", err)
				return
			}
		})
	}
}

func Test_parseAddress(t *testing.T) {
	ipv4Addr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:7777")
	ipv6Addr, _ := net.ResolveTCPAddr("tcp", "[2001:db8::1]:http")
	ipv4UDPAddr, _ := net.ResolveUDPAddr("tcp", "192.168.1.1:7777")

	type args struct {
		addr net.Addr
	}
	tests := []struct {
		name    string
		args    args
		want    addressType
		want1   net.IP
		want2   int
		wantErr bool
	}{
		{
			name: "non tcp addr",
			args: args{
				addr: ipv4UDPAddr,
			},
			want:    0,
			want1:   nil,
			want2:   0,
			wantErr: true,
		},
		{
			name: "ipv4",
			args: args{
				addr: ipv4Addr,
			},
			want:    ipv4,
			want1:   net.ParseIP("192.168.1.1").To4(),
			want2:   7777,
			wantErr: false,
		},
		{
			name: "ipv6",
			args: args{
				addr: ipv6Addr,
			},
			want:    ipv6,
			want1:   net.ParseIP("2001:db8::1").To16(),
			want2:   80,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, err := parseAddress(tt.args.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseAddress() got = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(got1, tt.want1) {
				t.Errorf("parseAddress() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("parseAddress() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func makeTCPConn() (net.Conn, error) {
	ls, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}
	defer ls.Close()
	go func() {
		_, _ = ls.Accept()
	}()

	return net.Dial("tcp", ls.Addr().String())
}
func Test_runConnect(t *testing.T) {
	ipaddr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:1234")

	validTCPConn, err := makeTCPConn()
	if err != nil {
		t.Fatalf("failed to start tcp server: %v", err)
	}

	resultBuffer := bytes.Buffer{}

	type args struct {
		state *state
	}
	tests := []struct {
		name  string
		args  args
		check func(*state, transition, error) error
	}{
		{
			name: "connect error: not allowed",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							// check that all params are passed well
							if addressType != int(ipv4) {
								return nil, fmt.Errorf("got invalid address type")
							}
							if !bytes.Equal(addr, ipaddr.IP.To4()) {
								return nil, fmt.Errorf("got invalid ip address")
							}
							if port != strconv.Itoa(ipaddr.Port) {
								return nil, fmt.Errorf("got invalid port %q, want %q", port, ipaddr.Port)
							}
							return nil, ErrNotAllowed
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, ErrNotAllowed) {
					return fmt.Errorf("unexpected error: %w, want %w", err, ErrNotAllowed)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != notAllowed {
					return fmt.Errorf("got status %d, want %d", s.status, notAllowed)
				}
				return nil
			},
		},
		{
			name: "connect error: host unreachable",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return nil, ErrHostUnreachable
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, ErrHostUnreachable) {
					return fmt.Errorf("unexpected error: %w, want %w", err, ErrHostUnreachable)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != hostUnreachable {
					return fmt.Errorf("got status %d, want %d", s.status, hostUnreachable)
				}
				return nil
			},
		},
		{
			name: "connect error: connection connectionRefused",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return nil, ErrConnectionRefused
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, ErrConnectionRefused) {
					return fmt.Errorf("unexpected error: %w, want: %w", err, ErrConnectionRefused)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != connectionRefused {
					return fmt.Errorf("got status %d, want %d", s.status, connectionRefused)
				}
				return nil
			},
		},
		{
			name: "connect error: network unreachable",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return nil, ErrNetworkUnreachable
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, ErrNetworkUnreachable) {
					return fmt.Errorf("unexpected error: %w, want: %w", err, ErrNetworkUnreachable)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != networkUnreachable {
					return fmt.Errorf("got status %d, want %d", s.status, networkUnreachable)
				}
				return nil
			},
		},
		{
			name: "connect error: ttl expired",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return nil, ErrTTLExpired
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, ErrTTLExpired) {
					return fmt.Errorf("unexpected error: %w, want: %w", err, ErrTTLExpired)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != ttlExpired {
					return fmt.Errorf("got status %d, want %d", s.status, ttlExpired)
				}
				return nil
			},
		},
		{
			name: "connect error: sock failure",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return nil, io.EOF // any other error
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("unexpected error: %w, want: %w", err, io.EOF)
				}
				if t == nil {
					return fmt.Errorf("got transition nil")
				}
				if s.status != sockFailure {
					return fmt.Errorf("got status %d, want %d", s.status, sockFailure)
				}
				return nil
			},
		},
		{
			name: "non tcp connect",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return &net.UDPConn{}, nil
						},
					},
					conn: nil,
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err == nil {
					return fmt.Errorf("unexpected error but got nil")
				}
				if t != nil {
					return fmt.Errorf("want transition nil")
				}
				return nil
			},
		},
		{
			name: "reply: network error",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return validTCPConn, nil
						},
					},
					conn: fakeRWCloser{
						fnWrite: func(p []byte) (n int, err error) {
							return 0, io.EOF
						},
					},
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("unexpected error: %w, want %w", err, io.EOF)
				}
				if t != nil {
					return fmt.Errorf("want transition nil")
				}
				return nil
			},
		},
		{
			name: "reply success",
			args: args{
				state: &state{
					opts: SOCKS5{
						connect: func(addressType int, addr []byte, port string) (net.Conn, error) {
							return validTCPConn, nil
						},
					},
					conn: fakeRWCloser{
						fnRead: func(p []byte) (n int, err error) {
							return 0, io.EOF
						},
						fnWrite: func(p []byte) (n int, err error) {
							return resultBuffer.Write(p)
						},
						fnClose: func() error {
							return nil
						},
					},
					command: commandRequest{
						commandType: connect,
						addressType: ipv4,
						addr:        ipaddr.IP.To4(),
						port:        uint16(ipaddr.Port),
					},
				},
			},
			check: func(s *state, t transition, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if t != nil {
					return fmt.Errorf("want transition nil")
				}
				p := resultBuffer.Bytes()
				resultBuffer.Reset()

				if p[0] != byte(protoVersion) {
					return fmt.Errorf("got proto version %d, want %d", p[0], protoVersion)
				}
				if p[1] != byte(succeeded) {
					return fmt.Errorf("got status %d, want %d", p[1], succeeded)
				}
				if p[2] != byte(0) {
					return fmt.Errorf("got rsv %d, want %d", p[2], 0)
				}
				if p[3] != byte(ipv4) {
					return fmt.Errorf("got address type %d, want %d", p[3], ipv4)
				}
				ip := p[4:8]
				localAddr := validTCPConn.(*net.TCPConn).LocalAddr().(*net.TCPAddr)
				if !bytes.Equal(ip, localAddr.IP.To4()) {
					return fmt.Errorf("got address %v, want %v", ip, localAddr.IP.To4())
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runConnect(tt.args.state)
			if err := tt.check(tt.args.state, got, err); err != nil {
				t.Errorf("runConnect() error = %v", err)
				return
			}
		})
	}
}
