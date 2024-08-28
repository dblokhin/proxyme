package proxyme

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func Test_getAuthHandlers(t *testing.T) {
	type args struct {
		opts Options
	}
	tests := []struct {
		name  string
		args  args
		check func(map[authMethod]authHandler, error) error
	}{
		{
			name: "no methods",
			args: args{},
			check: func(m map[authMethod]authHandler, err error) error {
				if err == nil {
					return fmt.Errorf("expect error but got nil")
				}
				if m != nil {
					return fmt.Errorf("expec nil map but got some")
				}
				return nil
			},
		},
		{
			name: "noauth handler",
			args: args{
				opts: Options{AllowNoAuth: true},
			},
			check: func(m map[authMethod]authHandler, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}

				if len(m) != 1 {
					return fmt.Errorf("wants just 1 no auth handler, got %d handlers", len(m))
				}
				method, ok := m[typeNoAuth]
				if !ok {
					return fmt.Errorf("noauth handler doesn't exist")
				}
				if method.method() != typeNoAuth {
					return fmt.Errorf("invalid method id %d, want %d", method.method(), typeNoAuth)
				}
				return nil
			},
		},
		{
			name: "username handler",
			args: args{
				opts: Options{Authenticate: func(username, password []byte) error {
					return nil
				}},
			},
			check: func(m map[authMethod]authHandler, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if len(m) != 1 {
					return fmt.Errorf("wants just 1 username handler, got %d handlers", len(m))
				}
				method, ok := m[typeLogin]
				if !ok {
					return fmt.Errorf("noauth handler doesn't exist")
				}
				if method.method() != typeLogin {
					return fmt.Errorf("invalid method id %d, want %d", method.method(), typeLogin)
				}
				return nil
			},
		},
		{
			name: "gssapi handler",
			args: args{
				opts: Options{
					GSSAPI: func() (GSSAPI, error) {
						return nil, nil
					},
				},
			},
			check: func(m map[authMethod]authHandler, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if len(m) != 1 {
					return fmt.Errorf("wants just 1 gssapi handler, got %d handlers", len(m))
				}
				method, ok := m[typeGSSAPI]
				if !ok {
					return fmt.Errorf("noauth handler doesn't exist")
				}
				if method.method() != typeGSSAPI {
					return fmt.Errorf("invalid method id %d, want %d", method.method(), typeGSSAPI)
				}
				return nil
			},
		},
		{
			name: "multiple handlers",
			args: args{
				opts: Options{
					AllowNoAuth: true,
					Authenticate: func(username, password []byte) error {
						return nil
					},
					GSSAPI: func() (GSSAPI, error) {
						return nil, nil
					},
				},
			},
			check: func(m map[authMethod]authHandler, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if len(m) != 3 {
					return fmt.Errorf("wants just 3 handlers, got %d handlers", len(m))
				}
				for k, method := range m {
					if method.method() != k {
						return fmt.Errorf("invalid method id %d, want %d", method.method(), k)
					}
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAuthHandlers(tt.args.opts)
			if err := tt.check(got, err); err != nil {
				t.Errorf("getAuthHandlers() error = %v", err)
				return
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		opts Options
	}
	tests := []struct {
		name  string
		args  args
		check func(*SOCKS5, error) error
	}{
		{
			name: "no auth methods error",
			args: args{},
			check: func(socks5 *SOCKS5, err error) error {
				if err == nil {
					return fmt.Errorf("expected error but got nil")
				}
				if socks5 != nil {
					return fmt.Errorf("expected nil return")
				}
				return nil
			},
		},
		{
			name: "common case",
			args: args{
				opts: Options{AllowNoAuth: true},
			},
			check: func(socks5 *SOCKS5, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if socks5 == nil {
					return fmt.Errorf("got nil return")
				}
				if socks5.auth == nil {
					return fmt.Errorf("invalid auth handlers")
				}
				if socks5.connect == nil {
					return fmt.Errorf("invalid connect callback")
				}
				if socks5.listen != nil {
					return fmt.Errorf("expected nil listen callback")
				}
				return nil
			},
		},
		{
			name: "common case: specify listen",
			args: args{
				opts: Options{
					AllowNoAuth: true,
					Listen: func() (net.Listener, error) {
						return nil, nil
					}},
			},
			check: func(socks5 *SOCKS5, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}
				if socks5 == nil {
					return fmt.Errorf("got nil return")
				}
				if socks5.auth == nil {
					return fmt.Errorf("invalid auth handlers")
				}
				if socks5.connect == nil {
					return fmt.Errorf("invalid connect callback")
				}
				if socks5.listen == nil {
					return fmt.Errorf("invalid listen callback")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts)
			if err := tt.check(got, err); err != nil {
				t.Errorf("New() error = %v", err)
				return
			}
		})
	}
}

func TestSOCKS5_Handle(t *testing.T) {
	var called bool

	type fields struct {
		auth    map[authMethod]authHandler
		listen  func() (net.Listener, error)
		connect func(addressType int, addr []byte, port int) (net.Conn, error)
	}
	type args struct {
		conn    io.ReadWriteCloser
		onError func(error)
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantCalled bool
	}{
		{
			name:   "check error: callback",
			fields: fields{},
			args: args{
				conn: fakeRWCloser{fnRead: func(p []byte) (n int, err error) {
					return 0, io.EOF
				}},
				onError: func(err error) {
					called = errors.Is(err, io.EOF)
				},
			},
			wantCalled: true,
		},
		{
			name:   "check error: nil callback",
			fields: fields{},
			args: args{
				conn: fakeRWCloser{fnRead: func(p []byte) (n int, err error) {
					return 0, io.EOF
				}},
			},
			wantCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SOCKS5{
				auth:    tt.fields.auth,
				listen:  tt.fields.listen,
				connect: tt.fields.connect,
			}
			called = false // initialize
			s.Handle(tt.args.conn, tt.args.onError)
			if called != tt.wantCalled {
				t.Errorf("error callback: got called %v, want %v", called, tt.wantCalled)
				return
			}
		})
	}
}
