package proxyme

import (
	"errors"
	"fmt"
	"io"
	"reflect"
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

func Test_socks5_errAuthState(t *testing.T) {
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
					opts: socks5{
						authMethods: map[authMethod]authHandler{
							typeNoAuth: &noAuth{},
						},
					},
					conn: fakeRWCloser{
						fnWrite: nil,
						fnRead: func(p []byte) (n int, err error) {
							if len(noAuthReq) == 0 {
								return 0, io.EOF
							}

							n = min(len(p), len(noAuthReq))
							copy(p, noAuthReq[:n])
							noAuthReq = noAuthReq[n:]

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
				if !reflect.DeepEqual(state.methods, []authMethod{typeNoAuth}) {
					return fmt.Errorf("got %v, want = %v", state.methods, []authMethod{typeNoAuth})
				}
				if state.method == nil {
					return fmt.Errorf("got nil auth hanlder")
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
					opts: socks5{
						authMethods: map[authMethod]authHandler{
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
					opts: socks5{},
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
					opts: socks5{},
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
