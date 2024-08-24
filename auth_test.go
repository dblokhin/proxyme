package proxyme

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
)

func Test_noAuth_method(t *testing.T) {
	tests := []struct {
		name string
		want authMethod
	}{
		{
			name: "common",
			want: 0, // rfc1928 noauth method
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := noAuth{}
			if got := a.method(); got != tt.want {
				t.Errorf("method() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_noAuth_auth(t *testing.T) {
	conn := &net.TCPConn{}
	type args struct {
		conn io.ReadWriteCloser
	}
	tests := []struct {
		name    string
		args    args
		want    io.ReadWriteCloser
		wantErr bool
	}{
		{
			name: "common",
			args: args{
				conn: conn,
			},
			want:    conn,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := noAuth{}
			got, err := a.auth(tt.args.conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("auth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("auth() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_usernameAuth_method(t *testing.T) {
	type fields struct {
		authenticator func(user, pass []byte) error
	}
	tests := []struct {
		name   string
		fields fields
		want   authMethod
	}{
		{
			name:   "common",
			fields: fields{},
			want:   2, // rfc1928 username/password method
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := usernameAuth{
				authenticator: tt.fields.authenticator,
			}
			if got := a.method(); got != tt.want {
				t.Errorf("method() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_gssapiAuth_method(t *testing.T) {
	type fields struct {
		gssapi func() (GSSAPI, error)
	}
	tests := []struct {
		name   string
		fields fields
		want   authMethod
	}{
		{
			name:   "common",
			fields: fields{},
			want:   1, // rfc1928 gssapi method
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gssapiAuth{
				gssapi: tt.fields.gssapi,
			}
			if got := a.method(); got != tt.want {
				t.Errorf("method() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_usernameAuth_auth(t *testing.T) {
	username := []byte("xxx")
	password := []byte("yyy")
	validPayload := []byte{subnVersion, byte(len(username)), username[0], username[1], username[2],
		byte(len(password)), password[0], password[1], password[2]}
	invalidPayload := []byte{subnVersion + 3, byte(len(username)), username[0], username[1], username[2],
		byte(len(password)), password[0], password[1], password[2]}
	succeedReply := bytes.NewBuffer([]byte{0x01, 0x00})
	deniedReply := bytes.NewBuffer([]byte{0x01, 0xFF})

	type fields struct {
		authenticator func(user, pass []byte) error
	}
	type args struct {
		conn io.ReadWriteCloser
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		check  func(orig, hijacked io.ReadWriteCloser, err error) error
	}{
		{
			name: "common valid",
			fields: fields{
				authenticator: func(user, pass []byte) error {
					// any is valid
					return nil
				},
			},
			args: args{
				conn: &fakeRWCloser{
					fnRead: func(p []byte) (n int, err error) {
						return bytes.NewBuffer(validPayload).Read(p)
					},
					fnWrite: func(p []byte) (n int, err error) {
						want := succeedReply.Next(len(p))
						if !reflect.DeepEqual(p, want) {
							return 0, fmt.Errorf("%w: %v", errors.ErrUnsupported, p) // <- just to signal that p is not as expected
						}
						return len(p), nil
					},
				},
			},
			check: func(orig, conn io.ReadWriteCloser, err error) error {
				if !reflect.DeepEqual(orig, conn) {
					return fmt.Errorf("got different connection")
				}

				if err != nil {
					return fmt.Errorf("unexpected error: %w", err)
				}

				return nil
			},
		},
		{
			name: "read: network error",
			fields: fields{
				authenticator: func(user, pass []byte) error {
					// any is valid
					return nil
				},
			},
			args: args{
				conn: &fakeRWCloser{
					fnRead: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
					fnWrite: func(p []byte) (n int, err error) {
						return len(p), nil
					},
				},
			},
			check: func(orig, conn io.ReadWriteCloser, err error) error {
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("got %w, want %w", err, io.EOF)
				}
				if !reflect.DeepEqual(orig, conn) {
					return fmt.Errorf("got different connection")
				}
				return nil
			},
		},
		{
			name: "write: network error",
			fields: fields{
				authenticator: func(user, pass []byte) error {
					// any is valid
					return nil
				},
			},
			args: args{
				conn: &fakeRWCloser{
					fnRead: func(p []byte) (n int, err error) {
						return bytes.NewBuffer(validPayload).Read(p)
					},
					fnWrite: func(p []byte) (n int, err error) {
						return 0, io.ErrUnexpectedEOF
					},
				},
			},
			check: func(orig, conn io.ReadWriteCloser, err error) error {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					return fmt.Errorf("got %w, want %w", err, io.ErrUnexpectedEOF)
				}
				if !reflect.DeepEqual(orig, conn) {
					return fmt.Errorf("got different connection")
				}
				return nil
			},
		},
		{
			name: "invalid payload",
			fields: fields{
				authenticator: func(user, pass []byte) error {
					// any is valid
					return nil
				},
			},
			args: args{
				conn: &fakeRWCloser{
					fnRead: func(p []byte) (n int, err error) {
						return bytes.NewBuffer(invalidPayload).Read(p)
					},
					fnWrite: func(p []byte) (n int, err error) {
						return len(p), nil
					},
				},
			},
			check: func(orig, conn io.ReadWriteCloser, err error) error {
				if err == nil {
					return fmt.Errorf("expected error but got nil")
				}
				if !reflect.DeepEqual(orig, conn) {
					return fmt.Errorf("got different connection")
				}
				return nil
			},
		},
		{
			name: "auth failed",
			fields: fields{
				authenticator: func(user, pass []byte) error {
					return errors.New("invalid login/pass")
				},
			},
			args: args{
				conn: &fakeRWCloser{
					fnRead: func(p []byte) (n int, err error) {
						return bytes.NewBuffer(validPayload).Read(p)
					},
					fnWrite: func(p []byte) (n int, err error) {
						want := deniedReply.Next(len(p))
						if !reflect.DeepEqual(p, want) {
							return 0, fmt.Errorf("%w: %v", errors.ErrUnsupported, p) // <- just to signal that p is not as expected
						}
						return len(p), nil
					},
				},
			},
			check: func(orig, conn io.ReadWriteCloser, err error) error {
				if errors.Is(err, errors.ErrUnsupported) {
					return fmt.Errorf("response must be status denied: 0x01 0xff, got: %w", err)
				}
				if err == nil {
					return fmt.Errorf("expected error but got nil")
				}
				if !reflect.DeepEqual(orig, conn) {
					return fmt.Errorf("got different connection")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := usernameAuth{
				authenticator: tt.fields.authenticator,
			}
			got, err := a.auth(tt.args.conn)
			if err := tt.check(tt.args.conn, got, err); err != nil {
				t.Errorf("auth() error = %v", err)
				return
			}
		})
	}
}
