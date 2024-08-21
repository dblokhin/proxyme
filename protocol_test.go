package proxyme

import (
	"errors"
	"fmt"
	"io"
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
