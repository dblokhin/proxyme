package proxyme

import (
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
)

type fakeResolver struct {
	fnLookupIP func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (f fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.fnLookupIP(ctx, network, host)
}

func Test_resolver_LookupIP(t *testing.T) {
	var (
		localhost = net.ParseIP("127.0.0.1")
		ips       = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}
	)

	type fields struct {
		resolver interface {
			LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
		}
		cache *syncLRU[string, []net.IP]
	}
	type args struct {
		ctx     context.Context
		network string
		host    string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		check  func([]net.IP, error) error
	}{
		{
			name: "common valid case 1 ip",
			fields: fields{
				resolver: fakeResolver{
					fnLookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return append([]net.IP{}, localhost), nil
					},
				},
				cache: newSyncCache[string, []net.IP](100),
			},
			args: args{},
			check: func(ip []net.IP, err error) error {
				if err != nil {
					return fmt.Errorf("got unexcepted error: %w", err)
				}

				if !reflect.DeepEqual(ip, append([]net.IP{}, localhost)) {
					return fmt.Errorf("got %v want %v", ip, localhost)
				}

				return nil
			},
		},
		{
			name: "common valid case multiple ip",
			fields: fields{
				resolver: fakeResolver{
					fnLookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return append([]net.IP{}, ips...), nil
					},
				},
				cache: newSyncCache[string, []net.IP](100),
			},
			args: args{},
			check: func(ip []net.IP, err error) error {
				if err != nil {
					return fmt.Errorf("got unexcepted error: %w", err)
				}

				if !reflect.DeepEqual(ip, ips) {
					return fmt.Errorf("got %v want %v", ip, ips)
				}

				return nil
			},
		},
		{
			name: "invalid case ips <nil>",
			fields: fields{
				resolver: fakeResolver{
					fnLookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return nil, nil
					},
				},
				cache: newSyncCache[string, []net.IP](100),
			},
			args: args{},
			check: func(ip []net.IP, err error) error {
				if err == nil {
					return fmt.Errorf("must be error but got nil")
				}

				return nil
			},
		},
		{
			name: "invalid case ips empty",
			fields: fields{
				resolver: fakeResolver{
					fnLookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return nil, nil
					},
				},
				cache: newSyncCache[string, []net.IP](100),
			},
			args: args{},
			check: func(ip []net.IP, err error) error {
				if err == nil {
					return fmt.Errorf("must be error but got nil")
				}

				return nil
			},
		},
		{
			name: "lookup error",
			fields: fields{
				resolver: fakeResolver{
					fnLookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return nil, io.EOF
					},
				},
				cache: newSyncCache[string, []net.IP](100),
			},
			args: args{},
			check: func(ip []net.IP, err error) error {
				if !reflect.DeepEqual(err, io.EOF) {
					return fmt.Errorf("got %v, want %v", err, io.EOF)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &resolver{
				resolver: tt.fields.resolver,
				cache:    tt.fields.cache,
			}
			got, err := r.LookupIP(tt.args.ctx, tt.args.network, tt.args.host)
			if err := tt.check(got, err); err != nil {
				t.Errorf("LookupIP(): %v", err)
				return
			}
		})
	}
}
