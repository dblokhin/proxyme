package proxyme

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
)

func Test_authRequest_ReadFrom(t *testing.T) {
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     | 1 to 255 |
	//+----+----------+----------+
	methods := byte(3)
	payload := []byte{protoVersion, methods, 0x01, 0x02, 0x03}

	type args struct {
		r io.Reader
	}
	tests := []struct {
		name  string
		args  args
		check func(*authRequest, int64, error) error
	}{
		{
			name: "common case",
			args: args{
				r: bytes.NewReader(payload),
			},
			check: func(msg *authRequest, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}

				if i != int64(len(payload)) {
					return fmt.Errorf("got len %d, want %d", i, len(payload))
				}
				if msg.version != protoVersion {
					return fmt.Errorf("got proto version %d, want %d", msg.version, protoVersion)
				}
				if len(msg.methods) != int(methods) {
					return fmt.Errorf("got methods size %d, want %d", len(msg.methods), methods)
				}
				if !slices.Equal(msg.methods, []authMethod{1, 2, 3}) {
					return fmt.Errorf("got methods %v, want %v", msg.methods, []authMethod{1, 2, 3})
				}
				return nil
			},
		},
		{
			name: "EOF",
			args: args{
				r: bytes.NewReader(payload[:3]),
			},
			check: func(req *authRequest, i int64, err error) error {
				if err == nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected error got %v, want %v", err, io.EOF)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authRequest{}
			gotN, err := a.ReadFrom(tt.args.r)
			if err := tt.check(a, gotN, err); err != nil {
				t.Errorf("ReadFrom() = %v", err)
				return
			}
		})
	}
}

func Test_commandRequest_ReadFrom(t *testing.T) {
	//+----+-----+-------+------+----------+----------+
	//|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//+----+-----+-------+------+----------+----------+
	//| 1  |  1  | X'00' |  1   | Variable |    2     |
	//+----+-----+-------+------+----------+----------+
	//ip6       addressType = 1
	//domainName addressType = 3
	//ip6       addressType = 4
	port := byte(0x77)
	ip4 := net.ParseIP("192.168.0.1").To4()
	ip6 := ip4.To16()
	domain := []byte("google")
	payloadipv4 := []byte{protoVersion, byte(connect), 0x00, byte(ipv4), ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port}
	payloadipv6 := []byte{protoVersion, byte(connect), 0x00, byte(ipv6), ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5],
		ip6[6], ip6[7], ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15], 0x00, port}
	payloadDomain := []byte{protoVersion, byte(connect), 0x00, byte(domainName), byte(len(domain)), domain[0], domain[1],
		domain[2], domain[3], domain[4], domain[5], 0x00, port}
	invalidAddrType := []byte{protoVersion, byte(connect), 0x00, 0x10, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port}

	type args struct {
		r io.Reader
	}
	tests := []struct {
		name  string
		args  args
		check func(*commandRequest, int64, error) error
	}{
		{
			name: "common case ip4",
			args: args{
				r: bytes.NewReader(payloadipv4),
			},
			check: func(msg *commandRequest, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}
				if i != int64(len(payloadipv4)) {
					return fmt.Errorf("got len %d, want %d", i, len(payloadipv4))
				}
				if msg.version != protoVersion {
					return fmt.Errorf("got proto version %d, want %d", msg.version, protoVersion)
				}
				if msg.commandType != connect {
					return fmt.Errorf("got command %d, want %d", msg.commandType, connect)
				}
				if msg.rsv != 0 {
					return fmt.Errorf("got rsv %d, want %d", msg.rsv, 0)
				}
				if msg.addressType != ipv4 {
					return fmt.Errorf("got address type %d, want %d", msg.addressType, ip4)
				}
				if !bytes.Equal(msg.addr, ip4) {
					return fmt.Errorf("got ip %v, want %v", msg.addr, ip4)
				}
				if msg.port != uint16(port) {
					return fmt.Errorf("got port %d, want %d", msg.port, port)
				}

				return nil
			},
		},
		{
			name: "common case ip6",
			args: args{
				r: bytes.NewReader(payloadipv6),
			},
			check: func(msg *commandRequest, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}

				if i != int64(len(payloadipv6)) {
					return fmt.Errorf("got len %d, want %d", i, len(payloadipv6))
				}
				if msg.version != protoVersion {
					return fmt.Errorf("got proto version %d, want %d", msg.version, protoVersion)
				}
				if msg.commandType != connect {
					return fmt.Errorf("got command %d, want %d", msg.commandType, connect)
				}
				if msg.rsv != 0 {
					return fmt.Errorf("got rsv %d, want %d", msg.rsv, 0)
				}
				if msg.addressType != ipv6 {
					return fmt.Errorf("got address type %d, want %d", msg.addressType, ip6)
				}
				if !bytes.Equal(msg.addr, ip6) {
					return fmt.Errorf("got ip %v, want %v", msg.addr, ip6)
				}
				if msg.port != uint16(port) {
					return fmt.Errorf("got port %d, want %d", msg.port, port)
				}
				return nil
			},
		},
		{
			name: "common case domain",
			args: args{
				r: bytes.NewReader(payloadDomain),
			},
			check: func(msg *commandRequest, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}
				if i != int64(len(payloadDomain)) {
					return fmt.Errorf("got len %d, want %d", i, len(payloadDomain))
				}
				if msg.version != protoVersion {
					return fmt.Errorf("got proto version %d, want %d", msg.version, protoVersion)
				}
				if msg.commandType != connect {
					return fmt.Errorf("got command %d, want %d", msg.commandType, connect)
				}
				if msg.rsv != 0 {
					return fmt.Errorf("got rsv %d, want %d", msg.rsv, 0)
				}
				if msg.addressType != domainName {
					return fmt.Errorf("got address type %d, want %d", msg.addressType, domainName)
				}
				if !bytes.Equal(msg.addr, domain) {
					return fmt.Errorf("got domain %v, want %v", msg.addr, domain)
				}
				if msg.port != uint16(port) {
					return fmt.Errorf("got port %d, want %d", msg.port, port)
				}
				return nil
			},
		},
		{
			name: "invalid address type",
			args: args{
				r: bytes.NewReader(invalidAddrType),
			},
			check: func(msg *commandRequest, i int64, err error) error {
				if !errors.Is(err, errInvalidAddrType) {
					return fmt.Errorf("got %v, want %v", err, errInvalidAddrType)
				}
				if msg.addressType != 0x10 {
					return fmt.Errorf("got addr type %v, want %v", msg.addressType, 0x10)
				}
				return nil
			},
		},
		{
			name: "EOF",
			args: args{
				r: bytes.NewReader(payloadipv4[:3]),
			},
			check: func(msg *commandRequest, i int64, err error) error {
				if err == nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected error got %v, want %v", err, io.EOF)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &commandRequest{}
			gotN, err := c.ReadFrom(tt.args.r)
			if err := tt.check(c, gotN, err); err != nil {
				t.Errorf("ReadFrom() = %v", err)
				return
			}
		})
	}
}

func Test_loginRequest_ReadFrom(t *testing.T) {
	//+----+------+----------+------+----------+
	//|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	//+----+------+----------+------+----------+
	//| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	//+----+------+----------+------+----------+
	username := []byte("xxx")
	password := []byte("yyy")
	payload := []byte{subnVersion, byte(len(username)), username[0], username[1], username[2],
		byte(len(password)), password[0], password[1], password[2]}
	type args struct {
		reader io.Reader
	}
	tests := []struct {
		name  string
		args  args
		check func(*loginRequest, int64, error) error
	}{
		{
			name: "common case",
			args: args{
				reader: bytes.NewReader(payload),
			},
			check: func(msg *loginRequest, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}
				if i != int64(len(payload)) {
					return fmt.Errorf("got len %d, want %d", i, len(payload))
				}
				if msg.version != subnVersion {
					return fmt.Errorf("got proto version %d, want %d", msg.version, subnVersion)
				}
				if !slices.Equal(msg.username, username) {
					return fmt.Errorf("got username %s, want %s", msg.username, username)
				}
				if !slices.Equal(msg.password, password) {
					return fmt.Errorf("got password %s, want %s", msg.password, password)
				}
				return nil
			},
		},
		{
			name: "EOF",
			args: args{
				reader: bytes.NewReader(payload[:3]),
			},
			check: func(req *loginRequest, i int64, err error) error {
				if err == nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected error got %v, want %v", err, io.EOF)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &loginRequest{}
			gotN, err := r.ReadFrom(tt.args.reader)
			if err := tt.check(r, gotN, err); err != nil {
				t.Errorf("ReadFrom() = %v", err)
				return
			}
		})
	}
}

func Test_gssapiMessage_ReadFrom(t *testing.T) {
	//+------+------+------+.......................+
	//+ ver  | mtyp | len  |       token           |
	//+------+------+------+.......................+
	//+ 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
	//+------+------+------+.......................+

	token := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 11, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	payload := append([]byte{subnVersion, gssAuthentication, 0x00, byte(len(token))}, token...)
	type args struct {
		reader io.Reader
	}
	tests := []struct {
		name  string
		args  args
		check func(*gssapiMessage, int64, error) error
	}{
		{
			name: "common case",
			args: args{
				reader: bytes.NewReader(payload),
			},
			check: func(msg *gssapiMessage, i int64, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error %v", err)
				}
				if i != int64(len(payload)) {
					return fmt.Errorf("got len %d, want %d", i, len(payload))
				}
				if msg.version != subnVersion {
					return fmt.Errorf("got version %d, want %d", msg.version, subnVersion)
				}
				if msg.messageType != gssAuthentication {
					return fmt.Errorf("got message type %d, want %d", msg.messageType, gssAuthentication)
				}
				if !slices.Equal(msg.token, token) {
					return fmt.Errorf("got token %s, want %s", msg.token, token)
				}
				return nil
			},
		},
		{
			name: "EOF",
			args: args{
				reader: bytes.NewReader(payload[:3]),
			},
			check: func(req *gssapiMessage, i int64, err error) error {
				if err == nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected error got %v, want %v", err, io.EOF)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &gssapiMessage{}
			gotN, err := m.ReadFrom(tt.args.reader)
			if err := tt.check(m, gotN, err); err != nil {
				t.Errorf("ReadFrom() = %v", err)
				return
			}
		})
	}
}

func Test_commandRequest_validate(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()

	type fields struct {
		version     uint8
		commandType commandType
		rsv         uint8
		addressType addressType
		addr        []byte
		port        uint16
	}
	tests := []struct {
		name   string
		fields fields
		check  func(error) error
	}{
		{
			name: "common valid",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: ipv4,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return fmt.Errorf("got %q, want nil", err)
				}

				return nil
			},
		},
		{
			name: "invalid proto",
			fields: fields{
				version:     0,
				commandType: connect,
				rsv:         0,
				addressType: ipv4,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid proto error")
			},
		},
		{
			name: "invalid rsv",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         1,
				addressType: ipv4,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid rsv error")
			},
		},
		{
			name: "invalid address type",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: 0,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid address type",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: 2,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid address type",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: 5,
				addr:        ip,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid address ipv6 type + ip v4",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: ipv6,
				addr:        ip.To4(),
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid address ipv4 type + ip nil",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: ipv4,
				addr:        nil,
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid address ipv4 type + [3]ip",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: ipv4,
				addr:        []byte{1, 2, 3},
				port:        1080,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid address type error")
			},
		},
		{
			name: "invalid port",
			fields: fields{
				version:     protoVersion,
				commandType: connect,
				rsv:         0,
				addressType: ipv4,
				addr:        ip,
				port:        0,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid port error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &commandRequest{
				version:     tt.fields.version,
				commandType: tt.fields.commandType,
				rsv:         tt.fields.rsv,
				addressType: tt.fields.addressType,
				addr:        tt.fields.addr,
				port:        tt.fields.port,
			}
			if err := tt.check(c.validate()); err != nil {
				t.Errorf("validate() error = %v", err)
			}
		})
	}
}

func Test_authRequest_validate(t *testing.T) {
	type fields struct {
		version uint8
		methods []authMethod
	}
	tests := []struct {
		name   string
		fields fields
		check  func(error) error
	}{
		{
			name: "common valid",
			fields: fields{
				version: protoVersion,
				methods: []authMethod{typeNoAuth, typeLogin, typeGSSAPI},
			},
			check: func(err error) error {
				if err != nil {
					return fmt.Errorf("got %q, want nil", err)
				}

				return nil
			},
		},
		{
			name: "invalid proto",
			fields: fields{
				version: 0,
				methods: []authMethod{typeNoAuth, typeLogin, typeGSSAPI},
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid proto error")
			},
		},
		{
			name: "empty methods",
			fields: fields{
				version: protoVersion,
				methods: []authMethod{},
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid authenticate method error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authRequest{
				version: tt.fields.version,
				methods: tt.fields.methods,
			}
			if err := tt.check(a.validate()); err != nil {
				t.Errorf("validate() error = %v", err)
			}
		})
	}
}

func Test_loginRequest_validate(t *testing.T) {
	type fields struct {
		version  uint8
		username []byte
		password []byte
	}
	tests := []struct {
		name   string
		fields fields
		check  func(error) error
	}{
		{
			name: "common valid",
			fields: fields{
				version:  subnVersion,
				username: []byte("username"),
				password: []byte("password"),
			},
			check: func(err error) error {
				if err != nil {
					return fmt.Errorf("got %q, want nil", err)
				}

				return nil
			},
		},
		{
			name: "invalid proto",
			fields: fields{
				version:  0,
				username: []byte("username"),
				password: []byte("password"),
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid proto error")
			},
		},
		{
			name: "invalid username",
			fields: fields{
				version:  subnVersion,
				username: nil,
				password: []byte("password"),
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid username error")
			},
		},
		{
			name: "invalid password",
			fields: fields{
				version:  subnVersion,
				username: []byte("username"),
				password: nil,
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid password error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &loginRequest{
				version:  tt.fields.version,
				username: tt.fields.username,
				password: tt.fields.password,
			}
			if err := tt.check(r.validate()); err != nil {
				t.Errorf("validate() error = %v", err)
			}
		})
	}
}

func Test_gssapiMessage_validate(t *testing.T) {
	type fields struct {
		version     uint8
		messageType uint8
		token       []byte
	}
	type args struct {
		messageType uint8
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		check  func(error) error
	}{
		{
			name: "common valid",
			args: args{messageType: gssAuthentication},
			fields: fields{
				version:     subnVersion,
				messageType: gssAuthentication,
				token:       []byte("some_string_token"),
			},
			check: func(err error) error {
				if err != nil {
					return fmt.Errorf("got %q, want nil", err)
				}

				return nil
			},
		},
		{
			name: "invalid proto",
			args: args{messageType: gssAuthentication},
			fields: fields{
				version:     0,
				messageType: gssAuthentication,
				token:       []byte("some_string_token"),
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid proto error")
			},
		},
		{
			name: "invalid message type",
			args: args{messageType: gssAuthentication},
			fields: fields{
				version:     subnVersion,
				messageType: 0,
				token:       []byte("some_string_token"),
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid message type error")
			},
		},
		{
			name: "invalid message type",
			args: args{messageType: gssAuthentication},
			fields: fields{
				version:     subnVersion,
				messageType: 4,
				token:       []byte("some_string_token"),
			},
			check: func(err error) error {
				if err != nil {
					return nil
				}
				return fmt.Errorf("got nil, want invalid message type error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &gssapiMessage{
				version:     tt.fields.version,
				messageType: tt.fields.messageType,
				token:       tt.fields.token,
			}
			if err := tt.check(m.validate(tt.args.messageType)); err != nil {
				t.Errorf("validate() error = %v", err)
			}
		})
	}
}

func Test_authReply_WriteTo(t *testing.T) {
	//+----+--------+
	//|VER | METHOD |
	//+----+--------+
	//| 1  |   1    |
	//+----+--------+

	type fields struct {
		method authMethod
	}
	tests := []struct {
		name    string
		fields  fields
		wantW   []byte
		wantN   int64
		wantErr bool
	}{
		{
			name: "common write",
			fields: fields{
				method: typeGSSAPI,
			},
			wantW:   []byte{protoVersion, byte(typeGSSAPI)},
			wantN:   2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := authReply{
				method: tt.fields.method,
			}
			w := &bytes.Buffer{}
			gotN, err := a.WriteTo(w)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.Bytes(); !bytes.Equal(gotW, tt.wantW) {
				t.Errorf("WriteTo() gotW = %v, want %v", gotW, tt.wantW)
			}
			if gotN != tt.wantN {
				t.Errorf("WriteTo() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_commandReply_WriteTo(t *testing.T) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	port := byte(0x77)
	ip4 := net.ParseIP("192.168.0.1").To4()
	ip6 := ip4.To16()
	domain := []byte("google")

	type fields struct {
		rep         commandStatus
		rsv         uint8
		addressType addressType
		addr        []byte
		port        uint16
	}
	tests := []struct {
		name    string
		buf     io.ReadWriter
		fields  fields
		wantW   []byte
		wantN   int64
		wantErr bool
	}{
		{
			name: "common ipv4",
			buf:  &bytes.Buffer{},
			fields: fields{
				rep:         succeeded,
				rsv:         0,
				addressType: ipv4,
				addr:        ip4,
				port:        uint16(port),
			},
			wantW:   []byte{protoVersion, byte(succeeded), 0x00, byte(ipv4), ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port},
			wantN:   int64(len([]byte{protoVersion, byte(succeeded), 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, port})),
			wantErr: false,
		},
		{
			name: "common ipv6",
			buf:  &bytes.Buffer{},
			fields: fields{
				rep:         notSupported,
				rsv:         0,
				addressType: ipv6,
				addr:        ip6,
				port:        uint16(port),
			},
			wantW: []byte{protoVersion, byte(notSupported), 0x00, byte(ipv6), ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5],
				ip6[6], ip6[7], ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15], 0x00, port},
			wantN: int64(len([]byte{protoVersion, byte(notSupported), 0x00, 0x04, ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5],
				ip6[6], ip6[7], ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15], 0x00, port})),
			wantErr: false,
		},
		{
			name: "common domain",
			buf:  &bytes.Buffer{},
			fields: fields{
				rep:         sockFailure,
				rsv:         0,
				addressType: domainName,
				addr:        domain,
				port:        uint16(port),
			},
			wantW: []byte{protoVersion, byte(sockFailure), 0x00, byte(domainName), byte(len(domain)), domain[0], domain[1],
				domain[2], domain[3], domain[4], domain[5], 0x00, port},
			wantN: int64(len([]byte{protoVersion, byte(sockFailure), 0x00, byte(domainName), byte(len(domain)), domain[0], domain[1],
				domain[2], domain[3], domain[4], domain[5], 0x00, port})),
			wantErr: false,
		},
		{
			name: "invalid domain (big size)",
			buf:  &bytes.Buffer{},
			fields: fields{
				rep:         succeeded,
				rsv:         0,
				addressType: domainName,
				addr:        make([]byte, maxDomainSize+1),
				port:        uint16(port),
			},
			wantW:   nil,
			wantN:   0,
			wantErr: true,
		},
		{
			name: "network error",
			buf: &fakeRWCloser{
				fnWrite: func(p []byte) (n int, err error) {
					return 0, io.EOF
				},
				fnRead: func(p []byte) (n int, err error) {
					return 0, io.EOF
				},
			},
			fields: fields{
				rep:         succeeded,
				rsv:         0,
				addressType: domainName,
				addr:        make([]byte, maxDomainSize+1),
				port:        uint16(port),
			},
			wantW:   nil,
			wantN:   0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := commandReply{
				rep:         tt.fields.rep,
				rsv:         tt.fields.rsv,
				addressType: tt.fields.addressType,
				addr:        tt.fields.addr,
				port:        tt.fields.port,
			}
			gotN, err := r.WriteTo(tt.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW, _ := io.ReadAll(tt.buf); !bytes.Equal(gotW, tt.wantW) {
				t.Errorf("WriteTo() gotW = %v, want %v", gotW, tt.wantW)
			}
			if gotN != tt.wantN {
				t.Errorf("WriteTo() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_gssapiMessage_WriteTo(t *testing.T) {
	// +------+------+------+.......................+
	// + ver  | mtyp | len  |       token           |
	// +------+------+------+.......................+
	// + 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
	// +------+------+------+.......................+
	token := []byte{1, 2, 3, 4, 5, 6, 7, 9, 10} // for test len within a byte
	type fields struct {
		version     uint8
		messageType uint8
		token       []byte
	}
	tests := []struct {
		name    string
		buf     io.ReadWriter
		fields  fields
		wantW   []byte
		wantN   int64
		wantErr bool
	}{
		{
			name: "common",
			buf:  &bytes.Buffer{},
			fields: fields{
				version:     subnVersion,
				messageType: gssAuthentication,
				token:       token,
			},
			wantW:   append([]byte{subnVersion, gssAuthentication, 00, byte(len(token))}, token...),
			wantN:   int64(len(token) + 4),
			wantErr: false,
		},
		{
			name: "invalid token size",
			buf:  &bytes.Buffer{},
			fields: fields{
				version:     subnVersion,
				messageType: gssAuthentication,
				token:       make([]byte, maxTokenSize+1), // <<-- too big token
			},
			wantW:   nil,
			wantN:   0,
			wantErr: true,
		},
		{
			name: "network error",
			buf: &fakeRWCloser{
				fnWrite: func(p []byte) (n int, err error) {
					return 0, io.EOF
				},
				fnRead: func(p []byte) (n int, err error) {
					return 0, io.EOF
				},
			},
			fields: fields{
				version:     subnVersion,
				messageType: gssAuthentication,
				token:       token,
			},
			wantW:   nil,
			wantN:   0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &gssapiMessage{
				version:     tt.fields.version,
				messageType: tt.fields.messageType,
				token:       tt.fields.token,
			}
			gotN, err := m.WriteTo(tt.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if data, _ := io.ReadAll(tt.buf); !bytes.Equal(data, tt.wantW) {
				t.Errorf("WriteTo() gotW = %v, want %v", data, tt.wantW)
			}
			if gotN != tt.wantN {
				t.Errorf("WriteTo() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}
