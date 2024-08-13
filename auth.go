package proxyme

import (
	"bytes"
	"fmt"
	"io"
)

// as defined http://www.ietf.org/rfc/rfc1928.txt

// as defined http://www.ietf.org/rfc/rfc1929.txt
type loginStatus uint8

const (
	success loginStatus = 0
	denied  loginStatus = 0xff
)

type authHandler interface {
	// auth method according to rfc 1928
	method() authMethod
	// auth conducts auth on the connection (and returns upgraded conn if needed)
	auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

type noAuth struct{}

func (n *noAuth) method() authMethod {
	return typeNoAuth
}

func (n *noAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	// no auth just returns conn itself
	return conn, nil
}

type usernameAuth struct {
	authenticator func(user, pass []byte) error
}

func (l *usernameAuth) method() authMethod {
	return typeLogin
}

func (l *usernameAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	var req loginRequest
	if _, err := req.ReadFrom(conn); err != nil {
		return conn, fmt.Errorf("sock read: %w", err)
	}

	if err := req.validate(); err != nil {
		return conn, err
	}

	resp := loginReply{success}
	err := l.authenticator(req.username, req.password)
	if err != nil {
		resp.status = denied
	}

	// server response
	if _, err := resp.WriteTo(conn); err != nil {
		return conn, fmt.Errorf("sock write: %w", err)
	}

	// If the server returns a `failure' (STATUS value other than X'00') status,
	// it MUST close the  connection.
	// It will close if err != nil
	return conn, err
}

const (
	gssMaxTokenSize   = 1<<16 - 1
	gssMaxMessageSize = 1<<16 + 2

	// gssapi message types
	gssAuthentication uint8 = 1
	gssProtection     uint8 = 2
	gssEncapsulation  uint8 = 3
)

type gssapiAuth struct {
	gssapi func() (GSSAPI, error)
}

func (g *gssapiAuth) method() authMethod {
	return typeGSSAPI
}

// auth authenticates and returns encapsulated conn.
// encapsulated conn MUST be non nil.
func (g *gssapiAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	gssapi, err := g.gssapi()
	if err != nil {
		return conn, err
	}

	var msg gssapiMessage

	// authenticate stage
	for {
		// If gss_accept_sec_context is not completed, the server
		// should return the generated output_token to the client, and
		// subsequently pass the resulting client supplied token to another call
		// to gss_accept_sec_context.

		// 1. receive client initial token
		if _, err := msg.ReadFrom(conn); err != nil {
			return conn, fmt.Errorf("sock read: %w", err)
		}

		if err := msg.validate(gssAuthentication); err != nil {
			return conn, err
		}

		// 2. gss accept context
		complete, token, err := gssapi.AcceptContext(msg.token)
		if err != nil {
			// refuse the client's connection for any reason (GSS-API
			// authentication failure or otherwise)
			refuseMsg := []uint8{1, 0xff}
			conn.Write(refuseMsg) // nolint

			return conn, fmt.Errorf("accept client context: %w", err)
		}

		// 3. reply
		msg.token = token
		if _, err := msg.WriteTo(conn); err != nil {
			return conn, fmt.Errorf("sock write: %w", err)
		}

		// If gss_accept_sec_context returns GSS_S_COMPLETE, then, if an
		// output_token is returned, the server should return it to the client.
		//
		// If no token is returned, a zero length token should be sent by the
		// server to signal to the client that it is ready to receive the
		// client's request.
		if complete || len(msg.token) == 0 {
			break
		}
	}

	// agreement message protection stage
	// 1. receive client request
	if _, err := msg.ReadFrom(conn); err != nil {
		return conn, fmt.Errorf("sock read: %w", err)
	}

	if err := msg.validate(gssProtection); err != nil {
		return conn, err
	}

	// 2. get payload
	data, err := gssapi.Decode(msg.token)
	if err != nil {
		return conn, err
	}

	if len(data) != 1 {
		return conn, fmt.Errorf("client send invalid protection level")
	}

	// 3. adjust protection lvl and takes security
	// context protection level which it agrees to
	lvl, err := gssapi.AcceptProtectionLevel(data[0])
	if err != nil {
		return conn, err
	}

	// 4. encode result
	token, err := gssapi.Encode([]byte{lvl})
	if err != nil {
		return conn, err
	}

	// 5. reply
	msg.token = token
	if _, err := msg.WriteTo(conn); err != nil {
		return conn, fmt.Errorf("sock write: %w", err)
	}

	// make encapsulated conn
	return gssConn{
		raw:    conn,
		gssapi: gssapi,
		buffer: bytes.Buffer{},
	}, nil
}

// gssConn is encapsulated GSSAPI connection.
type gssConn struct {
	raw    io.ReadWriteCloser
	gssapi GSSAPI
	buffer bytes.Buffer
}

func (g gssConn) Read(p []byte) (int, error) {
	// from raw conn -> gssapi decode -> encapsulated conn
	var msg gssapiMessage

	if g.buffer.Len() > 0 {
		return g.buffer.Read(p)
	}

	_, err := msg.ReadFrom(g.raw)
	if err != nil {
		return 0, err
	}

	payload, err := g.gssapi.Decode(msg.token)
	if err != nil {
		return 0, err
	}

	n := min(len(p), len(payload))
	copy(p, payload)

	if n < len(payload) {
		if _, err := g.buffer.Write(payload[n:]); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (g gssConn) Write(p []byte) (n int, err error) {
	// from encapsulated conn -> gssapi encode -> raw conn
	token, err := g.gssapi.Encode(p)
	if err != nil {
		return 0, err
	}

	return g.raw.Write(token)
}

func (g gssConn) Close() error {
	return g.raw.Close()
}
