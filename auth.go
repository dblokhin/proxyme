package proxyme

import (
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

func (n noAuth) method() authMethod {
	return typeNoAuth
}

func (n noAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	// no auth just returns conn itself
	return conn, nil
}

type usernameAuth struct {
	authenticator func(user, pass []byte) error
}

func (l usernameAuth) method() authMethod {
	return typeLogin
}

func (l usernameAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
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
	gssMaxTokenSize = 1<<16 - 1

	// gssapi message types
	gssAuthenticateMessage   uint8 = 1
	gssProtectionNegotiation uint8 = 2
)

type gssapiAuth struct {
	gssapi GSSAPI
	conn   io.ReadWriteCloser
}

func (g *gssapiAuth) method() authMethod {
	return typeGSSAPI
}

func (g *gssapiAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
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

		if err := msg.validate(gssAuthenticateMessage); err != nil {
			return conn, err
		}

		// 2. gss accept context
		complete, token, err := g.gssapi.AcceptContext(msg.token)
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

	if err := msg.validate(gssProtectionNegotiation); err != nil {
		return conn, err
	}

	// 2. get payload
	data, err := g.gssapi.Decode(msg.token)
	if err != nil {
		return conn, err
	}

	if len(data) != 1 {
		return conn, fmt.Errorf("client send invalid protection level")
	}

	// 3. adjust protection lvl and takes security
	// context protection level which it agrees to
	lvl, err := g.gssapi.AcceptProtectionLevel(data[0])
	if err != nil {
		return conn, err
	}

	// 4. encode result
	token, err := g.gssapi.Encode([]byte{lvl})
	if err != nil {
		return conn, err
	}

	// 5. reply
	msg.token = token
	if _, err := msg.WriteTo(conn); err != nil {
		return conn, fmt.Errorf("sock write: %w", err)
	}

	// traffic stage

	return nil, nil
}
