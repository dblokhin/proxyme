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

//type gssapiAuth struct {
//}
//
//func (g gssapiAuth) method() authMethod {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (g gssapiAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
//	//TODO implement me
//	panic("implement me")
//}
