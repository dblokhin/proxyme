package protocol

import (
	"fmt"
	"io"
)

// as defined http://www.ietf.org/rfc/rfc1928.txt

// identify methods
const (
	authTypeNoAuth uint8 = 0
	authTypeGSSAPI uint8 = 1
	authTypeLogin  uint8 = 2
	authTypeError  uint8 = 0xff
)

// as defined http://www.ietf.org/rfc/rfc1929.txt
const (
	loginStatusSuccess uint8 = 0
	loginStatusDenied  uint8 = 0xff
)

type authHandler interface {
	// methodID according to rfc 1928 method of authenticity
	methodID() uint8
	// auth conducts auth on conn (and returns upgraded conn if needed)
	auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

type noAuth struct{}

func (n noAuth) methodID() uint8 {
	return authTypeNoAuth
}

func (n noAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	// no auth just returns conn itself
	return conn, nil
}

type usernameAuth struct {
	validator func(user, pass []byte) error
}

func (l usernameAuth) methodID() uint8 {
	return authTypeLogin
}

func (l usernameAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	var req LoginRequest
	if _, err := req.ReadFrom(conn); err != nil {
		return conn, fmt.Errorf("sock read: %w", err)
	}

	if req.Ver != subnegotiationVersion {
		return conn, fmt.Errorf("client sent invalid subnegation version: %d", req.Ver)
	}

	resp := LoginReply{loginStatusSuccess}
	err := l.validator(req.Username, req.Passwd)
	if err != nil {
		resp.Status = loginStatusDenied
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

type gssapiAuth struct {
}

func (g gssapiAuth) methodID() uint8 {
	//TODO implement me
	panic("implement me")
}

func (g gssapiAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	//TODO implement me
	panic("implement me")
}
