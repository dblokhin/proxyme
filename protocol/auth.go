package protocol

import (
	"io"
)

// identify methods
const (
	identNoAuth uint8 = 0
	identGSSAPI uint8 = 1
	identLogin  uint8 = 2
	identError  uint8 = 0xff
)

type authHandler interface {
	// methodID according to rfc 1928 method of authenticity
	methodID() uint8
	// auth conducts auth on conn (and returns upgraded conn if needed)
	auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

type noAuth struct{}

func (n noAuth) methodID() uint8 {
	return identNoAuth
}

func (n noAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	return conn, nil
}

type usernameAuth struct {
	validator func(user, pass string) error
}

func (l usernameAuth) methodID() uint8 {
	return identLogin
}

func (l usernameAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	//TODO implement me
	panic("implement me")
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
