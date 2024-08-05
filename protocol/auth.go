package protocol

import (
	"io"
)

type authType uint8

// identify methods
const (
	identNoAuth authType = 0
	identGSSAPI authType = 1
	identLogin  authType = 2
	identError  authType = 0xff
)

type authHandler interface {
	// methodID according to rfc 1928 method of authenticity
	methodID() authType
	// auth conducts auth on conn (and returns upgraded conn if needed)
	auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

type noAuth struct{}

func (n noAuth) methodID() authType {
	return identNoAuth
}

func (n noAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	return conn, nil
}

type usernameAuth struct {
	validator func(user, pass string) error
}

func (l usernameAuth) methodID() authType {
	return identLogin
}

func (l usernameAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	//TODO implement me
	panic("implement me")
}

type gssapiAuth struct {
}

func (g gssapiAuth) methodID() authType {
	//TODO implement me
	panic("implement me")
}

func (g gssapiAuth) auth(conn io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	//TODO implement me
	panic("implement me")
}
