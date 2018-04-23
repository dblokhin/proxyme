// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"net"
	"io"
	"encoding/binary"
	"errors"
)

// defined in rfc1929.txt

// Login ident method with username/pass auth
type Login struct {
	Validator LoginValidator
}

type LoginValidator interface {
	Authorize(login, pass string) bool
}

const (
	loginStatusSuccess uint8 = 0
	loginStatusDenied  uint8 = 0xff

	// as defined http://www.ietf.org/rfc/rfc1929.txt
	loginSubnegotiationVersion uint8 = 1
)

var errLoginVersion = errors.New("error login version")

// ID is identical method id
func (a Login) ID() uint8 {
	return IdentLogin
}

// Identify authorization proc
func (a Login) Identify(conn net.Conn) error {
	var (
		request loginRequest
		reply   loginReply
	)

	// read client request with login/pass
	if err := request.Read(conn); err != nil {
		return err
	}

	// validate login & pass
	if a.Validator.Authorize(request.Login, request.Passwd) {
		// Granted
		reply.Status = loginStatusSuccess
		return reply.Send(conn)
	} else {
		// Denied
		reply.Status = loginStatusDenied
		if err := reply.Send(conn); err != nil {
			return err
		}

		return errAccessDenied
	}

	// never rich
	return nil
}

func (a Login) auth(login, pass string) bool {
	return true
}

// loginRequest client request with username/passwd
type loginRequest struct {
	Ver    uint8 // MUST BE 1
	Login  string
	Passwd string
}

// Read the client request
func (req *loginRequest) Read(r io.Reader) error {
	var err error

	if err = binary.Read(r, binary.BigEndian, &req.Ver); err != nil {
		return err
	}

	// check MUST BE
	if req.Ver != loginSubnegotiationVersion {
		return errLoginVersion
	}

	var len uint8
	// Read len of login
	if err = binary.Read(r, binary.BigEndian, &len); err != nil {
		return err
	}

	login := make([]byte, len)
	if _, err := io.ReadFull(r, login); err != nil {
		return err
	}

	req.Login = string(login)

	// Read len of pwd
	if err = binary.Read(r, binary.BigEndian, &len); err != nil {
		return err
	}

	pwd := make([]byte, len)
	if _, err := io.ReadFull(r, pwd); err != nil {
		return err
	}

	req.Passwd = string(pwd)

	return nil
}

type loginReply struct {
	Status uint8
}

func (r loginReply) Send(w io.Writer) error {

	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, loginSubnegotiationVersion); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, r.Status); err != nil {
		return err
	}

	return nil
}
