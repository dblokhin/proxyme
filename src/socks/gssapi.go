// 25.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"net"
	"io"
	"encoding/binary"
	"errors"
)

// GSSAPI ident method with GSSAPI
type GSSAPI struct{}

// ID is identical method id
func (a GSSAPI) ID() uint8 {
	return IdentGSSAPI
}

// Identify authorization proc
func (a GSSAPI) Identify(conn net.Conn) error {
	// get sec context
	var req gssapiMessage
	if err := req.Read(conn); err != nil {
		return err
	}

	// set sec context
	// not supported yet
	if err := req.WriteError(conn); err != nil {
		return err
	}

	return errors.New("GSSAPI is not supported yet")
}

const (
	gssapiSubnegotiationVersion uint8 = 1

	// types of GSSAPI messages (mtyp)
	gssapiMessageInit          uint8 = 1
	gssapiMessageSubnegotiation  uint8 = 2
	gssapiMessageEncapsulation uint8 = 3

	gssapiMessageError uint8 = 0xff
)

var errGSSAPIVersion = errors.New("error gss-api version")

// gssapiMessage message as defined in http://www.ietf.org/rfc/rfc1961.txt
type gssapiMessage struct {
	Ver   uint8
	Mtyp  uint8
	Token []byte
}

// Read the client request
func (ch *gssapiMessage) Read(r io.Reader) error {
	var err error

	// read version
	if err = binary.Read(r, binary.BigEndian, &ch.Ver); err != nil {
		return err
	}

	// check MUST BE
	if ch.Ver != gssapiSubnegotiationVersion {
		return errLoginVersion
	}

	// read mtyp
	if err = binary.Read(r, binary.BigEndian, &ch.Mtyp); err != nil {
		return err
	}

	var len uint16
	// Read len of token
	if err = binary.Read(r, binary.BigEndian, &len); err != nil {
		return err
	}

	ch.Token = make([]byte, len)
	if _, err := io.ReadFull(r, ch.Token); err != nil {
		return err
	}

	return nil
}

// Write response
func (ch *gssapiMessage) Write(w io.Writer) error {

	// write version
	if err := binary.Write(w, binary.BigEndian, gssapiSubnegotiationVersion); err != nil {
		return err
	}

	// write mtyp
	if err := binary.Write(w, binary.BigEndian, ch.Mtyp); err != nil {
		return err
	}

	// Read len of token
	if err := binary.Write(w, binary.BigEndian, len(ch.Token)); err != nil {
		return err
	}

	// write token
	if _, err := w.Write(ch.Token); err != nil {
		return err
	}

	return nil
}

// WriteError sends gssapi error packet as defined at RFC 1961
func (ch *gssapiMessage) WriteError(w io.Writer) error {
	// write version
	if err := binary.Write(w, binary.BigEndian, gssapiSubnegotiationVersion); err != nil {
		return err
	}

	// write mtyp error
	if err := binary.Write(w, binary.BigEndian, gssapiMessageError); err != nil {
		return err
	}

	return nil
}
