package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type AuthRequest struct {
	Version uint8
	Methods []uint8
}

func (a *AuthRequest) ReadFrom(r io.Reader) (n int64, err error) {
	// read the protocol version first
	if err = binary.Read(r, binary.BigEndian, &a.Version); err != nil {
		return
	}
	n++

	// read identity methods
	var count uint8
	if err = binary.Read(r, binary.BigEndian, &count); err != nil {
		return
	}
	n++

	a.Methods = make([]uint8, count)
	for i := 0; i < int(count); i++ {
		if err = binary.Read(r, binary.BigEndian, &a.Methods[i]); err != nil {
			return
		}
		n++
	}

	return
}

type AuthReply struct {
	Method uint8
}

func (a AuthReply) WriteTo(w io.Writer) (n int64, err error) {
	// write Sock5 version
	if err = binary.Write(w, binary.BigEndian, protoVersion); err != nil {
		return
	}
	n++

	// write method ID
	if err = binary.Write(w, binary.BigEndian, a.Method); err != nil {
		return
	}
	n++

	return
}

type CommandRequest struct {
	Version uint8 // MUST BE 5
	Cmd     uint8 // support only CONNECT
	Rsv     uint8 // MUST BE 0
	Atyp    uint8
	Addr    []byte
	Port    uint16
}

func (c *CommandRequest) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &c.Version); err != nil {
		return
	}
	n++

	// Read CMD and others
	if err = binary.Read(r, binary.BigEndian, &c.Cmd); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.Rsv); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.Atyp); err != nil {
		return
	}
	n++

	// read the string size
	var size uint8
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		return
	}
	n++

	c.Addr = make([]byte, size)
	if _, err = io.ReadFull(r, c.Addr); err != nil {
		return
	}
	n += int64(size)

	if err = binary.Read(r, binary.BigEndian, &c.Port); err != nil {
		return
	}
	n += 2

	return
}

// CanonicalAddr string that accept net.Dial(): [host]:[port]
func (c *CommandRequest) CanonicalAddr() string {
	// validate
	switch c.Atyp {
	case atypIpv4, atypIpv6, atypDomainName:
	default:
		// invalid atyp
		return ""
	}

	if c.Atyp == atypDomainName {
		return fmt.Sprintf("%s:%d", c.Addr, c.Port)
	}

	return fmt.Sprintf("%s:%d", net.IP(c.Addr).String(), c.Port)
}

type CommandReply struct {
	// Ver protocol version
	Rep  uint8
	Rsv  uint8 // MUST BE 0
	Atyp uint8
	Addr []byte
	Port uint16
}

func (r CommandReply) WriteTo(w io.Writer) (n int64, err error) {
	// write Sock5 version
	if err = binary.Write(w, binary.BigEndian, protoVersion); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.Rep); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.Rsv); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.Atyp); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, uint8(len(r.Addr))); err != nil {
		return
	}
	n += 1

	if _, err = w.Write(r.Addr); err != nil {
		return
	}
	n += int64(len(r.Addr))

	if err = binary.Write(w, binary.BigEndian, r.Port); err != nil {
		return
	}

	n += 2
	return
}
