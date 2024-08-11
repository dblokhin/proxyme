package proxyme

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type authRequest struct {
	version uint8
	methods []authMethod
}

func (a *authRequest) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &a.version); err != nil {
		return
	}
	n++

	var size uint8
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		return
	}
	n++

	a.methods = make([]authMethod, size)
	for i := 0; i < int(size); i++ {
		if err = binary.Read(r, binary.BigEndian, &a.methods[i]); err != nil {
			return
		}
		n++
	}

	return
}

func (a *authRequest) validate() error {
	if a.version != protoVersion {
		return fmt.Errorf("invalid auth.version: %d", a.version)
	}

	if len(a.methods) == 0 {
		return fmt.Errorf("empty auth.methods")
	}

	return nil
}

type authReply struct {
	method authMethod
}

func (a authReply) WriteTo(w io.Writer) (n int64, err error) {
	if err = binary.Write(w, binary.BigEndian, protoVersion); err != nil {
		return
	}
	n++

	if err = binary.Write(w, binary.BigEndian, a.method); err != nil {
		return
	}
	n++

	return
}

type commandRequest struct {
	version     uint8 // MUST BE 5
	commandType commandType
	rsv         uint8 // MUST BE 0
	addressType addressType
	addr        []byte
	port        uint16
}

func (c *commandRequest) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &c.version); err != nil {
		return
	}
	n++

	// Read CMD and others
	if err = binary.Read(r, binary.BigEndian, &c.commandType); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.rsv); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.addressType); err != nil {
		return
	}
	n++

	// read the string size
	var size uint8
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		return
	}
	n++

	c.addr = make([]byte, size)
	if _, err = io.ReadFull(r, c.addr); err != nil {
		return
	}
	n += int64(size)

	if err = binary.Read(r, binary.BigEndian, &c.port); err != nil {
		return
	}
	n += 2

	return
}

// canonicalAddr string that accept net.Dial(): [host]:[port]
func (c *commandRequest) canonicalAddr() string {
	if c.validate() != nil {
		return ""
	}

	if c.addressType == domainName {
		return fmt.Sprintf("%s:%d", c.addr, c.port)
	}

	return fmt.Sprintf("%s:%d", net.IP(c.addr).String(), c.port)
}

func (c *commandRequest) validate() error {
	if c.version != protoVersion {
		return fmt.Errorf("invalid command.version: %d", c.version)
	}

	if c.rsv != 0 {
		return fmt.Errorf("invalid command.rsv: %d", c.rsv)
	}

	switch c.addressType {
	case ipv4, ipv6, domainName:
	default:
		return fmt.Errorf("invalid command.addressType: %d", c.addressType)
	}

	switch c.commandType {
	case connect, bind, udpAssoc:
	default:
		return fmt.Errorf("invalid command: %d", c.addressType)
	}

	if len(c.addr) == 0 || (c.addressType == ipv4 && len(c.addr) != net.IPv4len) || (c.addressType == ipv6 && len(c.addr) != net.IPv6len) {
		return fmt.Errorf("invalid addr: %d %q", c.addressType, string(c.addr))
	}

	if c.port == 0 {
		return fmt.Errorf("invalid port: %d", c.port)
	}

	return nil
}

type commandReply struct {
	rep         commandStatus
	rsv         uint8 // MUST BE 0
	addressType addressType
	addr        []byte
	port        uint16
}

func (r commandReply) WriteTo(w io.Writer) (n int64, err error) {
	if err = binary.Write(w, binary.BigEndian, protoVersion); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.rep); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.rsv); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, r.addressType); err != nil {
		return
	}
	n += 1

	if err = binary.Write(w, binary.BigEndian, uint8(len(r.addr))); err != nil {
		return
	}
	n += 1

	if _, err = w.Write(r.addr); err != nil {
		return
	}
	n += int64(len(r.addr))

	if err = binary.Write(w, binary.BigEndian, r.port); err != nil {
		return
	}

	n += 2
	return
}

// loginRequest clients request username/passwd auth scenario
type loginRequest struct {
	version  uint8 // MUST BE 1
	username []byte
	password []byte
}

func (r *loginRequest) ReadFrom(reader io.Reader) (n int64, err error) {
	if err = binary.Read(reader, binary.BigEndian, &r.version); err != nil {
		return
	}
	n++

	var size uint8
	if err = binary.Read(reader, binary.BigEndian, &size); err != nil {
		return
	}
	n++

	r.username = make([]byte, size)
	if _, err = io.ReadFull(reader, r.username); err != nil {
		return
	}
	n += int64(size)

	if err = binary.Read(reader, binary.BigEndian, &size); err != nil {
		return
	}
	n++

	r.password = make([]byte, size)
	if _, err = io.ReadFull(reader, r.password); err != nil {
		return
	}
	n += int64(size)

	return
}

func (r *loginRequest) validate() error {
	if r.version != subnVersion {
		return fmt.Errorf("invalid subnegotion version: %d", r.version)
	}

	if len(r.username) == 0 {
		return fmt.Errorf("empty username")
	}

	if len(r.username) == 0 {
		return fmt.Errorf("empty password")
	}

	return nil
}

// loginReply servers respond on request username/password authentication
type loginReply struct {
	status loginStatus
}

func (l loginReply) WriteTo(w io.Writer) (n int64, err error) {
	if err = binary.Write(w, binary.BigEndian, subnVersion); err != nil {
		return
	}
	n++

	if err = binary.Write(w, binary.BigEndian, l.status); err != nil {
		return
	}
	n++

	return
}
