package messages

import (
	"encoding/binary"
	"io"
)

type Auth struct {
	Version uint8
	Methods []uint8
}

func (a *Auth) ReadFrom(r io.Reader) (n int64, err error) {
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
