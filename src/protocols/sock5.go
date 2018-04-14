// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package protocols

import (
	"io"
	"encoding/binary"
	"ident"
	"errors"
)

// SOCK5 RFC: http://www.ietf.org/rfc/rfc1928.txt

func sock5Identity(client Client, approved []ident.Identifier) error {

	// read the first message
	var request identRequest
	if err := request.Read(client.Conn); err != nil {
		return err
	}

	// define ident method
	var identify ident.Identifier

	check:
	for _, methodID := range request.Methods {
		for _, ident := range approved {

			if ident.ID() ==  methodID {
				identify = ident
				break check
			}
		}
	}

	// send selected method
	var resp identResp
	resp.ID = identify.ID()
	resp.Send(client.Conn)

	// identify client
	if !identify.Auth() {
		return errors.New("access denied")
	}

	return nil
}

// identRequest is the first message from sock5 client
// represents identifier/method selection message
type identRequest struct {
	NMethods int8
	Methods []int8
}

// Read sock5 identifier/method selection message
func (h *identRequest) Read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian,  &h.NMethods); err != nil {
		return err
	}

	h.Methods = make([]int8, h.NMethods)
	if err := binary.Read(r, binary.BigEndian,  h.Methods); err != nil {
		return err
	}

	return nil
}

// identResp responce structure on requesting iden method
type identResp struct {
	ID int8
}

// Send response to client
func (m *identResp) Send(w io.Writer) error {
	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, int8(5)); err != nil {
		return err
	}

	// write method ID
	if err := binary.Write(w, binary.BigEndian, m.ID); err != nil {
		return err
	}

	return nil
}