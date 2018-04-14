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

// sock5IdentityMethod gets client ident methods & select one
func sock5IdentityMethod(client *Client, approved []ident.Identifier) error {

	// read the first message
	var request identRequest
	if err := request.Read(client.Conn); err != nil {
		return err
	}

	// determine ident method
	var determined bool
	check:
	for _, methodID := range request.Methods {
		for _, identMethod := range approved {

			if identMethod.ID() ==  methodID {
				client.IdentMethod = identMethod
				determined = true
				break check
			}
		}
	}


	var resp identResp

	if !determined {
		// send error no ident to client
		resp.ID = ident.SOCK5IdentError
		return errors.New("no selected ident method")
	}

	// send selected method
	resp.ID = client.IdentMethod.ID()
	return resp.Send(client.Conn)
}

// identRequest is the first message from sock5 client
// represents identifier/method selection message
type identRequest struct {
	NMethods uint8
	Methods []uint8
}

// Read sock5 identifier/method selection message
func (h *identRequest) Read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian,  &h.NMethods); err != nil {
		return err
	}

	h.Methods = make([]uint8, h.NMethods)
	if err := binary.Read(r, binary.BigEndian,  h.Methods); err != nil {
		return err
	}

	return nil
}

// identResp responce structure on requesting iden method
type identResp struct {
	ID uint8
}

// Send response to client
func (m *identResp) Send(w io.Writer) error {
	// write sock5 version
	if err := binary.Write(w, binary.BigEndian, SOCK5Version); err != nil {
		return err
	}

	// write method ID
	if err := binary.Write(w, binary.BigEndian, m.ID); err != nil {
		return err
	}

	return nil
}