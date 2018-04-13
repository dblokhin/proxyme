// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package protocols

import (
	"io"
	"encoding/binary"
	"ident"
)

// SOCK5 RFC: http://www.ietf.org/rfc/rfc1928.txt

func sock5Identity(client Client, idents []ident.Identifier) error {

	// read the hand first
	var hand sock5Hand
	hand.Read(client.Conn)

	//



}

// sock5Hand is the first message from sock5 client
// represents identifier/method selection message
type sock5Hand struct {
	NMethods int8
	Methods []int8
}

// Read sock5 identifier/method selection message
func (h *sock5Hand) Read(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian,  &h.NMethods); err != nil {
		return err
	}

	h.Methods = make([]int8, h.NMethods)
	if err := binary.Read(r, binary.BigEndian,  h.Methods); err != nil {
		return err
	}

	return nil
}