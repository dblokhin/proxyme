package proxyme

import (
	"bytes"
	"io"
)

// gssConn is encapsulated GSSAPI connection.
type gssConn struct {
	raw    io.ReadWriteCloser
	gssapi GSSAPI
	buffer bytes.Buffer
}

func (g gssConn) Read(p []byte) (int, error) {
	// from raw conn -> gssapi decode -> encapsulated conn
	var msg gssapiMessage

	if g.buffer.Len() > 0 {
		return g.buffer.Read(p)
	}

	_, err := msg.ReadFrom(g.raw)
	if err != nil {
		return 0, err
	}

	if err := msg.validate(gssEncapsulation); err != nil {
		return 0, err
	}

	payload, err := g.gssapi.Decode(msg.token)
	if err != nil {
		return 0, err
	}

	n := min(len(p), len(payload))
	copy(p, payload)

	if n < len(payload) {
		if _, err := g.buffer.Write(payload[n:]); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (g gssConn) Write(p []byte) (n int, err error) {
	// from encapsulated conn -> gssapi encode -> raw conn
	token, err := g.gssapi.Encode(p)
	if err != nil {
		return 0, err
	}

	return g.raw.Write(token)
}

func (g gssConn) Close() error {
	return g.raw.Close()
}
