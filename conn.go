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
	// from raw conn -> gssapi decode -> encapsulated conn -> payload
	var msg gssapiMessage

	if g.buffer.Len() > 0 {
		defer func() {
			if g.buffer.Len() == 0 {
				g.buffer.Reset()
			}
		}()

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

	n := copy(p, payload)
	if n < len(payload) {
		if _, err := g.buffer.Write(payload[n:]); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (g gssConn) Write(p []byte) (int, error) {
	// payload -> encapsulated conn -> gssapi encode -> raw conn
	const maxChunkSize = 1<<16 - 5

	var (
		n     int
		chunk []byte
	)

	for len(p) > 0 {
		bound := min(len(p), maxChunkSize)
		chunk, p = p[:bound], p[bound:]

		token, err := g.gssapi.Encode(chunk)
		if err != nil {
			return n, err
		}

		msg := gssapiMessage{
			version:     subnVersion,
			messageType: gssEncapsulation,
			token:       token,
		}

		buf := new(bytes.Buffer)
		if _, err = msg.WriteTo(buf); err != nil {
			return n, err
		}

		nn, err := g.raw.Write(buf.Bytes())
		n += nn

		if err != nil {
			return n, err
		}
	}

	return n, nil
}

func (g gssConn) Close() error {
	return g.raw.Close()
}
