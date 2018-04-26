// 26.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"testing"
	"net"
	"bytes"
)

func createTransferWindow(l net.Listener) error {
	defer l.Close()
	src, err := l.Accept()
	if err != nil {
		return err
	}

	dst, err := l.Accept()
	if err != nil {
		return err
	}
	defer func() {
		src.Close()
		dst.Close()
	}()

	if err := spliceStreams(src, dst); err != nil {
		return err
	}

	return err
}

func newProxy(addr string) (net.Conn, net.Conn, error, chan error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err, nil
	}
	defer l.Close()
	errc := make(chan error, 1)
	go func() {
		errc <- createTransferWindow(l)
	}()

	c1, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err, errc
	}

	c2, err := net.Dial("tcp", addr)
	if err != nil {
		c1.Close()
		return nil, nil, err, errc
	}

	return c1, c2, nil, errc
}

func testSpliceStream(t *testing.T, chunkSize int) {
	c1, c2, err, errc := newProxy("127.0.0.1:9999")
	if err != nil {
		t.Fatal("setup error:", err)
	}

	select {
	case err = <-errc:
		t.Fatal("setup error:", err)
	default:
	}

	defer c1.Close()
	defer c2.Close()


	data := make([]byte, chunkSize)
	data[chunkSize - 1] = byte(chunkSize)
	//write
	if _, err := c1.Write(data); err != nil {
		t.Fatal("write error:", err)
	}

	// read
	recv := make([]byte, len(data))
	if _, err := c2.Read(recv); err != nil {
		t.Fatal("read error:", err)
	}

	if !bytes.Equal(data, recv) {
		t.Fatal("data are not equal")
	}

	//write
	if _, err := c1.Write(data); err != nil {
		t.Fatal("write error:", err)
	}

	// read
	if _, err := c2.Read(recv); err != nil {
		t.Fatal("read error:", err)
	}

	if !bytes.Equal(data, recv) {
		t.Fatal("data are not equal")
	}

	// & vice versa
	//write
	if _, err := c2.Write(data); err != nil {
		t.Fatal("write error:", err)
	}

	// read
	if _, err := c1.Read(recv); err != nil {
		t.Fatal("read error:", err)
	}

	if !bytes.Equal(data, recv) {
		t.Fatal("data are not equal")
	}

	//write
	if _, err := c2.Write(data); err != nil {
		t.Fatal("write error:", err)
	}

	// read
	if _, err := c1.Read(recv); err != nil {
		t.Fatal("read error:", err)
	}

	if !bytes.Equal(data, recv) {
		t.Fatal("data are not equal")
	}
}

func TestSpliceStream(t *testing.T) {
	testSpliceStream(t, 1024*1024)
	testSpliceStream(t, 1*1024)
	testSpliceStream(t, 16*1024)
	testSpliceStream(t, 256*1024)
}
