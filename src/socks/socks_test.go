// 15.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"testing"
	"io"
	"time"
	"net"
	"crypto/rand"
	"io/ioutil"
)


type myConn struct {
	R io.Reader
	W io.Writer
}

func (rw *myConn) Read(b []byte) (n int, err error) {
	return rw.R.Read(b)
}

func (rw *myConn) Write(b []byte) (n int, err error) {
	return rw.W.Write(b)
}
func (rw *myConn) Close() error {
	return nil
}

// LocalAddr returns the local network address.
func (rw *myConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remote network address.
func (rw *myConn) RemoteAddr() net.Addr {
	return nil
}

func (rw *myConn) SetDeadline(t time.Time) error {
	return nil
}

func (rw *myConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (rw *myConn) SetWriteDeadline(t time.Time) error {
	return nil
}


func BenchmarkIOCopyBuffPool(b *testing.B) {
	src := &myConn{
		R: io.LimitReader(rand.Reader, 12*1024),
		W: ioutil.Discard,
	}

	dst := &myConn{
		R: io.LimitReader(rand.Reader, 48*1024),
		W: ioutil.Discard,
	}

	incomingBuff := reBuffer{
		queue:    make(chan []byte, 100),
		maxSize:  100,
		buffSize: 2 * 1024,
	}

	outcomingBuff := reBuffer{
		queue:    make(chan []byte, 100),
		maxSize:  100,
		buffSize: 32 * 1024,
	}

	for i := 0; i < b.N; i++ {
		go func() {
			// get reusable buff
			buff := incomingBuff.Get()
			ioCopyBuff(dst, src, buff)
			incomingBuff.Put(buff)
		}()

		go func() {
			// get reusable buff
			buff := outcomingBuff.Get()
			ioCopyBuff(dst, src, buff)
			outcomingBuff.Put(buff)
		}()
	}
}
