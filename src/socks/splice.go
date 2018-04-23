// 18.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

// +build amd64,linux

package socks

import (
	"syscall"
	"net"
)

const (
	SPLICE_F_MOVE     = 1
	SPLICE_F_NONBLOCK = 2
	SPLICE_F_MORE     = 4
	SPLICE_F_GIFT     = 8

	spliceBufferSize = 0xff
)

// Splice kernel mode zero-copying method to transfer data
// http://man7.org/linux/man-pages/man2/splice.2.html
func Splice(dstFD, srcFD int) error {
	var (
		err   error
		pipe2 [2]int
	)

	// create a pipe
	if err = syscall.Pipe2(pipe2[:], syscall.O_CLOEXEC); err != nil {
		return err
	}
	defer func() {
		syscall.Close(pipe2[0])
		syscall.Close(pipe2[1])
	}()

	for {
		// splice from socket to pipe
		if _, err = syscall.Splice(srcFD, nil, pipe2[1], nil, 1<<62, SPLICE_F_MOVE); err != nil {
			return err
		}

		// splice from pipe to socket
		if _, err = syscall.Splice(pipe2[0], nil, dstFD, nil, 1<<62, SPLICE_F_MOVE); err != nil {
			return err
		}
	}

	// never reach
	return nil
}

// spliceStreams efficient kernel method to transfer data without context switching
// and additional buffering
func spliceStreams(a, b net.Conn) error {

	// getting FD handles
	aFile, err := a.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer aFile.Close()

	bFile, err := b.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer bFile.Close()

	aFD := int(bFile.Fd())
	bFD := int(aFile.Fd())

	quit := make(chan error)

	go func() {
		quit <- Splice(bFD, aFD)
	}()
	go func() {
		quit <- Splice(aFD, bFD)
	}()

	err = <-quit
	go func() { <-quit }() // avoid leaks another goroutine (or use context cancel for this purpose)

	return err
}
