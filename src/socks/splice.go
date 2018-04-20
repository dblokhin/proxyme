// 18.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

// +build amd64,linux

package socks

import (
	"syscall"
	"net"
	"sync"
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
func Splice(dst net.Conn, src net.Conn) (int64, error) {
	var (
		err   error
		pipe2 [2]int
	)

	// creates a pipe
	if err = syscall.Pipe2(pipe2[:], syscall.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer func() {
		syscall.Close(pipe2[0])
		syscall.Close(pipe2[1])
	}()

	// getting FD handles
	dstFile, err := dst.(*net.TCPConn).File()
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	srcFile, err := src.(*net.TCPConn).File()
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	var (
		written1, written2 int64
		err1, err2         error
		wg                 sync.WaitGroup
	)

	for {
		wg.Add(2)
		go func() {
			// splice from socket to pipe
			written1, err1 = syscall.Splice(int(srcFile.Fd()), nil, pipe2[1], nil, spliceBufferSize, SPLICE_F_MOVE)

			wg.Done()
		}()

		go func() {
			// splice from pipe to socket
			written2, err2 = syscall.Splice(pipe2[0], nil, int(dstFile.Fd()), nil, spliceBufferSize, SPLICE_F_MOVE)

			wg.Done()
		}()

		wg.Wait()

		if err1 != nil {
			return 0, err1
		}

		if err2 != nil {
			return 0, err2
		}
	}

	return written1, nil
}
