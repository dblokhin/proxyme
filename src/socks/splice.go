// 18.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

// +build amd64,linux

package socks

import (
	"syscall"
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

	var (
		err1, err2         error
		wg                 sync.WaitGroup
	)

	for {
		wg.Add(2)

		go func() {
			// splice from socket to pipe
			_, err1 = syscall.Splice(srcFD, nil, pipe2[1], nil, 1 << 62, SPLICE_F_MOVE)

			wg.Done()
		}()

		go func() {
			// splice from pipe to socket
			_, err2 = syscall.Splice(pipe2[0], nil, dstFD, nil, 1 << 62, SPLICE_F_MOVE)

			wg.Done()
		}()

		wg.Wait()

		if err1 != nil {
			return err1
		}

		if err2 != nil {
			return err2
		}
	}

	// never reach
	return nil
}
