package protocol

import (
	"context"
	"golang.org/x/sync/errgroup"
	"io"
	"net"
)

func bind(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		_, err := io.Copy(dst, src)
		return err
	})

	eg.Go(func() error {
		_, err := io.Copy(src, dst)
		return err
	})

	eg.Wait()
}
