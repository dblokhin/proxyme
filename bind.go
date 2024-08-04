package proxyme

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
		for {
			if _, err := io.Copy(dst, src); err != nil {
				return err
			}
		}
	})

	eg.Go(func() error {
		for {
			if _, err := io.Copy(src, dst); err != nil {
				return err
			}
		}
	})

	_ = eg.Wait()
}
