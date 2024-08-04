package proxyme

import (
	"context"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"net"
)

func bind(dst net.Conn, ls net.Listener) {
	defer dst.Close()

	src, err := ls.Accept()
	if err != nil {
		// todo: just log
		return
	}

	log.Println("connected to bind port")

	defer src.Close()
	_ = ls.Close()

	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		log.Println(io.ReadAll(src))
		return io.EOF
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
