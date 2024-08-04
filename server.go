package proxyme

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Server struct {
	protocol sock5
	done     chan any
	once     *sync.Once
}

// NewServer returns new socks5 server
func NewServer(bindIP string) (Server, error) {
	addr, err := netip.ParseAddr(bindIP)
	if err != nil {
		return Server{}, err
	}

	return Server{
		protocol: sock5{
			bindIP: addr.AsSlice(),
		},
		done: make(chan any),
		once: new(sync.Once),
	}, nil
}

func (s Server) Run(addr string) error {
	ls, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen: %q", err)
	}

	defer s.Close()

	go func() {
		<-s.done
		_ = ls.Close()
	}()

	for {
		conn, err := ls.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(time.Second / 5)
				continue
			}

			return fmt.Errorf("accept: %w", err)
		}

		go s.handle(conn)
	}
}

func (s Server) handle(conn net.Conn) {
	const (
		readBuffer  = 32 * 1024
		writeBuffer = 4 * 1024
	)
	rdr := bufio.NewReaderSize(conn, readBuffer)
	wrt := bufio.NewWriterSize(conn, writeBuffer)
	p := &peer{
		rdr: rdr,
		wrt: wrt,
	}
	defer conn.Close()

	state := s.protocol.initialState(p)
	for state != nil {
		state = state(p)
	}

	log.Println(p.err)
}

func (s Server) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}
