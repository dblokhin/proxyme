package proxyme

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"proxyme/protocol"
)

type Server struct {
	protocol protocol.Sock5
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
		protocol: protocol.New(addr.AsSlice()),
		done:     make(chan any),
		once:     new(sync.Once),
	}, nil
}

func (s Server) EnableNoAuth() {
	s.protocol.EnableNoAuth()
}

func (s Server) EnableUsernameAuth(fn func(user, pass []byte) error) {
	s.protocol.EnableUsernameAuth(fn)
}

func (s Server) ListenAndServer(addr string) error {
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
	defer conn.Close()

	client := protocol.NewClient(conn)
	state := s.protocol.InitState(client)
	for state != nil {
		state = state(client)
	}

	if err := client.LastError(); err != nil {
		log.Println(err)
	}
}

func (s Server) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}
