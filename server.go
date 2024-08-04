package proxyme

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"proxyme/protocol"
	"sync"
	"time"
)

type Server struct {
	protocol protocol.Sock5
	done     chan any
	once     *sync.Once
}

// NewServer returns new socks5 server
func NewServer(externalIP string) (Server, error) {
	addr, err := netip.ParseAddr(externalIP)
	if err != nil {
		return Server{}, err
	}

	return Server{
		protocol: protocol.Sock5{
			ExternalIP: addr.AsSlice(),
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
	defer conn.Close()

	p := protocol.NewPeer(conn)
	state := s.protocol.InitState(p)
	for state != nil {
		state = state(p)
	}

	if err := p.LastError(); err != nil {
		log.Println(err)
	}
}

func (s Server) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}
