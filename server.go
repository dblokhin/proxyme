package proxyme

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Options struct {
	// BindIP is public server interface (IP v4/v6) for protocol BIND operation (incoming traffic
	// from outside to client sock).
	// If not specified the socks5 BIND operation will be disabled.
	BindIP string

	// AllowNoAuth enables "NO AUTHENTICATION REQUIRED" authentication method
	AllowNoAuth bool

	// Authenticate enables USERNAME/PASSWORD authentication method.
	// Checks user credentials, non nil error causes DENIED status for client.
	Authenticate func(username, password []byte) error
	// TODO: GSSAPI

	// Connect establishes tcp sock connection to remote server, addr is host:port string.
	// If not specified, default dialer will be used that just net.Dial to remote server.
	// Use specific Connect to create custom tunnels to remote server.
	Connect func(addr string) (io.ReadWriteCloser, error)
}

type Server struct {
	protocol socks5
	done     chan any
	once     *sync.Once
}

// New returns new socks5 proxyme server
func New(opts Options) (Server, error) {
	// set up allowed authentication methods
	authMethods := make(map[authMethod]authHandler)
	if opts.AllowNoAuth {
		// enable no auth method
		authMethods[typeNoAuth] = noAuth{}
	}
	if opts.Authenticate != nil {
		// enable username/password method
		authMethods[typeLogin] = usernameAuth{opts.Authenticate}
	}

	// set up connect fn for creating tunnel to remote server
	connectFn := defaultConnect
	if opts.Connect != nil {
		// use custom fn
		connectFn = opts.Connect
	}

	// set up BIND operation setting
	var bindIP []byte
	if len(opts.BindIP) > 0 {
		addr, err := netip.ParseAddr(opts.BindIP)
		if err != nil {
			return Server{}, err
		}

		bindIP = addr.AsSlice()
	}

	return Server{
		protocol: socks5{
			authMethods: authMethods,
			bindIP:      bindIP,
			connect:     connectFn,
		},
		done: make(chan any),
		once: new(sync.Once),
	}, nil
}

func (s Server) ListenAndServe(addr string) error {
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

	client := NewClient(conn)
	state := s.protocol.initState(client)
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
