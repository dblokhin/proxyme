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

// GSSAPI provides contract to implement GSSAPI boilerplate.
// Proxyme refuses client if following methods return non-nil error
type GSSAPI interface {
	// AcceptContext accepts client gssapi token produced by gss_init_sec_context.
	// Token is the opaque authentication token emitted by client GSS-API.
	// When calling gss_accept_sec_context() for the first time, the
	// context_handle argument is initially set to GSS_C_NO_CONTEXT.
	//
	// For portability, verifier_cred_handle is set to GSS_C_NO_CREDENTIAL
	// to specify default credentials (for acceptor usage).
	//
	// If gss_accept_sec_context returns GssContinueNeeded, the server
	// should return the generated output_token to the client, and
	// subsequently pass the resulting client supplied token to another call
	// to gss_accept_sec_context.
	//
	// If gss_accept_sec_context returns GssSComplete, then, if an
	// output_token is returned, the server should return it to the client.
	//
	// If no token is returned, a zero length token should be sent by the
	// server to signal to the client that it is ready to receive the
	// client's request.
	AcceptContext(token []byte) (complete bool, outputToken []byte, err error)

	// AcceptProtectionLevel adjusts protection level.
	// The default value of quality of protection shall be specified, and
	// the use of conf_req_flag shall be as determined by the previous
	// subnegotiation step.  If protection level 1 is agreed then
	// conf_req_flag MUST always be FALSE; if protection level 2 is agreed
	// then conf_req_flag MUST always be TRUE; and if protection level 3 is
	// agreed then conf_req is determined on a per-message basis by client
	// and server using local configuration.
	//
	// The security context protection level sent by client and server must
	// be one of the following values (byte):
	//         1 required per-message integrity
	//         2 required per-message integrity and confidentiality
	//         3 selective per-message integrity or confidentiality based on
	//           local client and server configurations
	//
	// Also lvl can be 0 meaning no protection. Returns security
	//   context protection level which it agrees to.
	AcceptProtectionLevel(lvl byte) (byte, error)

	// The token is produced by encapsulating an octet containing the
	// required protection level using gss_seal()/gss_wrap() with conf_req
	// set to FALSE.  The token is verified using gss_unseal()/
	// gss_unwrap().
	// For TCP and UDP clients and servers, the GSS-API functions for
	// encapsulation and de-encapsulation shall be used by implementations -
	// i.e. gss_seal()/gss_wrap(), and gss_unseal()/ gss_unwrap().
	//

	// Encode produces output token signing/encrypting the data based on protection level.
	Encode(data []byte) (output []byte, err error)

	// Decode verifies/decrypts token and returns payload.
	Decode(token []byte) (data []byte, err error)
}

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

	// GSSAPI enables GSS-API authentication method.
	// This func is called whenever new GSSAPI client connects to get an object
	// implementing GSSAPI interface.
	GSSAPI func() (GSSAPI, error)

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
		authMethods[typeNoAuth] = &noAuth{}
	}
	if opts.Authenticate != nil {
		// enable username/password method
		authMethods[typeLogin] = &usernameAuth{
			authenticator: opts.Authenticate,
		}
	}
	if opts.GSSAPI != nil {
		// enable gssapi interface
		authMethods[typeLogin] = &gssapiAuth{
			gssapi: opts.GSSAPI,
		}
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

func (s Server) ListenAndServe(network, addr string) error {
	ls, err := net.Listen(network, addr)
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
