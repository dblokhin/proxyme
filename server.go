package proxyme

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

const defaultMaxConnIdle = 3 * time.Minute

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
	// token (input/output) must be less than 2^16 bytes
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

	// Encode produces output token signing/encrypting the data based on protection level.
	Encode(data []byte) (output []byte, err error)

	// Decode verifies/decrypts token and returns payload.
	Decode(token []byte) (data []byte, err error)
}

type Options struct {
	// AllowNoAuth enables "NO AUTHENTICATION REQUIRED" authentication method
	// OPTIONAL, default disabled.
	AllowNoAuth bool

	// Authenticate enables USERNAME/PASSWORD authentication method.
	// Checks user credentials, non nil error causes DENIED status for client.
	// OPTIONAL, default disabled.
	Authenticate func(username, password []byte) error

	// GSSAPI enables GSS-API authentication method.
	// This func is called whenever new GSSAPI client connects to get an object
	// implementing GSSAPI interface.
	// OPTIONAL, default disabled.
	GSSAPI func() (GSSAPI, error)

	// Connect establishes tcp sock connection to remote server.
	// If not specified, default connect will be used that just use net.Dial to remote server.
	//
	// Use specific Connect to create custom dns resolvers, specific connections to remote server.
	//
	// Connect SHOULD return one the following errors: ErrNotAllowed, ErrHostUnreachable, ErrNetworkUnreachable,
	// ErrConnectionRefused, ErrTTLExpired. According to this errors Server responds corresponding reply status:
	//  o  X'00' succeeded  <- Connect returns no errors
	//  o  X'01' general SOCKS server failure <- Connect returns other errors
	//  o  X'02' connection not allowed by ruleset
	//  o  X'03' Network unreachable
	//  o  X'04' Host unreachable
	//  o  X'05' Connection refused
	//  o  X'06' TTL expired
	//
	// addressType here is type of addr in terms of SOCKS5 RFC1928, it's guarantee that value will be on of those:
	// o  ATYP   address type of following address
	//    o  IP V4 address: X'01' -> addr contains net.IP
	//    o  DOMAINNAME: X'03'    -> addr contains domain name
	//    o  IP V6 address: X'04' -> addr contains net.IP
	// OPTIONAL
	Connect func(ctx context.Context, addressType int, addr []byte, port string) (io.ReadWriteCloser, error)

	// Bind returns listener to accept incoming connections for protocol BIND operation:
	// incoming traffic from outside to client sock.
	// If not specified the SOCKS5 BIND operation will be rejected with notAllowed status.
	// OPTIONAL.
	Bind func() (net.Listener, error)

	// MaxConnIdle defines maximum duration for inactive tcp connections.
	// OPTIONAL, default 3 minutes.
	MaxConnIdle time.Duration
}

// New returns new SOCKS5 proxyme server
func New(opts Options) (SOCKS5, error) {
	// set up allowed authentication methods
	auth, err := getAuthHandlers(opts)
	if err != nil {
		return SOCKS5{}, err
	}

	// set up CONNECT command callback
	connectFn := defaultConnect
	if opts.Connect != nil {
		// use custom fn
		connectFn = opts.Connect
	}

	// setup network maxConnIdle
	maxConnIdle := defaultMaxConnIdle
	if opts.MaxConnIdle > 0 {
		maxConnIdle = opts.MaxConnIdle
	}

	return SOCKS5{
		auth:    auth,
		bind:    opts.Bind,
		connect: connectFn,
		timeout: maxConnIdle,
	}, nil
}

func getAuthHandlers(opts Options) (map[authMethod]authHandler, error) {
	res := make(map[authMethod]authHandler)

	if opts.AllowNoAuth {
		// enable no authenticate method
		res[typeNoAuth] = &noAuth{}
	}
	if opts.Authenticate != nil {
		// enable username/password method
		res[typeLogin] = &usernameAuth{
			authenticator: opts.Authenticate,
		}
	}
	if opts.GSSAPI != nil {
		// enable gssapi interface
		res[typeLogin] = &gssapiAuth{
			gssapi: opts.GSSAPI,
		}
	}

	if len(res) == 0 {
		return nil, errors.New("none of SOCKS5 authenticate method are specified")
	}

	return res, nil
}

// Handle handles client connection into SOCKS5, starts SOCKS5 protocol negation.
func (s SOCKS5) Handle(conn io.ReadWriteCloser, onError func(error)) {
	state := state{
		opts: s,
		conn: conn,
	}

	for fnState, err := initial(&state); fnState != nil; {
		if err != nil && onError != nil {
			onError(err)
		}
		fnState, err = fnState(&state)
	}
}
