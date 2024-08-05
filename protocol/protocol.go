package protocol

import (
	"fmt"
	"net"
)

type State func(*Client) State

// Sock5 implements Sock5 protocol
type Sock5 struct {
	// todo proto options
	ExternalIP net.IP // external address for clients to connect
}

// InitState starts protocol negotiation
func (s Sock5) InitState(p *Client) State {
	var msg Auth

	if _, err := msg.ReadFrom(p.rdr); err != nil {
		p.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	// check version: is only SOCKS5 server
	if err := validateProtocolVersion(msg.Version); err != nil {
		p.err = err
		return nil
	}

	return s.chooseAuthState(msg)
}

func (s Sock5) chooseAuthState(msg Auth) State {
	return func(p *Client) State {
		for _, method := range msg.Methods {
			switch method {
			case identNoAuth:
				return s.authState(msg)
			case identGSSAPI:
				return s.errAuthState(msg)
			case identLogin:
				return s.errAuthState(msg)
			}
		}

		return s.errAuthState(msg)
	}
}

func (s Sock5) errAuthState(msg Auth) State {
	return func(p *Client) State {
		reply := AuthReply{Method: identError}

		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		p.err = fmt.Errorf("client sent unsupported auth methods: %v", msg.Methods)

		return nil // stop
	}
}

func (s Sock5) authState(msg Auth) State {
	return func(p *Client) State {
		reply := AuthReply{Method: identNoAuth}

		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s Sock5) newCommandState(p *Client) State {
	var msg Command

	if _, err := msg.ReadFrom(p.rdr); err != nil {
		p.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	// validate fields
	if err := validateProtocolVersion(msg.Version); err != nil {
		p.err = err
		return nil
	}

	switch msg.Cmd {
	case cmdConnect:
		return s.connectState(msg)
	case cmdBind:
		return s.bindState(msg)
	case cmdUDPAssoc:
		return s.commandErrorState(msg, replyStatusNotSupported)

	default:
		p.err = fmt.Errorf("client sent unsupported commandMessage: %d", msg.Cmd)
		return s.commandErrorState(msg, replyStatusNotSupported)
	}
}

func (s Sock5) connectState(msg Command) State {
	return func(p *Client) State {
		conn, err := net.Dial("tcp", msg.CanonicalAddr())
		if err != nil {
			p.err = fmt.Errorf("dial: %w", err)
			return s.commandErrorState(msg, replyStatusHostUnreachable)
		}

		reply := CommandReply{
			Rep:  replyStatusSucceeded,
			Rsv:  0,
			Atyp: msg.Atyp,
			Addr: msg.Addr,
			Port: msg.Port,
		}

		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		bind(conn, p.conn)

		return nil
	}
}

func (s Sock5) commandErrorState(msg Command, status uint8) State {
	reply := CommandReply{
		Rep:  status,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(p *Client) State {
		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s Sock5) bindState(msg Command) State {
	return func(p *Client) State {
		ls, err := net.Listen("tcp", fmt.Sprintf("%s:0", s.ExternalIP))
		if err != nil {
			p.err = fmt.Errorf("bind listen: %w", err)
			return s.commandErrorState(msg, replyStatusSockFailure)
		}

		port := uint16(ls.Addr().(*net.TCPAddr).Port)
		ip := ls.Addr().(*net.TCPAddr).IP

		atyp := atypIpv4
		if len(ip) != 4 {
			atyp = atypIpv6
		}

		reply := CommandReply{
			Rep:  replyStatusSucceeded,
			Rsv:  0,
			Atyp: atyp,
			Addr: s.ExternalIP,
			Port: port,
		}

		// send first reply
		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		conn, err := ls.Accept()
		if err != nil {
			p.err = fmt.Errorf("bind accept: %w", err)
			return s.commandErrorState(msg, replyStatusSockFailure)
		}

		// send first reply (on connect)
		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		bind(conn, p.conn)

		return nil
	}
}

func validateProtocolVersion(version uint8) error {
	if version != protoVersion {
		return fmt.Errorf("client sent unsupported version: %d", version)
	}

	return nil
}
