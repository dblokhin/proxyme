package protocol

import (
	"fmt"
	"net"
)

type State func(*Peer) State

// Sock5 implements Sock5 protocol
type Sock5 struct {
	// todo proto options
	ExternalIP net.IP // external address for clients to connect
}

// InitState starts protocol negotiation
func (s Sock5) InitState(p *Peer) State {
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
	return func(p *Peer) State {
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
	return func(p *Peer) State {
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
	return func(p *Peer) State {
		reply := AuthReply{Method: identNoAuth}

		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s Sock5) newCommandState(p *Peer) State {
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

	if err := validateProtocolCommand(msg.Cmd); err != nil {
		p.err = err
		return s.unsupportedCommand(msg)
	}

	return s.connectState(msg)
}

func (s Sock5) unsupportedCommand(msg Command) State {
	reply := CommandReply{
		Rep:  replyStatusNotSupported,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(p *Peer) State {
		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func (s Sock5) connectState(msg Command) State {
	return func(p *Peer) State {
		conn, err := net.Dial("tcp", msg.CanonicalAddr())
		if err != nil {
			p.err = fmt.Errorf("dial: %w", err)
			return s.connectErrorState(msg, replyStatusHostUnreachable)
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

func (s Sock5) connectErrorState(msg Command, status uint8) State {
	reply := CommandReply{
		Rep:  status,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(p *Peer) State {
		if err := p.WriteMessage(reply); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		return s.newCommandState
	}
}

func validateProtocolVersion(version uint8) error {
	if version != protoVersion {
		return fmt.Errorf("client sent unsupported version: %d", version)
	}

	return nil
}

func validateProtocolCommand(cmd uint8) error {
	if cmd != cmdConnect {
		return fmt.Errorf("client sent unsupported commandMessage: %d", cmd)
	}

	return nil
}
