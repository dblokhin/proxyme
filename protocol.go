package proxyme

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"proxyme/messages"
)

const protoVersion uint8 = 5

// identify methods
const (
	identNoAuth uint8 = 0
	identGSSAPI uint8 = 1
	identLogin  uint8 = 2
	identError  uint8 = 0xff
)

// protocol commands
const (
	cmdConnect  uint8 = 1
	cmdBind     uint8 = 2
	cmdUDPAssoc uint8 = 3
)

// Reply status based on RFC
const (
	replyStatusSucceeded           uint8 = 0
	replyStatusSockFailure         uint8 = 1 // general SOCKS server failure
	replyStatusNowAllowed          uint8 = 2 // connection not allowed by ruleset
	replyStatusNetworkUnreachable  uint8 = 3 // Network unreachable
	replyStatusHostUnreachable     uint8 = 4 // Host unreachable
	replyStatusRefused             uint8 = 5 // Connection refused
	replyStatusTTLExpired          uint8 = 6 // TTL expired
	replyStatusNotSupported        uint8 = 7 // Command not supported
	replyStatusAddressNotSupported uint8 = 8 // Address type not supported
)

type protocolState func(*peer) protocolState

// sock5 implements sock5 protocol
type sock5 struct {
	// todo proto options
	bindIP net.IP // external address for clients to connect
}

func (s sock5) initialState(p *peer) protocolState {
	var msg messages.Auth
	if _, err := msg.ReadFrom(p.rdr); err != nil {
		p.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	log.Println("got auth", msg)

	// check version: proxyme is only SOCKS5 server
	if err := validateProtocolVersion(msg.Version); err != nil {
		p.err = err
		return nil
	}

	return s.chooseAuthState(msg)
}

func (s sock5) chooseAuthState(msg messages.Auth) protocolState {
	return func(p *peer) protocolState {
		for _, method := range msg.Methods {
			if method == identNoAuth {
				return s.noAuthState
			}
		}

		return s.errAuthState
	}
}

func (s sock5) errAuthState(p *peer) protocolState {
	// write sock5 version
	if err := binary.Write(p.wrt, binary.BigEndian, protoVersion); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	// write method ID
	if err := binary.Write(p.wrt, binary.BigEndian, identError); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	if err := p.wrt.Flush(); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	log.Println("write no auth err reply")

	return nil // stop
}

func (s sock5) noAuthState(p *peer) protocolState {
	// write sock5 version
	if err := binary.Write(p.wrt, binary.BigEndian, protoVersion); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	// write method ID
	if err := binary.Write(p.wrt, binary.BigEndian, identNoAuth); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	if err := p.wrt.Flush(); err != nil {
		p.err = fmt.Errorf("sock write: %w", err)
		return nil
	}

	log.Println("send auth reply no auth")

	return s.newCommandState
}

func (s sock5) newCommandState(p *peer) protocolState {
	var msg messages.Command

	if _, err := msg.ReadFrom(p.rdr); err != nil {
		p.err = fmt.Errorf("sock read: %w", err)
		return nil
	}

	log.Println("got command", msg)

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

func (s sock5) unsupportedCommand(msg messages.Command) protocolState {
	reply := messages.CommandReply{
		Rep:  replyStatusNotSupported,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(p *peer) protocolState {
		if _, err := reply.WriteTo(p.wrt); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		if err := p.wrt.Flush(); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		log.Println("send cmd err reply", reply)

		return s.newCommandState
	}
}

func (s sock5) connectState(msg messages.Command) protocolState {
	return func(p *peer) protocolState {
		conn, err := net.Dial("tcp", msg.CanonicalAddr())
		if err != nil {
			p.err = fmt.Errorf("dial: %w", err)
			return s.connectErrorState(msg, replyStatusHostUnreachable)
		}

		port := uint16(1200 + rand.Intn(1<<16-1-1200))
		ls, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindIP.String(), port))
		if err != nil {
			p.err = fmt.Errorf("listen: %w", err)
			return s.connectErrorState(msg, replyStatusSockFailure)
		}

		go bind(conn, ls)

		return s.connectSuccessState(s.bindIP, port)
	}
}

func (s sock5) connectSuccessState(ip []byte, port uint16) protocolState {
	reply := messages.CommandReply{
		Rep:  replyStatusSucceeded,
		Rsv:  0,
		Atyp: 1, // todo: change it
		Addr: ip,
		Port: port,
	}

	return func(p *peer) protocolState {
		if _, err := reply.WriteTo(p.wrt); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		if err := p.wrt.Flush(); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		log.Println("send cmd reply", reply)

		return s.newCommandState
	}
}

func (s sock5) connectErrorState(msg messages.Command, status uint8) protocolState {
	reply := messages.CommandReply{
		Rep:  status,
		Rsv:  0,
		Atyp: msg.Atyp,
		Addr: msg.Addr,
		Port: msg.Port,
	}

	return func(p *peer) protocolState {
		if _, err := reply.WriteTo(p.wrt); err != nil {
			p.err = fmt.Errorf("sock write: %w", err)
			return nil
		}

		if err := p.wrt.Flush(); err != nil {
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
