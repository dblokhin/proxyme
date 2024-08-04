package protocol

const protoVersion uint8 = 5

// identify methods
const (
	identNoAuth uint8 = 0
	identGSSAPI uint8 = 1
	identLogin  uint8 = 2
	identError  uint8 = 0xff
)

// address types based on RFC
const (
	atypIpv4       uint8 = 1
	atypDomainName uint8 = 3
	atypIpv6       uint8 = 4
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
