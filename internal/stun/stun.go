package stun

// Consider using github.com/tailscale/tailscale/net/stun instead!
import (
	"fmt"
	"net"
	"strconv"

	// "github.com/ccding/go-stun/stun"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v3/stdnet"
)

type IPFamily int

const (
	IPv4 = iota
	IPv6
)

func (iF IPFamily) String() string {
	repr, ok := piFamilyMap[iF]
	if !ok {
		return "unknown"
	}
	return repr
}

var (
	ipFamilyMap = map[IPFamily]string{
		IPv4: "udp4",
		IPv6: "udp6",
	}

	piFamilyMap = map[IPFamily]string{
		IPv4: "IPv4",
		IPv6: "IPv6",
	}

	stunServers = [...]string{
		"stun:stun.l.google.com:19302",
		"stun:stun.services.mozilla.org:3478",
	}
)

func GetPubIPOverSTUN(ipFamily IPFamily) (net.IP, error) {
	// Parse a STUN URI
	u, err := stun.ParseURI(stunServers[0])
	if err != nil {
		return nil, fmt.Errorf("couldn't parse the STUN uri: %w", err)
	}

	// Creating a "connection" to STUN server. The following have been 'ripped'
	// from the DialURI method so as to allow the selection of the dialNetwork
	// to force the use of either IPv4 or IPv6.
	var conn stun.Connection
	nw, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("failed to create network for STUN client: %w", err)
	}
	addr := net.JoinHostPort(u.Host, strconv.Itoa(u.Port))

	dialNet, ok := ipFamilyMap[ipFamily]
	if !ok {
		return nil, fmt.Errorf("chosen IP Family (%s) is not correct", ipFamily)
	}
	if conn, err = nw.Dial(dialNet, addr); err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	c, err := stun.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("error creating the client: %w", err)
	}

	// Building binding request with random transaction id.
	message, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, fmt.Errorf("error building ")
	}

	var (
		parsedIP   net.IP
		closureErr error
	)
	// Sending request to STUN server, waiting for response message.
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			closureErr = res.Error
			return
		}

		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			closureErr = err
			return
		}
		parsedIP = xorAddr.IP
	}); err != nil {
		return nil, fmt.Errorf("error making the request: %w", closureErr)
	}

	return parsedIP, nil
}

// Implementation of RFC 5389. This can also be accomplished with Pion as seen
// on https://github.com/pion/stun/blob/959cdb5320679144547cac716f2cb7b52fea4d74/cmd/stun-nat-behaviour/main.go,
// but it's not really necessary for us as we just want the external IPs...
// func STUN5389() (net.IP, error) {
// 	natType, hostInfo, err := stun.NewClient().Discover()
// 	if err != nil {
// 		return nil, fmt.Errorf("error discovering STUN info: %w", err)
// 	}
// 	slog.Debug("detected NAT", "type", natType.String())

// 	slog.Debug("detected host info", "family", hostInfo.Family(), "port", hostInfo.Port(),
// 		"transportAddr", hostInfo.TransportAddr())

// 	parsedIP := net.ParseIP(hostInfo.IP())
// 	if parsedIP == nil {
// 		return nil, fmt.Errorf("discovered STUN IP (%s) couldn't be parsed", hostInfo.IP())
// 	}

// 	return parsedIP, nil
// }
