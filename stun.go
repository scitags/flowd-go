package glowd

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

// MustParseCIDR parses string into net.IPNet
func MustParseCIDR(s string) net.IPNet {
	if _, ipnet, err := net.ParseCIDR(s); err != nil {
		panic(err)
	} else {
		return *ipnet
	}
}

// DefaultFilteredNetworks net.IPNets that are loopback, private, link local, default unicast
// based on https://github.com/letsencrypt/boulder/blob/master/bdns/dns.go
var DefaultFilteredNetworks = []net.IPNet{
	MustParseCIDR("10.0.0.0/8"),         // RFC1918
	MustParseCIDR("172.16.0.0/12"),      // private
	MustParseCIDR("192.168.0.0/16"),     // private
	MustParseCIDR("127.0.0.0/8"),        // RFC5735
	MustParseCIDR("0.0.0.0/8"),          // RFC1122 Section 3.2.1.3
	MustParseCIDR("169.254.0.0/16"),     // RFC3927
	MustParseCIDR("192.0.0.0/24"),       // RFC 5736
	MustParseCIDR("192.0.2.0/24"),       // RFC 5737
	MustParseCIDR("198.51.100.0/24"),    // Assigned as TEST-NET-2
	MustParseCIDR("203.0.113.0/24"),     // Assigned as TEST-NET-3
	MustParseCIDR("192.88.99.0/24"),     // RFC 3068
	MustParseCIDR("192.18.0.0/15"),      // RFC 2544
	MustParseCIDR("224.0.0.0/4"),        // RFC 3171
	MustParseCIDR("240.0.0.0/4"),        // RFC 1112
	MustParseCIDR("255.255.255.255/32"), // RFC 919 Section 7
	MustParseCIDR("100.64.0.0/10"),      // RFC 6598
	MustParseCIDR("::/128"),             // RFC 4291: Unspecified Address
	MustParseCIDR("::1/128"),            // RFC 4291: Loopback Address
	MustParseCIDR("100::/64"),           // RFC 6666: Discard Address Block
	MustParseCIDR("2001::/23"),          // RFC 2928: IETF Protocol Assignments
	MustParseCIDR("2001:2::/48"),        // RFC 5180: Benchmarking
	MustParseCIDR("2001:db8::/32"),      // RFC 3849: Documentation
	MustParseCIDR("2001::/32"),          // RFC 4380: TEREDO
	MustParseCIDR("fc00::/7"),           // RFC 4193: Unique-Local
	MustParseCIDR("fe80::/10"),          // RFC 4291: Section 2.5.6 Link-Scoped Unicast
	MustParseCIDR("ff00::/8"),           // RFC 4291: Section 2.7
	MustParseCIDR("2002::/16"),          // RFC 7526: 6to4 anycast prefix deprecated
}

// FindIPNet true if any of the ipnets contains ip
func IsIPPrivate(ip net.IP) bool {
	for _, ipnet := range DefaultFilteredNetworks {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
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

func GetExternalIP(ipFamily IPFamily) (net.IP, error) {
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

func GetDefaultOutboundIP(ipFamily IPFamily) (net.IP, error) {
	dialNet, ok := ipFamilyMap[ipFamily]
	if !ok {
		return nil, fmt.Errorf("chosen IP Family (%s) is not correct", ipFamily)
	}
	conn, err := net.Dial(dialNet, "dns.google.com:80")
	if err != nil {
		return nil, fmt.Errorf("couldn't dial 8.8.8.8:80: %w", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP, nil
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
