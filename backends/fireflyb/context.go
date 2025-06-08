package fireflyb

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/enrichment/netlink"

	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) addNetlinkContext(family uint8, srcPort, dstPort uint16) (*glowdTypes.Enrichment, error) {
	nlReplies, err := netlink.NewTCPDiagRequest(family, srcPort, dstPort).ExecuteRequest()
	if err != nil {
		return nil, fmt.Errorf("couldn't execute the netlink request: %w", err)
	}

	switch len(nlReplies) {
	case 0:
		// Depending on how sockets are opened, we can find a case where IPv4 sockets are actually
		// 'multiplexed' on IPv6 sockets and their addresses are 4-in-6 (i.e. IPv4 addresses with
		// some leaading 0s and 0xFFs). Within the Linux kernel these sockets belong to the IPv6
		// 'realm'... Note we are safe when recursively calling addNetlinkContext given we force
		// the value of the family! By the way, be sure to check ipv6(7), specially the section
		// on IPV6_V6ONLY and the last paragraphs of the description.
		if family == uint8(glowdTypes.IPv4) {
			slog.Debug("trying to get info from the IPv6 realm on an IPv4 flow...")
			return b.addNetlinkContext(uint8(glowdTypes.IPv6), srcPort, dstPort)
		}

		return nil, fmt.Errorf("got no information from netlink")
	case 1:
		return nlReplies[0], nil
	default:
		slog.Warn("got information for more than one flow...")

		// TODO: Filter replies from netlink based on IPv{4,6} addresses
		return nlReplies[0], nil
	}
}
