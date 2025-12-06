package types

import (
	"fmt"
	"net/netip"
)

/*
 * Even if it's abusing the naming a bit, we'll include goodies dealing with
 * IPv{4,6} addresses here, as it's something needed by several plugins and
 * backends.
 */

func parseCidr(network string, comment string) netip.Prefix {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		panic(fmt.Sprintf("error parsing %s (%s): %v", network, comment, err))
	}
	return prefix
}

var (
	linkLocalNet = parseCidr("fe80::/10", "RFC 4291: Link-Local Unicast")

	// This has been shamelessly plundered from [0]. Thanks a ton for keeping all this up to date!
	//   0: https://raw.githubusercontent.com/letsencrypt/boulder/refs/heads/main/bdns/dns.go

	// Private IPv4 CIDRs obtained from [0].
	//   0: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	privateNetworks = []netip.Prefix{
		parseCidr("0.0.0.0/8", "RFC 791, Section 3.2: This network"),
		parseCidr("0.0.0.0/32", "RFC 1122, Section 3.2.1.3: This host on this network"),
		parseCidr("10.0.0.0/8", "RFC 1918: Private-Use"),
		parseCidr("100.64.0.0/10", "RFC 6598: Shared Address Space"),
		parseCidr("127.0.0.0/8", "RFC 1122, Section 3.2.1.3: Loopback"),
		parseCidr("169.254.0.0/16", "RFC 3927: Link Local"),
		parseCidr("172.16.0.0/12", "RFC 1918: Private-Use"),
		parseCidr("192.0.0.0/24", "RFC 6890, Section 2.1: IETF Protocol Assignments"),
		parseCidr("192.0.0.0/29", "RFC 7335: IPv4 Service Continuity Prefix"),
		parseCidr("192.0.0.8/32", "RFC 7600: IPv4 dummy address"),
		parseCidr("192.0.0.9/32", "RFC 7723: Port Control Protocol Anycast"),
		parseCidr("192.0.0.10/32", "RFC 8155: Traversal Using Relays around NAT Anycast"),
		parseCidr("192.0.0.170/32", "RFC 8880 & RFC 7050, Section 2.2: NAT64/DNS64 Discovery"),
		parseCidr("192.0.0.171/32", "RFC 8880 & RFC 7050, Section 2.2: NAT64/DNS64 Discovery"),
		parseCidr("192.0.2.0/24", "RFC 5737: Documentation (TEST-NET-1)"),
		parseCidr("192.31.196.0/24", "RFC 7535: AS112-v4"),
		parseCidr("192.52.193.0/24", "RFC 7450: AMT"),
		parseCidr("192.88.99.0/24", "RFC 7526: Deprecated (6to4 Relay Anycast)"),
		parseCidr("192.168.0.0/16", "RFC 1918: Private-Use"),
		parseCidr("192.175.48.0/24", "RFC 7534: Direct Delegation AS112 Service"),
		parseCidr("198.18.0.0/15", "RFC 2544: Benchmarking"),
		parseCidr("198.51.100.0/24", "RFC 5737: Documentation (TEST-NET-2)"),
		parseCidr("203.0.113.0/24", "RFC 5737: Documentation (TEST-NET-3)"),
		parseCidr("240.0.0.0/4", "RFC1112, Section 4: Reserved"),
		parseCidr("255.255.255.255/32", "RFC 8190 & RFC 919, Section 7: Limited Broadcast"),
		// 224.0.0.0/4 are multicast addresses as per RFC 3171. They are not
		// present in the IANA registry.
		parseCidr("224.0.0.0/4", "RFC 3171: Multicast Addresses"),

		// Private IPv6 CIDRs obtained from [0].
		//   0: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
		parseCidr("::/128", "RFC 4291: Unspecified Address"),
		parseCidr("::1/128", "RFC 4291: Loopback Address"),
		// parseCidr("::ffff:0:0/96", "RFC 4291: IPv4-mapped Address"),
		parseCidr("64:ff9b::/96", "RFC 6052: IPv4-IPv6 Translat."),
		parseCidr("64:ff9b:1::/48", "RFC 8215: IPv4-IPv6 Translat."),
		parseCidr("100::/64", "RFC 6666: Discard-Only Address Block"),
		parseCidr("2001::/23", "RFC 2928: IETF Protocol Assignments"),
		parseCidr("2001::/32", "RFC 4380 & RFC 8190: TEREDO"),
		parseCidr("2001:1::1/128", "RFC 7723: Port Control Protocol Anycast"),
		parseCidr("2001:1::2/128", "RFC 8155: Traversal Using Relays around NAT Anycast"),
		parseCidr("2001:1::3/128", "RFC-ietf-dnssd-srp-25: DNS-SD Service Registration Protocol Anycast"),
		parseCidr("2001:2::/48", "RFC 5180 & RFC Errata 1752: Benchmarking"),
		parseCidr("2001:3::/32", "RFC 7450: AMT"),
		parseCidr("2001:4:112::/48", "RFC 7535: AS112-v6"),
		parseCidr("2001:10::/28", "RFC 4843: Deprecated (previously ORCHID)"),
		parseCidr("2001:20::/28", "RFC 7343: ORCHIDv2"),
		parseCidr("2001:30::/28", "RFC 9374: Drone Remote ID Protocol Entity Tags (DETs) Prefix"),
		parseCidr("2001:db8::/32", "RFC 3849: Documentation"),
		parseCidr("2002::/16", "RFC 3056: 6to4"),
		parseCidr("2620:4f:8000::/48", "RFC 7534: Direct Delegation AS112 Service"),
		parseCidr("3fff::/20", "RFC 9637: Documentation"),
		parseCidr("5f00::/16", "RFC 9602: Segment Routing (SRv6) SIDs"),
		parseCidr("fc00::/7", "RFC 4193 & RFC 8190: Unique-Local"),
		linkLocalNet,
		// ff00::/8 are multicast addresses as per RFC 4291, Sections 2.4 & 2.7.
		// They are not present in the IANA registry.
		parseCidr("ff00::/8", "RFC 4291: Multicast Addresses"),
	}
)

// IsIPPrivate will return true whenever the provided netip.Prefix belongs to a
// private range as defined per IANA.
func IsIPPrivate(ip netip.Addr) bool {
	for _, ipnet := range privateNetworks {
		if ipnet.Contains(ip) {
			// slog.Debug("ip is private", "i", i, "ip", ip, "ipnet", ipnet)
			return true
		}
	}
	return false
}

func IsIPLinkLocal(ip netip.Addr) bool {
	// What about prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLinkLocalMulticast()?
	if linkLocalNet.Contains(ip) {
		// slog.Debug("ip is a link-local address", "ip", ip, "ipnet", linkLocalNet)
		return true
	}
	return false
}
