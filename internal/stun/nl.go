package stun

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink/v2/rtnl"
	"golang.org/x/sys/unix"
)

const (
	// PUB_IP is an IPv4 known to be public. We've chosen the Quad9 DNS
	// resolver.
	PUB_IP string = "9.9.9.9"
)

func GetDefaultInterface() (*net.Interface, error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't open a rtnl connection: %w", err)
	}
	defer conn.Close()

	r, err := conn.RouteGet(net.ParseIP(PUB_IP))
	if err != nil {
		return nil, fmt.Errorf("error getting routes: %w", err)
	}

	return r.Interface, nil
}

func GetInterfacePrefixes(iface *net.Interface) ([]netip.Prefix, []netip.Prefix, error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't open a rtnl connection: %w", err)
	}
	defer conn.Close()

	ip4Addrs, err := conn.Addrs(iface, unix.AF_INET)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving ip4 addresses: %w", err)
	}

	// Translate old net stuff to netip!
	ip4Prefixes := []netip.Prefix{}
	for _, addr := range ip4Addrs {
		nAddr, _ := netip.AddrFromSlice(addr.IP)
		cidr, _ := addr.Mask.Size()
		ip4Prefixes = append(ip4Prefixes, netip.PrefixFrom(nAddr, cidr))
	}

	ip6Addrs, err := conn.Addrs(iface, unix.AF_INET6)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving ip6 addresses: %w", err)
	}

	// Translate old net stuff to netip!
	ip6Prefixes := []netip.Prefix{}
	for _, addr := range ip6Addrs {
		nAddr, _ := netip.AddrFromSlice(addr.IP)
		cidr, _ := addr.Mask.Size()
		ip6Prefixes = append(ip6Prefixes, netip.PrefixFrom(nAddr, cidr))
	}

	return ip4Prefixes, ip6Prefixes, nil
}
