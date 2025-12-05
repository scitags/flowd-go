package stun

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink/v2/rtnl"
	"github.com/scitags/flowd-go/types"
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

func GetInterfaceAddresses(iface *net.Interface) ([]*net.IPNet, []*net.IPNet, error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't open a rtnl connection: %w", err)
	}
	defer conn.Close()

	ip4Addrs, err := conn.Addrs(iface, unix.AF_INET)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving ip4 addresses: %w", err)
	}

	ip6Addrs, err := conn.Addrs(iface, unix.AF_INET6)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving ip6 addresses: %w", err)
	}

	return ip4Addrs, ip6Addrs, nil
}

func GetPublicAddresses() (map[netip.Addr]net.IP, error) {
	dIface, err := GetDefaultInterface()
	if err != nil {
		return nil, err
	}

	ip4Addrs, ip6Addrs, err := GetInterfaceAddresses(dIface)
	if err != nil {
		return nil, err
	}

	pubIPMap := map[netip.Addr]net.IP{}
	for _, addr := range append(ip4Addrs, ip6Addrs...) {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			slog.Warn("error casting net.IP to netip.Addr", "ip", addr.IP)
			continue
		}

		if types.IsIPLinkLocal(addr.IP) {
			continue
		}

		// If private, get a public address through STUN, DNS, HTTP...
		if types.IsIPPrivate(addr.IP) {
			pub, err := GetPubIPOverHTTP(addr.IP)
			if err == nil {
				pubIPMap[ip] = pub
				continue
			}
			slog.Warn("couldn't resolve public ip over HTTP", "err", err)
			continue
		}

		pubIPMap[ip] = addr.IP
	}

	return pubIPMap, nil
}
