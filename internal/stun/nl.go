package stun

import (
	"fmt"
	"net"

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
