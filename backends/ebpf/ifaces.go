package ebpf

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	glowdTypes "github.com/scitags/flowd-go/types"
)

// Function discoverInterfaces will inspect all the available interfaces
// on the machine and return those with an associated public IPv6 address.
func discoverInterfaces() ([]string, error) {
	iFaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting the system's interfaces: %w", err)
	}

	targetInterfaces := []string{}
	for _, iFace := range iFaces {
		addrs, err := iFace.Addrs()
		if err != nil {
			slog.Warn("couldn't get interface addresses", "interface", iFace.Name, "err", err)
			continue
		}
		for _, addr := range addrs {
			slog.Debug("interface addr", "interface", iFace.Name, "addr", addr)
			cidr, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				slog.Warn("error parsing CIDR", "interface", iFace.Name, "cidr", addr.String())
			}

			// Note how this conversion from the CIDR to a netip.Addr will ALWAYS convert
			// IPv4 addresses into 4-in-6 addresses: that's why the following check will
			// filter out all IPv4 addresses for us!
			pAddr := netip.AddrFrom16([16]byte(cidr.To16()))

			// Check if ipAddr is a 4-in-6 address: this will effectively filter out
			// all IPv4 addresses given out previous cast
			if pAddr.Unmap() != pAddr {
				slog.Debug("address is a v4-in-v6 address, skipping", "interface", iFace.Name, "cidr", cidr)
				continue
			}

			// Just to be sure: this shouldn't be necessary at all though...
			if pAddr.Is4() {
				continue
			}

			if !glowdTypes.IsIPPrivate(cidr) {
				targetInterfaces = append(targetInterfaces, iFace.Name)
				break
			}
		}
	}

	return targetInterfaces, nil
}
