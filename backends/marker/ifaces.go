//go:build linux && ebpf

package marker

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/scitags/flowd-go/types"
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

			if types.IsIPv4(cidr) {
				slog.Debug("address is IPv4", "interface", iFace.Name, "cidr", cidr)
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
