package stun

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

func GetPublicAddresses(c Config) (map[netip.Addr]net.IP, error) {
	dIface, err := GetDefaultInterface()
	if err != nil {
		return nil, err
	}

	ip4Addrs, ip6Addrs, err := GetInterfaceAddresses(dIface)
	if err != nil {
		return nil, err
	}

	pubIPMap := map[netip.Addr]net.IP{}

	for family, addrs := range map[int][]*net.IPNet{
		unix.AF_INET:  ip4Addrs,
		unix.AF_INET6: ip6Addrs,
	} {
		for _, addr := range addrs {
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok {
				slog.Warn("error casting net.IP to netip.Addr", "ip", addr.IP)
				continue
			}

			manual, ok := c.manualMappingParsed[ip]
			if ok {
				pubIPMap[ip] = manual
				continue
			}

			// Only applicable for AF_INET6, but it doesn't hurt for AF_INET
			if types.IsIPLinkLocal(addr.IP) {
				continue
			}

			// If private, get a public address through STUN, DNS, HTTP...
			if types.IsIPPrivate(addr.IP) {
				pub, err := GetPubIPOverHTTP(c, family, addr.IP)
				if err == nil {
					pubIPMap[ip] = pub
					continue
				}
				slog.Warn("couldn't resolve public ip over HTTP", "err", err)

				pub, err = GetPubIPOverSTUN(c, family, addr.IP)
				if err == nil {
					pubIPMap[ip] = pub
				}
				slog.Warn("couldn't resolve public IP over STUN", "err", err)

				continue
			}

			pubIPMap[ip] = addr.IP
		}
	}

	if len(pubIPMap) == 0 {
		return nil, fmt.Errorf("didn't get any public IPs")
	}

	return pubIPMap, nil
}
