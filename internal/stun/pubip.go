package stun

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

func GetPublicAddresses(c Config) (map[netip.Addr]netip.Addr, error) {
	dIface, err := GetDefaultInterface()
	if err != nil {
		return nil, err
	}

	ip4Addrs, ip6Addrs, err := GetInterfacePrefixes(dIface)
	if err != nil {
		return nil, err
	}

	pubIPMap := map[netip.Addr]netip.Addr{}

	for family, prefixes := range map[int][]netip.Prefix{
		unix.AF_INET:  ip4Addrs,
		unix.AF_INET6: ip6Addrs,
	} {
		for _, prefix := range prefixes {
			addr := prefix.Addr()

			slog.Debug("mapping ip", "ip", addr)

			manual, ok := c.manualMappingParsed[addr]
			if ok {
				slog.Debug("adding manual mapping", "privIp", addr, "pubIp", manual)
				pubIPMap[addr] = manual
				continue
			}

			// Only applicable for AF_INET6, but it doesn't hurt for AF_INET
			if types.IsIPLinkLocal(addr) {
				slog.Debug("ip is a link-local address", "ip", addr)
				continue
			}

			// If private, get a public address through STUN, DNS, HTTP...
			if types.IsIPPrivate(addr) {
				slog.Debug("trying to get public IP over HTTP")
				pub, err := GetPubIPOverHTTP(c, family, addr)
				if err == nil {
					slog.Debug("got public ip over HTTP", "pubIp", pub)
					pubIPMap[addr] = pub
					continue
				}
				slog.Warn("couldn't resolve public ip over HTTP", "err", err)

				slog.Debug("trying to get public IP over STUN")
				pub, err = GetPubIPOverSTUN(c, family, addr)
				if err == nil {
					slog.Debug("got public ip over STUN", "pubIp", pub)
					pubIPMap[addr] = pub
					continue
				}
				slog.Warn("couldn't resolve public IP over STUN", "err", err)

				continue
			}

			slog.Debug("ip is public", "ip", addr)
		}
	}

	if len(pubIPMap) == 0 {
		return nil, fmt.Errorf("didn't get any public IPs")
	}

	return pubIPMap, nil
}
