package subcmd

import (
	"log/slog"
	"net/netip"

	"github.com/scitags/flowd-go/internal/stun"
	"github.com/scitags/flowd-go/types"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func init() {
	StunSample.PersistentFlags().StringVar(&stunServer, "stun-server", "stun.l.google.com:3478", "stun server")
}

var (
	stunServer string

	StunSample = &cobra.Command{
		Use:   "sample",
		Short: "Resolve the default interface's public IP addresses.",
		Run: func(cmd *cobra.Command, args []string) {
			dIf, err := stun.GetDefaultInterface()
			if err != nil {
				slog.Error("error getting the default interface", "err", err)
				return
			}
			slog.Info("got the default interface", "name", dIf.Name, "index", dIf.Index)

			ip4Prefixes, ip6Prefixes, err := stun.GetInterfacePrefixes(dIf)
			if err != nil {
				slog.Error("error getting interface prefixes", "err", err)
				return
			}

			for family, prefixes := range map[int][]netip.Prefix{
				unix.AF_INET:  ip4Prefixes,
				unix.AF_INET6: ip6Prefixes,
			} {
				for _, prefix := range prefixes {
					slog.Info("interface prefix", "family", types.Family(family), "prefix", prefix)

					if types.IsIPLinkLocal(prefix.Addr()) {
						slog.Info("address is link-local", "address", prefix.Addr())
						continue
					}

					if !types.IsIPPrivate(prefix.Addr()) {
						slog.Info("address is public", "address", prefix.Addr())
						continue
					}

					pubIp, err := stun.GetPubIPOverHTTP(stun.Config{}, family, prefix.Addr())
					if err != nil {
						slog.Error("error getting public IP", "method", "http", "err", err)
					} else {
						slog.Info("got public IP", "method", "http", "private", prefix.Addr(), "public", pubIp)
					}

					pubIp, err = stun.GetPubIPOverSTUN(stun.Config{
						StunServers: []string{stunServer},
					}, family, prefix.Addr())
					if err != nil {
						slog.Error("error getting public IP", "method", "stun", "err", err)
					} else {
						slog.Info("got public IP", "method", "stun", "private", prefix.Addr(), "public", pubIp)
					}
				}
			}
		},
	}
)
