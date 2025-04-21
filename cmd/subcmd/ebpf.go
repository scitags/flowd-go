//go:build linux && cgo

package subcmd

import (
	"log/slog"

	"github.com/scitags/flowd-go/backends/ebpf"
	"github.com/spf13/cobra"
)

func init() {
	EbpfClean.PersistentFlags().StringVar(&targetInterface, "target-interface", "lo", "interface to delete the eBPF hook from")
	EbpfClean.PersistentFlags().BoolVar(&removeQdisc, "remove-qdisc", true, "whether to remove the backing qdisc")
}

var (
	targetInterface string
	removeQdisc     bool

	EbpfClean = &cobra.Command{
		Use:   "clean",
		Short: "Clean up flowd-go's backing eBPF hooks and qdisc.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := ebpf.RemoveTCHook(targetInterface, removeQdisc); err != nil {
				slog.Error("couldn't remove the existing hook", "err", err)
			}
		},
	}
)
