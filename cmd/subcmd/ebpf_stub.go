//go:build !linux || !ebpf

package subcmd

import (
	"github.com/spf13/cobra"
)

var (
	MarkerClean = &cobra.Command{
		Use:   "clean",
		Short: "stubbed-out method with no effect on non-linux platforms.",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
)
