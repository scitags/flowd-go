//go:build darwin || !cgo

package subcmd

import (
	"github.com/spf13/cobra"
)

var (
	EbpfClean = &cobra.Command{
		Use:   "clean",
		Short: "stubbed-out method with no effect on non-linux platforms.",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
)
