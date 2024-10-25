package main

import (
	"fmt"
	"os"

	"github.com/pcolladosoto/glowd/backends/ebpf"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&sampleBoolFlag, "json", false, "Just an example for now...")
}

var (
	rootCmd = &cobra.Command{
		Use:   "glowd",
		Short: "A SciTags client.",
		Long:  "Go nuts!",
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Get the built version.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("built commit: %s\n", builtCommit)
		},
	}

	ebpfTest = &cobra.Command{
		Use:   "version",
		Short: "Get the built version.",
		Run: func(cmd *cobra.Command, args []string) {
			ebpf.Launch()
		},
	}

	sampleBoolFlag bool
	builtCommit    = "dev"
)

func init() {
	// Disable completion please!
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add the different sub-commands
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
