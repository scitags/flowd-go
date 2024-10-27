package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/pcolladosoto/glowd"
	"github.com/pcolladosoto/glowd/backends/ebpf"
	"github.com/pcolladosoto/glowd/plugins/np"

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
		Use:   "ebpf-test",
		Short: "Try to load the eBPF program.",
		Run: func(cmd *cobra.Command, args []string) {
			ebpf.Init()
		},
	}

	npTest = &cobra.Command{
		Use:   "np-test",
		Short: "Try to create and read from a named pipe.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := np.Init(); err != nil {
				fmt.Printf("error setting up the named pipe: %v\n", err)
				os.Exit(-1)
			}
			defer func() {
				if err := np.Cleanup(); err != nil {
					fmt.Printf("error cleaning up the named pipe: %v\n", err)
				}
			}()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

			flowChan := make(chan glowd.FlowID)
			doneChan := make(chan struct{})
			go np.Run(doneChan, flowChan)

			for {
				select {
				case flowID, ok := <-flowChan:
					if !ok {
						fmt.Printf("flowChannel closed by producer...\n")
						return
					}
					fmt.Printf("got a flow: %+v\n", flowID)
				case <-sigChan:
					close(doneChan)
					return
				}
			}

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
	rootCmd.AddCommand(ebpfTest)
	rootCmd.AddCommand(npTest)
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
