package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/pcolladosoto/glowd"
	"github.com/pcolladosoto/glowd/backends/ebpf"
	"github.com/pcolladosoto/glowd/backends/firefly"
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
			ebpfBackend := ebpf.New()
			if err := ebpfBackend.Init(); err != nil {
				fmt.Printf("error on Init(): %v\n", err)
				return
			}

			ebpfBackend.Run(nil, nil)

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)
			<-sigChan
			// time.Sleep(5 * time.Second)

			if err := ebpfBackend.Cleanup(); err != nil {
				fmt.Printf("error on Cleanup(): %v\n", err)
				return
			}
		},
	}

	npTest = &cobra.Command{
		Use:   "np-test",
		Short: "Try to create and read from a named pipe.",
		Run: func(cmd *cobra.Command, args []string) {
			namedPipe := np.New()
			if err := namedPipe.Init(); err != nil {
				fmt.Printf("error setting up the named pipe: %v\n", err)
				os.Exit(-1)
			}
			defer func() {
				if err := namedPipe.Cleanup(); err != nil {
					fmt.Printf("error cleaning up the named pipe: %v\n", err)
				}
			}()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

			flowChan := make(chan glowd.FlowID)
			doneChan := make(chan struct{})
			go namedPipe.Run(doneChan, flowChan)

			fireflyBackend := firefly.New()
			go fireflyBackend.Run(doneChan, flowChan)

			// Block until we are told to quit
			<-sigChan
			close(doneChan)
			return
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
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Remove time.
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			source := a.Value.Any().(*slog.Source)
			source.File = filepath.Base(source.File)
		}
		return a
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelDebug,
		ReplaceAttr: replace,
	}))
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
