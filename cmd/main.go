package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/scitags/flowd-go/cmd/subcmd"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&confPath, "conf", "/etc/flowd-go/conf.yaml", "path of the JSON configuration file")
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info", "log level: one of debug, info, warn, error")
	rootCmd.PersistentFlags().BoolVar(&logTimeFlag, "log-time", false, "whether to include timestamps in the log")
}

var (
	rootCmd = &cobra.Command{
		Use:   "glowd",
		Short: "A SciTags client.",
		Long:  "Go nuts!",

		// Note we need to configure logging here as flags are not parsed before
		// calling rootCmd.Execute on main... As this PreRun function is persistent,
		// it'll be inherited by subcommands
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logLevel, ok := logLevelMap[logLevelFlag]
			if !ok {
				logLevel = slog.LevelInfo
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				AddSource:   true,
				Level:       logLevel,
				ReplaceAttr: logReplacements,
			}))
			slog.SetDefault(logger)
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Get the built version.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("built commit: %s\nbase version: %s\n", builtCommit, baseVersion)
		},
	}

	confCmd = &cobra.Command{
		Use:   "conf",
		Short: "Dump the configuration we're running with.",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := ReadConf(confPath)
			if err != nil {
				slog.Error("couldn't read the configuration", "err", err)
				return
			}
			jsonConf, err := json.MarshalIndent(conf, "", "    ")
			if err != nil {
				fmt.Printf("couldn't marshall the configuration: %v", err)
			}
			fmt.Printf("%s\n", jsonConf)
		},
	}

	markerCmd = &cobra.Command{
		Use:   "marker",
		Short: "Handle several marker (i.e. eBPF) thingies.",
	}

	stunCmd = &cobra.Command{
		Use:   "stun",
		Short: "STUN-related utilities.",
	}

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Time to show what glowd can do!",
		Run:   run,
	}

	confPath     string
	logLevelFlag string
	logTimeFlag  bool
	builtCommit  string
	baseVersion  string
)

func init() {
	// Disable completion please!
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add sub2-commands
	markerCmd.AddCommand(subcmd.MarkerClean)
	stunCmd.AddCommand(subcmd.StunSample)

	// Add the different sub-commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(confCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(markerCmd)
	rootCmd.AddCommand(stunCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
