package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scitags/flowd-go/cmd/subcmd"
	"github.com/scitags/flowd-go/types"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&confPath, "conf", "/etc/glowd/conf.json", "path of the JSON configuration file")
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

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Time to show what glowd can do!",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := ReadConf(confPath)
			if err != nil {
				slog.Error("couldn't read the configuration", "err", err)
				return
			}

			plugins, err := createPlugins(conf)
			if err != nil {
				slog.Error("couldn't create the plugins", "err", err)
			}

			backends, err := createBackends(conf)
			if err != nil {
				slog.Error("couldn't create the backends", "err", err)
			}

			if err := pluginBackendDependencies(plugins, backends); err != nil {
				slog.Error("couldn't fulfill the plugin-backend dependencies", "err", err)
				return
			}

			if err := os.WriteFile(conf.PidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
				slog.Error("couldn't create the PID file", "path", conf.PidPath, "err", err)
			}
			defer os.Remove(conf.PidPath)

			if err := initPlugins(plugins); err != nil {
				slog.Error("couldn't initialise the plugins", "err", err)
				return
			}
			defer cleanupPlugins(plugins)

			if err := initBackends(backends); err != nil {
				slog.Error("couldn't initialise the backends", "err", err)
				return
			}
			defer cleanupBackends(backends)

			// Set up the necessary channels, one per plugin and per backend
			pluginChans := make([]chan types.FlowID, 0, len(plugins))
			backendChans := make([]chan types.FlowID, 0, len(backends))

			// Set up the broadcast channel for exiting cleanly
			doneChan := make(chan struct{})

			// Dispatch the producers (i.e. plugins)
			for i, plugin := range plugins {
				pluginChans = append(pluginChans, make(chan types.FlowID))
				go plugin.Run(doneChan, pluginChans[i])
			}

			// Dispatch the consumers (i.e. backends)
			for i, backend := range backends {
				backendChans = append(backendChans, make(chan types.FlowID))
				go backend.Run(doneChan, backendChans[i])
			}

			// Funnel plugin flowIDs into an aggregate channel.
			// Buffer the channel so that consumers (i.e. backends)
			// can have some wiggle room if under pressuer.
			agg := make(chan types.FlowID)
			for i, ch := range pluginChans {
				go func(c chan types.FlowID, i int) {
					slog.Debug("began listening for plugin flowIDs", "i", i)
					for flowID := range c {
						slog.Debug("funneling flowID", "i", i)
						agg <- flowID
					}
				}(ch, i)
			}

			// Set up the machinery for catching SIGINT (i.e. os.Interrupt) and SIGTERM
			// which will be sent by SystemD when stopping/restarting the service.
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

			// Simply listen for events on the aggregated channel and dispatch
			// them to the backends. Another option could be reflect.Select,
			// although it's much less performing... Could a point-to-point
			// (i.e. mesh) architecture be better?
			slog.Info("let's go!", "nPlugins", len(pluginChans), "nBackends", len(backendChans))
			for {
				select {
				case flowID, ok := <-agg:
					if !ok {
						slog.Warn("somebody closed the aggregated channel!")
						return
					}
					slog.Debug("dispatching flowID to backends")
					for _, ch := range backendChans {
						ch <- flowID
					}
				case <-sigChan:
					close(doneChan)
					return
				}
			}
		},
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

	// Add the different sub-commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(confCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(markerCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
